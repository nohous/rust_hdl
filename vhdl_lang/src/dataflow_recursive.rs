// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

//! Recursive data-flow analysis: opens each leaf entity to ask
//! semantically (via the leaf's `rising_edge`/`falling_edge` clock
//! detection) which of its input ports are clocks, instead of guessing
//! by name. As a side effect we also learn each leaf's per-output-port
//! clock domain, which lets us propagate domain attribution across
//! multi-clock leaves at the parent level.
//!
//! Cost: each entity in the reachable design tree is computed at most
//! once per top-level call (via the cache). Acyclic by VHDL semantics.

use std::collections::{HashMap, HashSet};

use crate::analysis::DesignRoot;
use crate::dataflow::{
    compute_data_flow, looks_like_clock_port, ClockPinResolver, DataFlow, EndpointKind, NetKind,
    PortDirection,
};
use crate::HierarchyError;

/// Compute the data-flow graph for `library.entity`, then enrich the
/// clock-domain attribution by recursively analysing each instantiated
/// leaf. Replaces the name-heuristic clock-pin detection with semantic
/// detection (rising_edge / falling_edge on actual port names) and
/// propagates per-output-port domains from leaves up to the parent's
/// nets.
///
/// Each entity in the reachable subtree is computed at most once.
pub fn compute_data_flow_recursive(
    root: &DesignRoot,
    library_name: &str,
    entity_name: &str,
) -> Result<DataFlow, HierarchyError> {
    let mut cache: HashMap<String, DataFlow> = HashMap::new();
    compute_with_cache(root, library_name, entity_name, &mut cache)
}

fn compute_with_cache(
    root: &DesignRoot,
    library_name: &str,
    entity_name: &str,
    cache: &mut HashMap<String, DataFlow>,
) -> Result<DataFlow, HierarchyError> {
    let key = format!("{library_name}.{entity_name}");
    if let Some(cached) = cache.get(&key) {
        return Ok(cached.clone());
    }

    // Extract parent first (uses heuristic clock-pin detection
    // internally - we'll override below).
    let mut df = compute_data_flow(root, library_name, entity_name)?;

    // Tentative: empty entry under our key so a hypothetical cycle
    // (which shouldn't happen in valid VHDL) returns an empty stub
    // rather than infinite-looping.
    cache.insert(key.clone(), df.clone());

    // For each instance, recursively compute its leaf's dataflow.
    let mut leaf_dfs: HashMap<String, DataFlow> = HashMap::new();
    for inst in &df.instances {
        let Some((leaf_lib, leaf_ent)) = split_entity_path(&inst.entity_path) else {
            continue;
        };
        match compute_with_cache(root, leaf_lib, leaf_ent, cache) {
            Ok(leaf) => {
                leaf_dfs.insert(inst.id.clone(), leaf);
            }
            Err(_) => {
                // Leaf not in project (external IP, broken ref); fall
                // back to heuristic for this instance.
            }
        }
    }

    // Build the semantic clock-pin map: instance id -> port names that
    // appear as clocks in the leaf's processes (matched against leaf
    // port names so we know they're external pins, not internal
    // signals).
    let mut clock_pins: HashMap<String, HashSet<String>> = HashMap::new();
    for (inst_id, leaf) in &leaf_dfs {
        let leaf_port_names: HashSet<&str> = leaf
            .external_ports
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        let mut pins: HashSet<String> = HashSet::new();
        for proc in &leaf.processes {
            if let Some(clk) = proc.clock_signal.as_ref() {
                if leaf_port_names.contains(clk.as_str()) {
                    pins.insert(clk.clone());
                }
            }
        }
        // Also mine instance clock pins inside the leaf - if a leaf is
        // a pure structural wrapper that doesn't have processes but
        // forwards a clock down to a child instance, the child's
        // semantic clock pin walks up through the leaf's own port map.
        for nested in &leaf.instances {
            for nested_clk_pin in &nested.clocks {
                if leaf_port_names.contains(nested_clk_pin.as_str()) {
                    pins.insert(nested_clk_pin.clone());
                }
            }
        }
        if !pins.is_empty() {
            clock_pins.insert(inst_id.clone(), pins);
        }
    }

    // Re-attribute parent's clock domains using the semantic
    // resolver. This wipes any heuristic-driven domains attached by
    // the initial compute_data_flow call so we don't leave stale data
    // around.
    reset_attribution(&mut df);
    let resolver = SemanticClockPins {
        per_instance: &clock_pins,
    };
    crate::dataflow::reattribute_clock_domains(&mut df, &resolver);

    // Per-output-port domain translation. For each multi-clock leaf,
    // find its output ports' internal domains and translate them to
    // the parent's clock signal via the port map.
    propagate_leaf_output_domains(&mut df, &leaf_dfs, &clock_pins);

    // Re-CDC after the new domains are filled in.
    crate::dataflow::recompute_cdc_flags(&mut df, &resolver);

    cache.insert(key, df.clone());
    Ok(df)
}

fn split_entity_path(path: &str) -> Option<(&str, &str)> {
    path.split_once('.').filter(|(l, e)| !l.is_empty() && !e.is_empty())
}

fn reset_attribution(df: &mut DataFlow) {
    for net in &mut df.nets {
        net.clock_domain = None;
        net.is_cdc = false;
    }
    for inst in &mut df.instances {
        inst.clocks.clear();
    }
}

struct SemanticClockPins<'a> {
    per_instance: &'a HashMap<String, HashSet<String>>,
}

impl<'a> ClockPinResolver for SemanticClockPins<'a> {
    fn is_clock_pin(&self, inst_id: &str, port_name: &str) -> bool {
        if let Some(set) = self.per_instance.get(inst_id) {
            return set.contains(port_name);
        }
        // Leaf wasn't analysed (external IP, missing source) - fall
        // back to the name heuristic.
        looks_like_clock_port(port_name)
    }
}

/// For each multi-clock instance, look at its leaf's per-output-port
/// domain (each leaf output port's net carries `clock_domain`,
/// detected semantically inside the leaf). Translate that
/// leaf-internal domain (which is the leaf's clock pin name) into the
/// parent's clock signal via the port map, then attribute the
/// parent's net accordingly.
fn propagate_leaf_output_domains(
    df: &mut DataFlow,
    leaf_dfs: &HashMap<String, DataFlow>,
    clock_pins: &HashMap<String, HashSet<String>>,
) {
    // Build an inverse of the parent port map: for each (instance,
    // pin), which net does the parent connect to it?
    let mut inst_pin_to_parent_net: HashMap<(String, String), String> = HashMap::new();
    for net in &df.nets {
        for ep in &net.endpoints {
            if let (EndpointKind::Instance, Some(cell)) = (ep.kind, ep.cell_id.as_deref()) {
                inst_pin_to_parent_net
                    .insert((cell.to_string(), ep.port.clone()), net.name.clone());
            }
        }
    }

    // For each instance, build a leaf-port-name -> parent-clock-net map
    // (only for the leaf's clock pins).
    let mut inst_clock_pin_to_parent_net: HashMap<String, HashMap<String, String>> =
        HashMap::new();
    for (inst_id, pins) in clock_pins {
        let mut m: HashMap<String, String> = HashMap::new();
        for pin in pins {
            if let Some(parent_net) =
                inst_pin_to_parent_net.get(&(inst_id.clone(), pin.clone()))
            {
                m.insert(pin.clone(), parent_net.clone());
            }
        }
        if !m.is_empty() {
            inst_clock_pin_to_parent_net.insert(inst_id.clone(), m);
        }
    }

    // For each leaf, build a per-output-port internal domain map.
    let mut inst_output_port_domain: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (inst_id, leaf) in leaf_dfs {
        let pins = clock_pins.get(inst_id);
        // We only need to translate when the leaf has more than one
        // clock pin - the single-clock case is already covered by the
        // per-instance attribution at the parent level.
        if pins.map(|p| p.len()).unwrap_or(0) < 2 {
            continue;
        }
        let mut per_port: HashMap<String, String> = HashMap::new();
        for port in &leaf.external_ports {
            if !matches!(
                port.direction,
                PortDirection::Out | PortDirection::Buffer | PortDirection::Inout
            ) {
                continue;
            }
            for net in &leaf.nets {
                if net.kind == NetKind::ParentPort && net.name == port.name {
                    if let Some(domain) = net.clock_domain.as_ref() {
                        per_port.insert(port.name.clone(), domain.clone());
                    }
                    break;
                }
            }
        }
        if !per_port.is_empty() {
            inst_output_port_domain.insert(inst_id.clone(), per_port);
        }
    }

    // Walk parent's nets; for each one driven by a multi-clock
    // instance's output, look up the leaf-internal domain and
    // translate to parent.
    for net in &mut df.nets {
        if net.clock_domain.is_some() {
            continue;
        }
        for ep in &net.endpoints {
            if !matches!(
                ep.direction,
                PortDirection::Out | PortDirection::Buffer | PortDirection::Inout
            ) {
                continue;
            }
            if ep.kind != EndpointKind::Instance {
                continue;
            }
            let Some(cell) = ep.cell_id.as_deref() else {
                continue;
            };
            let Some(per_port) = inst_output_port_domain.get(cell) else {
                continue;
            };
            let Some(leaf_internal_clock) = per_port.get(ep.port.as_str()) else {
                continue;
            };
            // leaf_internal_clock is a leaf-side signal name. If it
            // matches a leaf clock pin, we can translate via the port
            // map. (If it's a leaf-internal generated clock, we can't
            // translate without knowing more; skip.)
            if let Some(parent_net) = inst_clock_pin_to_parent_net
                .get(cell)
                .and_then(|m| m.get(leaf_internal_clock))
            {
                net.clock_domain = Some(parent_net.clone());
                break;
            }
        }
    }
}
