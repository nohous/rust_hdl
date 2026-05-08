// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

//! Yosys-style JSON conversion for [`crate::DataFlow`], the format
//! consumed by netlistsvg. Lives in the library so both the CLI
//! (`vhdl_lang --dataflow-format yosys`) and the language server's
//! `vhdl/dataFlow` LSP request can produce the same payload.
//!
//! Names sharing a common `_`-delimited prefix (>= [`MIN_BUNDLE_SIZE`]
//! siblings) collapse into multi-bit bus pins and netnames so the
//! rendered schematic doesn't drown in individual AXI / AXI-Stream
//! wires.
//!
//! CDC-aware extensions in the schema (additive, ignored by stock
//! netlistsvg renderers but available to a custom skin):
//! * each `cell` carries `clocks`: the connected clock-pin nets.
//! * each `netname` carries `clock_domain` and `is_cdc`.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{json, Map, Value};

use crate::data::SrcPos;
use crate::dataflow::{DataFlow, EndpointKind, NetInfo, PortDirection};

/// Encode a [`SrcPos`] as `{ "file": "...", "start": {"line": L,
/// "character": C}, "end": {...} }`. Lines/characters are 0-based, the
/// same convention LSP uses, so the client can build a `vscode.Range`
/// directly.
fn pos_to_json(pos: &SrcPos) -> Value {
    let s = pos.start();
    let e = pos.end();
    json!({
        "file": pos.file_name().to_string_lossy(),
        "start": { "line": s.line, "character": s.character },
        "end": { "line": e.line, "character": e.character },
    })
}

/// Minimum number of name-prefix-sharing siblings required to collapse
/// them into a bundle. Below this they stay as individual pins / nets.
pub const MIN_BUNDLE_SIZE: usize = 3;

/// Render a [`DataFlow`] graph as a Yosys-style JSON payload.
pub fn format_yosys(df: &DataFlow) -> Value {
    let mut net_bit: HashMap<String, u32> = HashMap::new();
    let mut next_bit: u32 = 2;
    for net in &df.nets {
        alloc_bit(&net.name, &mut net_bit, &mut next_bit);
    }
    for port in &df.external_ports {
        alloc_bit(&port.name, &mut net_bit, &mut next_bit);
    }

    let port_items: Vec<(String, String)> = df
        .external_ports
        .iter()
        .map(|p| (p.name.clone(), yosys_dir(p.direction).to_string()))
        .collect();
    let port_bundles = compute_bundles(&port_items, MIN_BUNDLE_SIZE);

    let net_items: Vec<(String, String)> = df
        .nets
        .iter()
        .map(|n| (n.name.clone(), String::new()))
        .collect();
    let net_bundles = compute_bundles(&net_items, MIN_BUNDLE_SIZE);

    let mut cell_bundles: HashMap<String, BundleMap> = HashMap::new();
    for inst in &df.instances {
        let mut seen: HashSet<String> = HashSet::new();
        let items: Vec<(String, String)> = inst
            .ports
            .iter()
            .filter(|p| seen.insert(p.name.clone()))
            .map(|p| (p.name.clone(), yosys_dir(p.direction).to_string()))
            .collect();
        cell_bundles.insert(inst.id.clone(), compute_bundles(&items, MIN_BUNDLE_SIZE));
    }

    let ports = build_module_ports(df, &net_bit, &port_bundles);
    let cells = build_cells(df, &net_bit, &cell_bundles);
    let netnames = build_netnames(df, &net_bit, &net_bundles);

    let mut module = json!({
        "ports": ports,
        "cells": cells,
        "netnames": netnames,
    });
    if let Some(p) = df.entity_pos.as_ref() {
        module
            .as_object_mut()
            .unwrap()
            .insert("vhdl_entity_pos".into(), pos_to_json(p));
    }
    let mut modules = Map::new();
    modules.insert(df.entity_path.clone(), module);
    json!({
        "creator": "vhdl_lang dataflow extractor",
        "modules": modules,
    })
}

/// Convenience: pretty-print [`format_yosys`] with a trailing newline.
pub fn format_yosys_string(df: &DataFlow) -> String {
    let mut s = serde_json::to_string_pretty(&format_yosys(df)).expect("serialize yosys");
    s.push('\n');
    s
}

// ---------------------------------------------------------------------------
// Bit assignment & direction mapping
// ---------------------------------------------------------------------------

fn alloc_bit(name: &str, net_bit: &mut HashMap<String, u32>, next_bit: &mut u32) -> u32 {
    *net_bit.entry(name.to_string()).or_insert_with(|| {
        let b = *next_bit;
        *next_bit += 1;
        b
    })
}

/// Map a [`PortDirection`] to yosys-speak. yosys only knows
/// input/output/inout - collapse buffer/linkage onto output.
fn yosys_dir(d: PortDirection) -> &'static str {
    match d {
        PortDirection::In => "input",
        PortDirection::Out | PortDirection::Buffer | PortDirection::Linkage => "output",
        PortDirection::Inout => "inout",
        PortDirection::Unknown => "input",
    }
}

/// Which net does the (instance, port) endpoint sit on? After the
/// slice-formal fix, multiple sub-bindings to the same formal can
/// produce multiple endpoints with the same (cell, port). We collapse
/// to the first; full slice reconstruction is a later concern.
fn inst_port_to_net<'a>(df: &'a DataFlow, cell: &str, port: &str) -> Option<&'a str> {
    for net in &df.nets {
        if net.endpoints.iter().any(|ep| {
            ep.kind == EndpointKind::Instance
                && ep.cell_id.as_deref() == Some(cell)
                && ep.port == port
        }) {
            return Some(net.name.as_str());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Bundling
// ---------------------------------------------------------------------------

/// Result of a bundling pass: each clustered name knows its bundle and
/// its slot within it; each bundle knows its ordered member list.
#[derive(Default)]
struct BundleMap {
    /// `name -> (bundle_id, position_within_bundle)`.
    name_to_slot: HashMap<String, (String, usize)>,
    /// `bundle_id -> ordered member names`. BTreeMap for stable output.
    bundles: BTreeMap<String, Vec<String>>,
    /// `bundle_id -> direction marker` (empty for nets).
    bundle_dir: HashMap<String, String>,
}

/// `_`-terminated prefix candidates of `name`, shortest to longest.
/// `s_axil_aclk` -> `["s_", "s_axil_"]`. Single-segment names like
/// `clk` produce no candidates.
fn prefix_candidates(name: &str) -> Vec<String> {
    let segments: Vec<&str> = name.split('_').collect();
    if segments.len() < 2 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut acc = String::new();
    for seg in &segments[..segments.len() - 1] {
        acc.push_str(seg);
        acc.push('_');
        if !acc.is_empty() && acc != "_" {
            out.push(acc.clone());
        }
    }
    out
}

/// Names that should never be folded into a bus bundle: clocks and
/// resets. Burying these in a fat wire destroys the most important
/// visual cues on a hardware schematic.
fn is_unbundleable(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let clocky = lower.contains("clk") || lower.contains("clock");
    let resety = matches!(
        lower.trim_end_matches('_').trim_start_matches('_'),
        "rst" | "reset" | "nrst" | "rstn" | "resetn" | "aresetn" | "areset"
    ) || lower.ends_with("_rst")
        || lower.ends_with("_reset")
        || lower.ends_with("_rstn")
        || lower.ends_with("_resetn")
        || lower.ends_with("_aresetn")
        || lower.starts_with("rst_")
        || lower.starts_with("reset_");
    clocky || resety
}

/// Group `(name, direction_marker)` pairs by longest shared prefix.
/// Pass an empty string as the marker when direction shouldn't split
/// groups (i.e. for nets). Names without a long-enough sibling group,
/// or those flagged as unbundleable, are absent from the map and
/// should be emitted individually.
fn compute_bundles(items: &[(String, String)], min_size: usize) -> BundleMap {
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for (name, dir) in items {
        if is_unbundleable(name) {
            continue;
        }
        for prefix in prefix_candidates(name) {
            *counts.entry((prefix, dir.clone())).or_insert(0) += 1;
        }
    }

    let mut name_to_prefix: HashMap<String, (String, String)> = HashMap::new();
    for (name, dir) in items {
        if is_unbundleable(name) {
            continue;
        }
        let mut best: Option<String> = None;
        for prefix in prefix_candidates(name) {
            let cnt = counts
                .get(&(prefix.clone(), dir.clone()))
                .copied()
                .unwrap_or(0);
            if cnt >= min_size
                && best
                    .as_ref()
                    .map(|p| prefix.len() > p.len())
                    .unwrap_or(true)
            {
                best = Some(prefix);
            }
        }
        if let Some(prefix) = best {
            name_to_prefix.insert(name.clone(), (prefix, dir.clone()));
        }
    }

    let mut bundles_by_id: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bundle_dir: HashMap<String, String> = HashMap::new();
    for (name, (prefix, dir)) in &name_to_prefix {
        let bundle_id = if dir.is_empty() {
            prefix.trim_end_matches('_').to_string()
        } else {
            format!("{}__{}", prefix.trim_end_matches('_'), dir)
        };
        bundles_by_id
            .entry(bundle_id.clone())
            .or_default()
            .push(name.clone());
        bundle_dir.insert(bundle_id, dir.clone());
    }

    bundles_by_id.retain(|_, members| members.len() >= min_size);
    bundle_dir.retain(|id, _| bundles_by_id.contains_key(id));

    let mut name_to_slot: HashMap<String, (String, usize)> = HashMap::new();
    for (bundle_id, members) in bundles_by_id.iter_mut() {
        let any_member = members[0].clone();
        let prefix = name_to_prefix.get(&any_member).unwrap().0.clone();
        members.sort_by(|a, b| a[prefix.len()..].cmp(&b[prefix.len()..]));
        for (i, m) in members.iter().enumerate() {
            name_to_slot.insert(m.clone(), (bundle_id.clone(), i));
        }
    }

    BundleMap {
        name_to_slot,
        bundles: bundles_by_id,
        bundle_dir,
    }
}

// ---------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------

fn bit_value(name: &str, net_bit: &HashMap<String, u32>) -> Value {
    net_bit
        .get(name)
        .copied()
        .map(Value::from)
        .unwrap_or(Value::from("x"))
}

fn build_module_ports(
    df: &DataFlow,
    net_bit: &HashMap<String, u32>,
    port_bundles: &BundleMap,
) -> Map<String, Value> {
    let mut ports = Map::new();
    let mut emitted: HashSet<String> = HashSet::new();
    for p in &df.external_ports {
        if let Some((bundle_id, _)) = port_bundles.name_to_slot.get(&p.name) {
            if emitted.insert(bundle_id.clone()) {
                let members = port_bundles.bundles.get(bundle_id).unwrap();
                let bits: Vec<Value> = members.iter().map(|m| bit_value(m, net_bit)).collect();
                let dir = port_bundles
                    .bundle_dir
                    .get(bundle_id)
                    .map(String::as_str)
                    .unwrap_or("input");
                ports.insert(
                    bundle_id.clone(),
                    json!({
                        "direction": dir,
                        "bits": bits,
                        "members": members,
                    }),
                );
            }
            continue;
        }
        ports.insert(
            p.name.clone(),
            json!({
                "direction": yosys_dir(p.direction),
                "bits": [bit_value(&p.name, net_bit)],
            }),
        );
    }
    ports
}

fn build_cells(
    df: &DataFlow,
    net_bit: &HashMap<String, u32>,
    cell_bundles: &HashMap<String, BundleMap>,
) -> Map<String, Value> {
    let mut cells = Map::new();
    for inst in &df.instances {
        let cb = cell_bundles.get(&inst.id).unwrap();
        let mut port_directions = Map::new();
        let mut connections = Map::new();
        let mut emitted: HashSet<String> = HashSet::new();
        let mut seen: HashSet<String> = HashSet::new();
        for port in &inst.ports {
            if !seen.insert(port.name.clone()) {
                continue;
            }
            if let Some((bundle_id, _)) = cb.name_to_slot.get(&port.name) {
                if emitted.insert(bundle_id.clone()) {
                    let members = cb.bundles.get(bundle_id).unwrap();
                    let dir = cb
                        .bundle_dir
                        .get(bundle_id)
                        .map(String::as_str)
                        .unwrap_or("input");
                    port_directions.insert(bundle_id.clone(), Value::from(dir));
                    let bits: Vec<Value> = members
                        .iter()
                        .map(|m| {
                            inst_port_to_net(df, &inst.id, m)
                                .and_then(|n| net_bit.get(n).copied())
                                .map(Value::from)
                                .unwrap_or(Value::from("x"))
                        })
                        .collect();
                    connections.insert(bundle_id.clone(), Value::Array(bits));
                }
                continue;
            }
            port_directions.insert(port.name.clone(), Value::from(yosys_dir(port.direction)));
            let bit = inst_port_to_net(df, &inst.id, &port.name)
                .and_then(|n| net_bit.get(n).copied())
                .map(Value::from)
                .unwrap_or(Value::from("x"));
            connections.insert(port.name.clone(), Value::Array(vec![bit]));
        }
        let cell_name = inst.label.clone().unwrap_or_else(|| inst.id.clone());
        // Display: "<INST_LABEL> : <library.entity>" so the user sees
        // both the instantiation label and the bound entity. The
        // standard netlistsvg skin only renders the type as a label;
        // there's nowhere it shows the cell's stable id otherwise.
        let cell_type = format!("{} : {}", cell_name, inst.entity_path);
        let mut cell = json!({
            "type": cell_type,
            "port_directions": port_directions,
            "connections": connections,
            "clocks": inst.clocks,
        });
        let cell_obj = cell.as_object_mut().unwrap();
        if let Some(p) = inst.instance_pos.as_ref() {
            cell_obj.insert("vhdl_instance_pos".into(), pos_to_json(p));
        }
        if let Some(p) = inst.entity_pos.as_ref() {
            cell_obj.insert("vhdl_entity_pos".into(), pos_to_json(p));
        }
        cells.insert(cell_name, cell);
    }

    for proc in &df.processes {
        let writes: HashSet<&str> = proc.writes.iter().map(String::as_str).collect();
        let proc_pin_items: Vec<(String, String)> = proc
            .writes
            .iter()
            .map(|s| (s.clone(), "output".to_string()))
            .chain(
                proc.reads
                    .iter()
                    .filter(|s| !writes.contains(s.as_str()))
                    .map(|s| (s.clone(), "input".to_string())),
            )
            .collect();
        let pb = compute_bundles(&proc_pin_items, MIN_BUNDLE_SIZE);

        let mut port_directions = Map::new();
        let mut connections = Map::new();
        let mut emitted: HashSet<String> = HashSet::new();

        let mut push_pin =
            |sig: &str,
             dir: &str,
             port_directions: &mut Map<String, Value>,
             connections: &mut Map<String, Value>| {
                if let Some((bundle_id, _)) = pb.name_to_slot.get(sig) {
                    if emitted.insert(bundle_id.clone()) {
                        let members = pb.bundles.get(bundle_id).unwrap();
                        let bits: Vec<Value> =
                            members.iter().map(|m| bit_value(m, net_bit)).collect();
                        let bdir = pb
                            .bundle_dir
                            .get(bundle_id)
                            .map(String::as_str)
                            .unwrap_or(dir);
                        port_directions.insert(bundle_id.clone(), Value::from(bdir));
                        connections.insert(bundle_id.clone(), Value::Array(bits));
                    }
                    return;
                }
                port_directions.insert(sig.to_string(), Value::from(dir));
                connections.insert(sig.to_string(), Value::Array(vec![bit_value(sig, net_bit)]));
            };

        for sig in &proc.writes {
            push_pin(sig, "output", &mut port_directions, &mut connections);
        }
        for sig in &proc.reads {
            if writes.contains(sig.as_str()) {
                continue;
            }
            push_pin(sig, "input", &mut port_directions, &mut connections);
        }

        let cell_name = proc.label.clone().unwrap_or_else(|| proc.id.clone());
        // Display: "<PROC_LABEL> : process(sync)" so the user sees
        // the process's label rather than just its kind. Same rule as
        // for instance cells; the netlistsvg skin only shows the
        // type field as a visible label.
        let kind = if proc.clock_signal.is_some() {
            "process (sync)"
        } else {
            "process (comb)"
        };
        let cell_type = format!("{} : {}", cell_name, kind);
        let mut cell = json!({
            "type": cell_type,
            "port_directions": port_directions,
            "connections": connections,
        });
        let cell_obj = cell.as_object_mut().unwrap();
        if let Some(c) = &proc.clock_signal {
            cell_obj.insert("clock".into(), Value::from(c.clone()));
        }
        if let Some(r) = &proc.reset_signal {
            cell_obj.insert("reset".into(), Value::from(r.clone()));
        }
        if let Some(p) = proc.source_pos.as_ref() {
            cell_obj.insert("vhdl_instance_pos".into(), pos_to_json(p));
        }
        cells.insert(cell_name, cell);
    }

    cells
}

fn build_netnames(
    df: &DataFlow,
    net_bit: &HashMap<String, u32>,
    net_bundles: &BundleMap,
) -> Map<String, Value> {
    let mut netnames = Map::new();
    let mut emitted: HashSet<String> = HashSet::new();
    let nets_by_name: HashMap<&str, &NetInfo> =
        df.nets.iter().map(|n| (n.name.as_str(), n)).collect();

    for net in &df.nets {
        if let Some((bundle_id, _)) = net_bundles.name_to_slot.get(&net.name) {
            if emitted.insert(bundle_id.clone()) {
                let members = net_bundles.bundles.get(bundle_id).unwrap();
                let bits: Vec<Value> = members.iter().map(|m| bit_value(m, net_bit)).collect();
                let mut entry = json!({
                    "bits": bits,
                    "hide_name": 0,
                    "members": members,
                });
                let obj = entry.as_object_mut().unwrap();
                let domains: HashSet<&str> = members
                    .iter()
                    .filter_map(|m| nets_by_name.get(m.as_str()))
                    .filter_map(|n| n.clock_domain.as_deref())
                    .collect();
                if domains.len() == 1 {
                    obj.insert(
                        "clock_domain".into(),
                        Value::from(domains.into_iter().next().unwrap().to_string()),
                    );
                }
                let any_cdc = members
                    .iter()
                    .filter_map(|m| nets_by_name.get(m.as_str()))
                    .any(|n| n.is_cdc);
                if any_cdc {
                    obj.insert("is_cdc".into(), Value::from(true));
                }
                netnames.insert(bundle_id.clone(), entry);
            }
            continue;
        }
        let bit = match net_bit.get(&net.name) {
            Some(b) => Value::from(*b),
            None => continue,
        };
        let mut entry = json!({
            "bits": [bit],
            "hide_name": 0,
        });
        let obj = entry.as_object_mut().unwrap();
        if let Some(d) = &net.clock_domain {
            obj.insert("clock_domain".into(), Value::from(d.clone()));
        }
        if net.is_cdc {
            obj.insert("is_cdc".into(), Value::from(true));
        }
        netnames.insert(net.name.clone(), entry);
    }
    netnames
}
