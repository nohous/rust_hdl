// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

//! Architecture-level data-flow extraction.
//!
//! Given a top entity, [`compute_data_flow`] returns the connectivity of
//! one architecture as a flat graph: external ports of the parent entity,
//! the child instances with their bound entity's port list, and the nets
//! that join port endpoints together via shared architecture-level
//! signals or via the parent's own ports.
//!
//! Limitations of this initial implementation:
//!
//! * Only port maps are extracted; generic maps are ignored.
//! * Only "simple" actuals are resolved against the analyzer (a single
//!   `Name` that points at a signal or port). Slices, concatenations,
//!   record selections, and arbitrary expressions are recorded as a
//!   single opaque endpoint without being merged with anything else
//!   that touches the same underlying signal.
//! * Multiple architectures: the same architecture-selection rule used
//!   by [`crate::compute_design_hierarchy`] applies (prefer `rtl`, then
//!   alphabetical).
//! * For-/if-/case-generate statements are visited once - each
//!   instance shows up at the source-text point it is written, not
//!   multiplied by the elaborated count.

use std::collections::{HashMap, HashSet};
use std::ops::Deref;

use crate::analysis::{DesignRoot, Library, LockedUnit};
use crate::ast::search::{
    DeclarationItem, FoundDeclaration, NotFinished, Search, SearchState, Searcher,
};
use crate::ast::{
    AnyDesignUnit, AnySecondaryUnit, ConcurrentStatement, Designator, InstantiatedUnit,
    LabeledConcurrentStatement, MapAspect, Mode, Name,
};
use crate::data::Symbol;
use crate::hierarchy::HierarchyError;
use crate::named_entity::{
    AnyEntKind, Design, EntRef, EntityId, HasEntityId, InterfaceMode, ObjectEnt, ObjectInterface,
    Region,
};
use crate::syntax::{HasTokenSpan, TokenAccess};
use crate::SrcPos;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortDirection {
    In,
    Out,
    Inout,
    Buffer,
    Linkage,
    /// Unknown (e.g. mode-view ports for which we have not yet picked a
    /// representative direction).
    Unknown,
}

impl PortDirection {
    fn from_mode(mode: Mode) -> Self {
        match mode {
            Mode::In => PortDirection::In,
            Mode::Out => PortDirection::Out,
            Mode::InOut => PortDirection::Inout,
            Mode::Buffer => PortDirection::Buffer,
            Mode::Linkage => PortDirection::Linkage,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortInfo {
    pub name: String,
    pub direction: PortDirection,
    /// Best-effort textual rendering of the type for display only.
    pub type_repr: String,
    pub decl_pos: Option<SrcPos>,
}

#[derive(Debug, Clone)]
pub struct InstanceInfo {
    /// Stable id within the data-flow graph (the instance label, or
    /// `inst_<n>` for unlabeled ones - which are not legal VHDL but can
    /// occur after parse errors).
    pub id: String,
    pub label: Option<String>,
    /// `library.entity` for the bound entity.
    pub entity_path: String,
    pub instance_pos: Option<SrcPos>,
    pub entity_pos: Option<SrcPos>,
    pub ports: Vec<PortInfo>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointKind {
    /// A port of the parent (top-of-graph) entity.
    External,
    /// A port of an instance child.
    Instance,
    /// A signal read or driven by a process.
    Process,
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub kind: EndpointKind,
    /// For `Instance`: the instance's stable id. For `Process`: the
    /// process's stable id. For `External`: `None`.
    pub cell_id: Option<String>,
    /// For instance/external endpoints: the port name. For process
    /// endpoints: the signal name (since processes don't have ports).
    pub port: String,
    /// Direction of the signal flow at this endpoint, when known.
    pub direction: PortDirection,
    pub source_pos: Option<SrcPos>,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub id: String,
    pub label: Option<String>,
    pub source_pos: Option<SrcPos>,
    /// What the process listens to.
    pub sensitivity: Sensitivity,
    /// Clock signal driving this process, detected via `rising_edge` /
    /// `falling_edge` calls in the body. `None` for combinational
    /// processes.
    pub clock_signal: Option<String>,
    /// Reset signal, detected by name heuristic from the sensitivity
    /// list. Advisory only.
    pub reset_signal: Option<String>,
    /// Architecture-level signals assigned in the body.
    pub writes: Vec<String>,
    /// Architecture-level signals or parent ports referenced in the
    /// sensitivity list (or `process(all)` reads).
    pub reads: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sensitivity {
    /// Explicit sensitivity list.
    Names(Vec<String>),
    /// `process (all)` (VHDL-2008).
    All,
    /// No sensitivity list, uses `wait` statements internally.
    Implicit,
}

#[derive(Debug, Clone)]
pub struct NetInfo {
    /// Underlying signal name, parent port name, or `<expr>` when the
    /// actual expression was not a single resolved name.
    pub name: String,
    pub kind: NetKind,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetKind {
    /// A net carried by an architecture-level signal.
    Signal,
    /// A net carried by one of the parent entity's ports.
    ParentPort,
    /// An association whose actual was not a single resolved name; the
    /// net contains exactly one endpoint and is labelled `<expr>`.
    Opaque,
}

#[derive(Debug, Clone)]
pub struct DataFlow {
    pub entity_path: String,
    pub architecture: Option<String>,
    pub entity_pos: Option<SrcPos>,
    pub external_ports: Vec<PortInfo>,
    pub instances: Vec<InstanceInfo>,
    pub processes: Vec<ProcessInfo>,
    pub nets: Vec<NetInfo>,
    pub notes: Vec<String>,
}

/// Compute the data-flow graph for `library.entity`'s architecture.
pub fn compute_data_flow(
    root: &DesignRoot,
    library_name: &str,
    entity_name: &str,
) -> Result<DataFlow, HierarchyError> {
    // Reuse the same library/entity lookup as the hierarchy walker so
    // error messages stay consistent.
    let lib_sym = root.symbol_utf8(library_name);
    let library = root
        .get_lib(&lib_sym)
        .ok_or_else(|| HierarchyError::UnknownLibrary {
            library: library_name.to_string(),
            known: known_libraries(root),
        })?;
    let ent_sym = root.symbol_utf8(entity_name);
    let entity =
        find_entity(root, library, &ent_sym).ok_or_else(|| HierarchyError::UnknownEntity {
            library: library_name.to_string(),
            entity: entity_name.to_string(),
            known: known_entities(root, library),
        })?;

    Ok(extract(root, library, entity))
}

fn known_libraries(root: &DesignRoot) -> Vec<String> {
    let mut names: Vec<String> = root.libraries().map(|l| l.name().name_utf8()).collect();
    names.sort();
    names
}

fn known_entities(root: &DesignRoot, library: &Library) -> Vec<String> {
    let mut names: Vec<String> = library
        .units()
        .filter_map(|locked| {
            let data = locked.unit.expect_analyzed();
            let primary = match *data.deref() {
                AnyDesignUnit::Primary(ref p) => p,
                _ => return None,
            };
            let id = primary.ent_id()?;
            let ent = root.get_ent(id);
            if !matches!(ent.kind(), AnyEntKind::Design(Design::Entity(..))) {
                return None;
            }
            match ent.designator() {
                Designator::Identifier(s) => Some(s.name_utf8()),
                _ => None,
            }
        })
        .collect();
    names.sort();
    names
}

fn find_entity<'a>(
    root: &'a DesignRoot,
    library: &Library,
    entity: &Symbol,
) -> Option<EntRef<'a>> {
    for locked in library.units() {
        let data = locked.unit.expect_analyzed();
        let AnyDesignUnit::Primary(ref primary) = *data.deref() else {
            continue;
        };
        let Some(id) = primary.ent_id() else { continue };
        let ent = root.get_ent(id);
        if matches!(ent.kind(), AnyEntKind::Design(Design::Entity(..)))
            && matches!(ent.designator(), Designator::Identifier(s) if s == entity)
        {
            return Some(ent);
        }
    }
    None
}

fn extract<'a>(root: &'a DesignRoot, library: &Library, entity: EntRef<'a>) -> DataFlow {
    let mut notes = Vec::new();

    let entity_path = format!(
        "{}.{}",
        entity
            .library_name()
            .map(|s| s.name_utf8())
            .unwrap_or_else(|| "?".into()),
        ident_string(entity),
    );

    let external_ports = match entity.kind() {
        AnyEntKind::Design(Design::Entity(_, region)) => collect_ports_from_region(region),
        _ => Vec::new(),
    };

    let architectures: Vec<EntRef<'a>> = root
        .find_implementation(entity)
        .into_iter()
        .filter(|e| matches!(e.kind(), AnyEntKind::Design(Design::Architecture(..))))
        .collect();
    let arch_count = architectures.len();
    let (arch_ent, arch_names) = pick_architecture(architectures);
    let architecture = arch_ent.map(ident_string);
    if arch_count == 0 {
        notes.push("entity has no architecture in the project".into());
    } else if arch_count > 1 {
        notes.push(format!(
            "multiple architectures ({}); using {}",
            arch_names.join(", "),
            architecture.clone().unwrap_or_default(),
        ));
    }

    let mut df = DataFlow {
        entity_path,
        architecture,
        entity_pos: entity.decl_pos().cloned(),
        external_ports,
        instances: Vec::new(),
        processes: Vec::new(),
        nets: Vec::new(),
        notes,
    };

    let Some(arch) = arch_ent else {
        return df;
    };

    let architecture_signals: HashSet<EntityId> = match arch.kind() {
        AnyEntKind::Design(Design::Architecture(_, region, _)) => signal_ids_in_region(region),
        _ => HashSet::new(),
    };
    let parent_port_ids: HashSet<EntityId> = df
        .external_ports
        .iter()
        .filter_map(|p| p.decl_pos.as_ref().map(|_| ()))
        .map(|_| ())
        .zip(df.external_ports.iter())
        .filter_map(|(_, port)| {
            port_id_in_region(
                match entity.kind() {
                    AnyEntKind::Design(Design::Entity(_, region)) => Some(region),
                    _ => None,
                }?,
                &port.name,
            )
        })
        .collect();

    // Collect all raw instances under the architecture.
    let raw_instances = match arch_locked_unit(library, arch) {
        Some(locked) => collect_instance_assocs(locked),
        None => Vec::new(),
    };

    // We will fill these as we visit each instance.
    let mut net_index: HashMap<EntityId, usize> = HashMap::new();
    let mut id_counter = 0usize;
    let mut used_ids: HashSet<String> = HashSet::new();

    let mut next_id = |label: Option<&str>| -> String {
        let base = label.map(str::to_string).unwrap_or_else(|| {
            id_counter += 1;
            format!("inst_{id_counter}")
        });
        let mut id = base.clone();
        let mut suffix = 2;
        while !used_ids.insert(id.clone()) {
            id = format!("{base}#{suffix}");
            suffix += 1;
        }
        id
    };

    for raw in raw_instances {
        let id = next_id(raw.label.as_deref());

        // Resolve the bound entity; for components, follow default
        // binding to the entity (mirrors the hierarchy walker).
        let bound_entity = match raw.target_id.and_then(|id| Some(root.get_ent(id))) {
            Some(ent) => match ent.kind() {
                AnyEntKind::Design(Design::Entity(..)) => Some(ent),
                AnyEntKind::Component(_) => root
                    .find_implementation(ent)
                    .into_iter()
                    .find(|e| matches!(e.kind(), AnyEntKind::Design(Design::Entity(..)))),
                _ => None,
            },
            None => None,
        };

        let mut info = InstanceInfo {
            id: id.clone(),
            label: raw.label.clone(),
            entity_path: bound_entity
                .map(|e| {
                    format!(
                        "{}.{}",
                        e.library_name()
                            .map(|s| s.name_utf8())
                            .unwrap_or_else(|| "?".into()),
                        ident_string(e),
                    )
                })
                .unwrap_or_else(|| "<unresolved>".into()),
            instance_pos: Some(raw.instance_pos.clone()),
            entity_pos: bound_entity.and_then(|e| e.decl_pos().cloned()),
            ports: bound_entity
                .map(|e| match e.kind() {
                    AnyEntKind::Design(Design::Entity(_, region)) => {
                        collect_ports_from_region(region)
                    }
                    _ => Vec::new(),
                })
                .unwrap_or_default(),
            notes: Vec::new(),
        };

        if bound_entity.is_none() {
            info.notes
                .push("could not resolve instantiation target to an entity".into());
        }

        // Walk associations: for each (formal, actual_id_or_opaque),
        // append an endpoint to the appropriate net.
        for assoc in raw.associations {
            let formal_name = match resolve_formal(&assoc, &info.ports) {
                Some(v) => v,
                None => continue,
            };

            match assoc.actual_id {
                Some(actual_id) if architecture_signals.contains(&actual_id) => {
                    let direction = port_direction(&info.ports, &formal_name);
                    push_endpoint(
                        &mut df.nets,
                        &mut net_index,
                        actual_id,
                        || NetInfo {
                            name: ident_string(root.get_ent(actual_id)),
                            kind: NetKind::Signal,
                            endpoints: Vec::new(),
                        },
                        Endpoint {
                            kind: EndpointKind::Instance,
                            cell_id: Some(id.clone()),
                            port: formal_name,
                            direction,
                            source_pos: Some(raw.instance_pos.clone()),
                        },
                    );
                }
                Some(actual_id) if parent_port_ids.contains(&actual_id) => {
                    let direction = port_direction(&info.ports, &formal_name);
                    push_endpoint(
                        &mut df.nets,
                        &mut net_index,
                        actual_id,
                        || NetInfo {
                            name: ident_string(root.get_ent(actual_id)),
                            kind: NetKind::ParentPort,
                            endpoints: Vec::new(),
                        },
                        Endpoint {
                            kind: EndpointKind::Instance,
                            cell_id: Some(id.clone()),
                            port: formal_name,
                            direction,
                            source_pos: Some(raw.instance_pos.clone()),
                        },
                    );
                }
                _ => {
                    let direction = port_direction(&info.ports, &formal_name);
                    df.nets.push(NetInfo {
                        name: assoc
                            .actual_text
                            .clone()
                            .unwrap_or_else(|| "<expr>".into()),
                        kind: NetKind::Opaque,
                        endpoints: vec![Endpoint {
                            kind: EndpointKind::Instance,
                            cell_id: Some(id.clone()),
                            port: formal_name,
                            direction,
                            source_pos: Some(raw.instance_pos.clone()),
                        }],
                    });
                }
            }
        }

        df.instances.push(info);
    }

    // Add an external endpoint for each parent port that is on a net.
    // (Otherwise external ports floating with no internal use don't get
    // a net at all - intentional, that's accurate.)
    let parent_port_id_to_name: HashMap<EntityId, String> = match entity.kind() {
        AnyEntKind::Design(Design::Entity(_, region)) => region
            .immediates()
            .filter_map(|ent| {
                let obj = ObjectEnt::from_any(ent)?;
                if matches!(obj.object().iface, Some(ObjectInterface::Port(_))) {
                    Some((ent.id(), ident_string(ent)))
                } else {
                    None
                }
            })
            .collect(),
        _ => HashMap::new(),
    };
    for (eid, name) in &parent_port_id_to_name {
        if let Some(idx) = net_index.get(eid) {
            let direction = port_direction(&df.external_ports, name);
            df.nets[*idx].endpoints.push(Endpoint {
                kind: EndpointKind::External,
                cell_id: None,
                port: name.clone(),
                direction,
                source_pos: None,
            });
        }
    }

    // Now collect processes from the architecture and stitch them in.
    if let Some(locked) = arch_locked_unit(library, arch) {
        let raw_processes = collect_processes(locked);
        let arch_signals_by_id: HashMap<EntityId, String> = match arch.kind() {
            AnyEntKind::Design(Design::Architecture(_, region, _)) => region
                .immediates()
                .filter_map(|ent| {
                    let obj = ObjectEnt::from_any(ent)?;
                    if obj.object().is_signal() && obj.object().iface.is_none() {
                        Some((ent.id(), ident_string(ent)))
                    } else {
                        None
                    }
                })
                .collect(),
            _ => HashMap::new(),
        };
        // Combined name -> id lookup for signals AND parent ports, so a
        // process that reads/writes either kind can be tied to the right
        // existing net.
        let mut name_to_net_id: HashMap<String, EntityId> = HashMap::new();
        for (eid, name) in &arch_signals_by_id {
            name_to_net_id.insert(name.clone(), *eid);
        }
        for (eid, name) in &parent_port_id_to_name {
            name_to_net_id.insert(name.clone(), *eid);
        }

        for raw in raw_processes {
            let pid = next_id(raw.label.as_deref());
            let mut info = ProcessInfo {
                id: pid.clone(),
                label: raw.label.clone(),
                source_pos: Some(raw.source_pos.clone()),
                sensitivity: raw.sensitivity.clone(),
                clock_signal: raw.clock_signal.clone(),
                reset_signal: None,
                writes: raw.writes.clone(),
                reads: raw.reads.clone(),
                notes: Vec::new(),
            };

            // Reset detection by name. We look at both the sensitivity
            // list (catches async resets) and the body reads (catches
            // sync resets used inside the clocked block).
            let sens_names: &[String] = match &raw.sensitivity {
                Sensitivity::Names(n) => n.as_slice(),
                _ => &[],
            };
            info.reset_signal = sens_names
                .iter()
                .chain(raw.reads.iter())
                .find(|n| looks_like_reset(n))
                .cloned();

            // Wire endpoints into existing nets (signals and parent ports
            // we already saw via instance port maps).
            for sig in &raw.writes {
                if let Some(eid) = name_to_net_id.get(sig.as_str()) {
                    let net_kind = if arch_signals_by_id.contains_key(eid) {
                        NetKind::Signal
                    } else {
                        NetKind::ParentPort
                    };
                    push_endpoint(
                        &mut df.nets,
                        &mut net_index,
                        *eid,
                        || NetInfo {
                            name: sig.clone(),
                            kind: net_kind,
                            endpoints: Vec::new(),
                        },
                        Endpoint {
                            kind: EndpointKind::Process,
                            cell_id: Some(pid.clone()),
                            port: sig.clone(),
                            direction: PortDirection::Out,
                            source_pos: Some(raw.source_pos.clone()),
                        },
                    );
                }
            }
            for sig in &raw.reads {
                if let Some(eid) = name_to_net_id.get(sig.as_str()) {
                    let net_kind = if arch_signals_by_id.contains_key(eid) {
                        NetKind::Signal
                    } else {
                        NetKind::ParentPort
                    };
                    push_endpoint(
                        &mut df.nets,
                        &mut net_index,
                        *eid,
                        || NetInfo {
                            name: sig.clone(),
                            kind: net_kind,
                            endpoints: Vec::new(),
                        },
                        Endpoint {
                            kind: EndpointKind::Process,
                            cell_id: Some(pid.clone()),
                            port: sig.clone(),
                            direction: PortDirection::In,
                            source_pos: Some(raw.source_pos.clone()),
                        },
                    );
                }
            }

            df.processes.push(info);
        }
    }

    // Sort nets for stable output: signals first, then parent ports,
    // then opaque; alphabetical within each group.
    df.nets.sort_by(|a, b| {
        net_kind_order(a.kind)
            .cmp(&net_kind_order(b.kind))
            .then_with(|| a.name.cmp(&b.name))
    });

    df
}

fn net_kind_order(k: NetKind) -> u8 {
    match k {
        NetKind::Signal => 0,
        NetKind::ParentPort => 1,
        NetKind::Opaque => 2,
    }
}

fn push_endpoint<F>(
    nets: &mut Vec<NetInfo>,
    index: &mut HashMap<EntityId, usize>,
    eid: EntityId,
    make_net: F,
    endpoint: Endpoint,
) where
    F: FnOnce() -> NetInfo,
{
    let idx = *index.entry(eid).or_insert_with(|| {
        nets.push(make_net());
        nets.len() - 1
    });
    nets[idx].endpoints.push(endpoint);
}

fn pick_architecture<'a>(architectures: Vec<EntRef<'a>>) -> (Option<EntRef<'a>>, Vec<String>) {
    let mut named: Vec<(String, EntRef<'a>)> = architectures
        .into_iter()
        .filter_map(|e| match e.designator() {
            Designator::Identifier(s) => Some((s.name_utf8(), e)),
            _ => None,
        })
        .collect();
    named.sort_by(|a, b| a.0.cmp(&b.0));
    let names: Vec<String> = named.iter().map(|(n, _)| n.clone()).collect();
    let pick = named
        .iter()
        .find(|(n, _)| n == "rtl")
        .or_else(|| named.first())
        .map(|(_, e)| *e);
    (pick, names)
}

fn arch_locked_unit<'a>(library: &'a Library, arch_ent: EntRef<'_>) -> Option<&'a LockedUnit> {
    let arch_id = arch_ent.id();
    for locked in library.units() {
        let data = locked.unit.expect_analyzed();
        if let AnyDesignUnit::Secondary(AnySecondaryUnit::Architecture(ref arch)) = *data.deref() {
            if arch.ident.decl.get() == Some(arch_id) {
                drop(data);
                return Some(locked);
            }
        }
    }
    None
}

fn collect_ports_from_region(region: &Region<'_>) -> Vec<PortInfo> {
    let mut out = Vec::new();
    for ent in region.immediates() {
        let Some(obj) = ObjectEnt::from_any(ent) else {
            continue;
        };
        let Some(iface) = obj.object().iface.as_ref() else {
            continue;
        };
        let ObjectInterface::Port(ref mode) = iface else {
            continue;
        };
        let direction = match mode {
            InterfaceMode::Simple(m) => PortDirection::from_mode(*m),
            InterfaceMode::View(_) => PortDirection::Unknown,
        };
        out.push(PortInfo {
            name: ident_string(ent),
            direction,
            type_repr: format!("{}", obj.type_mark().designator()),
            decl_pos: ent.decl_pos().cloned(),
        });
    }
    out
}

fn signal_ids_in_region(region: &Region<'_>) -> HashSet<EntityId> {
    region
        .immediates()
        .filter_map(|ent| {
            let obj = ObjectEnt::from_any(ent)?;
            if obj.object().is_signal() && obj.object().iface.is_none() {
                Some(ent.id())
            } else {
                None
            }
        })
        .collect()
}

fn port_id_in_region(region: &Region<'_>, name: &str) -> Option<EntityId> {
    region
        .immediates()
        .filter(|ent| matches!(
            ent.actual_kind(),
            AnyEntKind::Object(_)
        ))
        .find(|ent| match ent.designator() {
            Designator::Identifier(s) => s.name_utf8() == name,
            _ => false,
        })
        .map(|ent| ent.id())
}

fn ident_string(ent: EntRef<'_>) -> String {
    match ent.designator() {
        Designator::Identifier(s) => s.name_utf8(),
        d => format!("{d}"),
    }
}

#[derive(Debug)]
struct RawAssociation {
    /// Formal port name as written in the source. `None` for positional
    /// associations.
    formal_name: Option<String>,
    /// Position in the port_map - used to map positional associations
    /// to the port at the same index in the bound entity's port_clause.
    position: usize,
    /// Resolved actual entity id when the actual is a single name; `None`
    /// for `open`, slices, concatenations, etc.
    actual_id: Option<EntityId>,
    /// Best-effort source-text rendering for opaque actuals.
    actual_text: Option<String>,
}

#[derive(Debug)]
struct RawInstanceAssoc {
    label: Option<String>,
    instance_pos: SrcPos,
    target_id: Option<EntityId>,
    associations: Vec<RawAssociation>,
}

fn collect_instance_assocs(locked: &LockedUnit) -> Vec<RawInstanceAssoc> {
    let mut searcher = InstanceCollector {
        instances: Vec::new(),
    };
    let _ = locked
        .unit
        .expect_analyzed()
        .search(&locked.tokens, &mut searcher);
    searcher.instances
}

struct InstanceCollector {
    instances: Vec<RawInstanceAssoc>,
}

impl Searcher for InstanceCollector {
    fn search_decl(&mut self, ctx: &dyn TokenAccess, decl: FoundDeclaration<'_>) -> SearchState {
        if let DeclarationItem::ConcurrentStatement(labeled) = decl.ast {
            if let Some(raw) = build_instance_assoc(ctx, labeled) {
                self.instances.push(raw);
            }
        }
        NotFinished
    }
}

fn build_instance_assoc(
    ctx: &dyn TokenAccess,
    labeled: &LabeledConcurrentStatement,
) -> Option<RawInstanceAssoc> {
    let ConcurrentStatement::Instance(ref inst) = labeled.statement.item else {
        return None;
    };
    let label = labeled
        .label
        .tree
        .as_ref()
        .map(|ident| ident.item.name_utf8());
    let instance_pos = match labeled.label.tree {
        Some(ref ident) => ident.pos(ctx).clone(),
        None => inst.get_pos(ctx),
    };
    let target_id = match inst.unit {
        InstantiatedUnit::Entity(ref name, _) => name.item.get_suffix_reference(),
        InstantiatedUnit::Component(ref name) => name.item.get_suffix_reference(),
        InstantiatedUnit::Configuration(ref name) => name.item.get_suffix_reference(),
    };

    let associations = inst
        .port_map
        .as_ref()
        .map(|m| collect_associations(ctx, m))
        .unwrap_or_default();

    Some(RawInstanceAssoc {
        label,
        instance_pos,
        target_id,
        associations,
    })
}

fn collect_associations(ctx: &dyn TokenAccess, map: &MapAspect) -> Vec<RawAssociation> {
    let mut out = Vec::with_capacity(map.list.items.len());
    for (i, el) in map.list.items.iter().enumerate() {
        let formal_name = el.formal.as_ref().and_then(|name| match &name.item {
            Name::Designator(desi) => match &desi.item {
                Designator::Identifier(s) => Some(s.name_utf8()),
                _ => None,
            },
            _ => None,
        });
        let (actual_id, actual_text) = match &el.actual.item {
            crate::ast::ActualPart::Open => (None, Some("open".into())),
            crate::ast::ActualPart::Expression(expr) => resolve_actual_expression(ctx, expr),
        };
        out.push(RawAssociation {
            formal_name,
            position: i,
            actual_id,
            actual_text,
        });
    }
    out
}

fn resolve_actual_expression(
    ctx: &dyn TokenAccess,
    expr: &crate::ast::Expression,
) -> (Option<EntityId>, Option<String>) {
    use crate::ast::Expression;
    match expr {
        Expression::Name(name) => {
            // Name is Box<Name>; reach in.
            match name.as_ref() {
                Name::Designator(desi) => (desi.reference.get(), None),
                other => {
                    let _ = ctx;
                    (None, Some(format_name(other)))
                }
            }
        }
        _ => (None, Some("<expr>".into())),
    }
}

fn format_name(name: &Name) -> String {
    match name {
        Name::Designator(desi) => format!("{}", desi.item),
        Name::Selected(prefix, suffix) => {
            format!("{}.{}", format_name(&prefix.item), suffix.item.item)
        }
        Name::SelectedAll(prefix) => format!("{}.all", format_name(&prefix.item)),
        Name::Slice(prefix, _) => format!("{}(...)", format_name(&prefix.item)),
        Name::Attribute(_) => "<attr>".into(),
        Name::CallOrIndexed(c) => format!("{}(...)", format_name(&c.name.item)),
        Name::External(_) => "<external>".into(),
    }
}

fn port_direction(ports: &[PortInfo], name: &str) -> PortDirection {
    ports
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
        .map(|p| p.direction)
        .unwrap_or(PortDirection::Unknown)
}

/// Heuristic reset detection by name. Recognised conventions:
/// * `rst`, `reset` (any case)
/// * `*_rst`, `*_reset`, `rst_*`, `reset_*`
/// * `nrst`, `n_rst`, `*_n` (active low), `*_aresetn`, `aresetn`
fn looks_like_reset(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let stripped = lower.trim_start_matches('_').trim_end_matches('_');
    matches!(
        stripped,
        "rst" | "reset" | "nrst" | "rstn" | "resetn" | "aresetn" | "areset"
    ) || stripped.ends_with("_rst")
        || stripped.ends_with("_reset")
        || stripped.ends_with("_rstn")
        || stripped.ends_with("_resetn")
        || stripped.ends_with("_aresetn")
        || stripped.starts_with("rst_")
        || stripped.starts_with("reset_")
}

/// Map a port_map association to the formal port it targets in the
/// bound entity's port list. Named associations win on name; positional
/// associations fall back to index. Returns the formal port's name.
fn resolve_formal(assoc: &RawAssociation, ports: &[PortInfo]) -> Option<String> {
    if let Some(name) = &assoc.formal_name {
        if ports.iter().any(|p| p.name.eq_ignore_ascii_case(name)) {
            return Some(name.clone());
        }
        // The named formal didn't match any known port - return the
        // typed name anyway so the visualiser can show "unknown port".
        return Some(name.clone());
    }
    ports.get(assoc.position).map(|p| p.name.clone())
}

// --- Process extraction ------------------------------------------------------

#[derive(Debug)]
struct RawProcess {
    label: Option<String>,
    source_pos: SrcPos,
    sensitivity: Sensitivity,
    clock_signal: Option<String>,
    reads: Vec<String>,
    writes: Vec<String>,
}

fn collect_processes(locked: &LockedUnit) -> Vec<RawProcess> {
    let mut searcher = ProcessCollector {
        processes: Vec::new(),
    };
    let _ = locked
        .unit
        .expect_analyzed()
        .search(&locked.tokens, &mut searcher);
    searcher.processes
}

struct ProcessCollector {
    processes: Vec<RawProcess>,
}

impl Searcher for ProcessCollector {
    fn search_decl(&mut self, ctx: &dyn TokenAccess, decl: FoundDeclaration<'_>) -> SearchState {
        if let DeclarationItem::ConcurrentStatement(labeled) = decl.ast {
            if let ConcurrentStatement::Process(ref proc) = labeled.statement.item {
                self.processes
                    .push(build_raw_process(ctx, labeled, proc));
            }
        }
        NotFinished
    }
}

fn build_raw_process(
    ctx: &dyn TokenAccess,
    labeled: &LabeledConcurrentStatement,
    proc: &crate::ast::ProcessStatement,
) -> RawProcess {
    let label = labeled
        .label
        .tree
        .as_ref()
        .map(|ident| ident.item.name_utf8());
    let source_pos = match labeled.label.tree {
        Some(ref ident) => ident.pos(ctx).clone(),
        None => proc.get_pos(ctx),
    };

    let mut sensitivity_names: Vec<String> = Vec::new();
    let sensitivity = match &proc.sensitivity_list {
        None => Sensitivity::Implicit,
        Some(list) => match &list.item {
            crate::ast::SensitivityList::All => Sensitivity::All,
            crate::ast::SensitivityList::Names(names) => {
                let collected: Vec<String> = names
                    .iter()
                    .filter_map(|n| simple_name_text(&n.item))
                    .collect();
                sensitivity_names = collected.clone();
                Sensitivity::Names(collected)
            }
        },
    };

    let mut writes: Vec<String> = Vec::new();
    let mut reads: Vec<String> = sensitivity_names.clone();
    let mut clock_signal: Option<String> = None;

    walk_sequential_statements(&proc.statements, &mut writes, &mut reads, &mut clock_signal);

    writes = dedup_preserve_order(writes);
    reads = dedup_preserve_order(reads);

    RawProcess {
        label,
        source_pos,
        sensitivity,
        clock_signal,
        reads,
        writes,
    }
}

fn dedup_preserve_order(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items.into_iter().filter(|s| seen.insert(s.clone())).collect()
}

fn walk_sequential_statements(
    statements: &[crate::ast::LabeledSequentialStatement],
    writes: &mut Vec<String>,
    reads: &mut Vec<String>,
    clock_signal: &mut Option<String>,
) {
    for stmt in statements {
        walk_sequential_statement(&stmt.statement.item, writes, reads, clock_signal);
    }
}

fn walk_sequential_statement(
    stmt: &crate::ast::SequentialStatement,
    writes: &mut Vec<String>,
    reads: &mut Vec<String>,
    clock_signal: &mut Option<String>,
) {
    use crate::ast::SequentialStatement;
    match stmt {
        SequentialStatement::SignalAssignment(assign) => {
            collect_target_names(&assign.target.item, writes);
            walk_assignment_rhs_waveform(&assign.rhs, reads, clock_signal);
        }
        SequentialStatement::SignalForceAssignment(assign) => {
            collect_target_names(&assign.target.item, writes);
            walk_assignment_rhs_expr(&assign.rhs, reads, clock_signal);
        }
        SequentialStatement::SignalReleaseAssignment(assign) => {
            collect_target_names(&assign.target.item, writes);
        }
        SequentialStatement::VariableAssignment(assign) => {
            walk_assignment_rhs_expr(&assign.rhs, reads, clock_signal);
        }
        SequentialStatement::If(if_stmt) => {
            for cond in &if_stmt.conds.conditionals {
                walk_expression(&cond.condition.item, reads, clock_signal);
                walk_sequential_statements(&cond.item, writes, reads, clock_signal);
            }
            if let Some(else_branch) = &if_stmt.conds.else_item {
                walk_sequential_statements(&else_branch.0, writes, reads, clock_signal);
            }
        }
        SequentialStatement::Case(case_stmt) => {
            walk_expression(&case_stmt.expression.item, reads, clock_signal);
            for alt in &case_stmt.alternatives {
                walk_sequential_statements(&alt.item, writes, reads, clock_signal);
            }
        }
        SequentialStatement::Loop(loop_stmt) => {
            walk_sequential_statements(&loop_stmt.statements, writes, reads, clock_signal);
        }
        SequentialStatement::ProcedureCall(call) => {
            walk_call_or_indexed(&call.item, reads, clock_signal);
        }
        SequentialStatement::Wait(_)
        | SequentialStatement::Assert(_)
        | SequentialStatement::Report(_)
        | SequentialStatement::Next(_)
        | SequentialStatement::Exit(_)
        | SequentialStatement::Return(_)
        | SequentialStatement::Null => {}
    }
}

fn collect_target_names(target: &crate::ast::Target, out: &mut Vec<String>) {
    use crate::ast::Target;
    match target {
        Target::Name(name) => {
            if let Some(s) = leftmost_simple_name(name) {
                out.push(s);
            }
        }
        Target::Aggregate(_) => {
            // Aggregate targets (e.g. `(a, b) <= ...`) - the named
            // members are signals, but extracting them requires
            // walking the choices. Skip for v1; the signals on the
            // left side will still appear if they're driven somewhere
            // else, otherwise they're hidden from this view.
        }
    }
}

fn walk_assignment_rhs_waveform(
    rhs: &crate::ast::AssignmentRightHand<crate::ast::Waveform>,
    reads: &mut Vec<String>,
    clock_signal: &mut Option<String>,
) {
    use crate::ast::{AssignmentRightHand, Waveform};
    let waveforms: Vec<&Waveform> = match rhs {
        AssignmentRightHand::Simple(w) => vec![w],
        AssignmentRightHand::Conditional(conds) => conds
            .conditionals
            .iter()
            .map(|c| &c.item)
            .chain(conds.else_item.iter().map(|e| &e.0))
            .collect(),
        AssignmentRightHand::Selected(sel) => {
            walk_expression(&sel.expression.item, reads, clock_signal);
            sel.alternatives.iter().map(|a| &a.item).collect()
        }
    };
    for waveform in waveforms {
        if let Waveform::Elements(elems) = waveform {
            for el in elems {
                walk_expression(&el.value.item, reads, clock_signal);
                if let Some(after) = &el.after {
                    walk_expression(&after.item, reads, clock_signal);
                }
            }
        }
    }
    if let AssignmentRightHand::Conditional(conds) = rhs {
        for cond in &conds.conditionals {
            walk_expression(&cond.condition.item, reads, clock_signal);
        }
    }
}

fn walk_assignment_rhs_expr(
    rhs: &crate::ast::AssignmentRightHand<
        crate::ast::token_range::WithTokenSpan<crate::ast::Expression>,
    >,
    reads: &mut Vec<String>,
    clock_signal: &mut Option<String>,
) {
    use crate::ast::AssignmentRightHand;
    match rhs {
        AssignmentRightHand::Simple(e) => walk_expression(&e.item, reads, clock_signal),
        AssignmentRightHand::Conditional(conds) => {
            for cond in &conds.conditionals {
                walk_expression(&cond.condition.item, reads, clock_signal);
                walk_expression(&cond.item.item, reads, clock_signal);
            }
            if let Some(else_branch) = &conds.else_item {
                walk_expression(&else_branch.0.item, reads, clock_signal);
            }
        }
        AssignmentRightHand::Selected(sel) => {
            walk_expression(&sel.expression.item, reads, clock_signal);
            for alt in &sel.alternatives {
                walk_expression(&alt.item.item, reads, clock_signal);
            }
        }
    }
}

fn walk_expression(
    expr: &crate::ast::Expression,
    reads: &mut Vec<String>,
    clock_signal: &mut Option<String>,
) {
    use crate::ast::Expression;
    match expr {
        Expression::Binary(_, lhs, rhs) => {
            walk_expression(&lhs.item, reads, clock_signal);
            walk_expression(&rhs.item, reads, clock_signal);
        }
        Expression::Unary(_, inner) => walk_expression(&inner.item, reads, clock_signal),
        Expression::Aggregate(elems) => {
            for el in elems {
                if let crate::ast::ElementAssociation::Positional(e) = &el.item {
                    walk_expression(&e.item, reads, clock_signal);
                } else if let crate::ast::ElementAssociation::Named(_, e) = &el.item {
                    walk_expression(&e.item, reads, clock_signal);
                }
            }
        }
        Expression::Qualified(qual) => walk_expression(&qual.expr.item, reads, clock_signal),
        Expression::New(_) => {
            // `new` allocator is irrelevant for hardware data-flow.
        }
        Expression::Name(name) => {
            // Capture the leftmost name as a read, and inspect the
            // function-call form in case it's `rising_edge(clk)` /
            // `falling_edge(clk)`.
            if let Name::CallOrIndexed(call) = name.as_ref() {
                walk_call_or_indexed(call, reads, clock_signal);
            } else if let Some(s) = leftmost_simple_name(name) {
                reads.push(s);
            }
        }
        Expression::Literal(_) => {}
        Expression::Parenthesized(inner) => walk_expression(&inner.item, reads, clock_signal),
    }
}

fn walk_call_or_indexed(
    call: &crate::ast::CallOrIndexed,
    reads: &mut Vec<String>,
    clock_signal: &mut Option<String>,
) {
    let func_name = simple_name_text(&call.name.item);
    if let Some(name) = &func_name {
        let lower = name.to_ascii_lowercase();
        if (lower == "rising_edge" || lower == "falling_edge")
            && clock_signal.is_none()
        {
            // First parameter's actual is the clock signal.
            if let Some(first) = call.parameters.items.first() {
                if let crate::ast::ActualPart::Expression(expr) = &first.actual.item {
                    if let crate::ast::Expression::Name(n) = expr {
                        if let Some(clk) = leftmost_simple_name(n) {
                            *clock_signal = Some(clk);
                        }
                    }
                }
            }
        }
    }
    // The call might also be an indexed signal access (e.g. `bus(7)`),
    // in which case the name is a signal read. Capture it.
    if let Some(s) = leftmost_simple_name(&call.name.item) {
        // Only count it as a read if it isn't the rising_edge/falling_edge
        // function itself.
        let lower = s.to_ascii_lowercase();
        if lower != "rising_edge" && lower != "falling_edge" {
            reads.push(s);
        }
    }
    for assoc in &call.parameters.items {
        if let crate::ast::ActualPart::Expression(expr) = &assoc.actual.item {
            walk_expression(expr, reads, clock_signal);
        }
    }
}

/// Extract the leftmost simple identifier in a name. For
/// `bus(7 downto 0)` returns `bus`; for `record.field` returns
/// `record`. Returns `None` for things we don't know how to chase.
fn leftmost_simple_name(name: &Name) -> Option<String> {
    match name {
        Name::Designator(desi) => match &desi.item {
            Designator::Identifier(s) => Some(s.name_utf8()),
            _ => None,
        },
        Name::Selected(prefix, _) => leftmost_simple_name(&prefix.item),
        Name::SelectedAll(prefix) => leftmost_simple_name(&prefix.item),
        Name::Slice(prefix, _) => leftmost_simple_name(&prefix.item),
        Name::CallOrIndexed(call) => leftmost_simple_name(&call.name.item),
        Name::Attribute(_) | Name::External(_) => None,
    }
}

fn simple_name_text(name: &Name) -> Option<String> {
    match name {
        Name::Designator(desi) => match &desi.item {
            Designator::Identifier(s) => Some(s.name_utf8()),
            _ => None,
        },
        _ => None,
    }
}
