// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

//! Custom LSP request `vhdl/dataFlow`.
//!
//! Given a `library.entity`, returns the architecture's data-flow
//! graph as a Yosys-style JSON payload (the same format the
//! `vhdl_lang --dataflow-format yosys` CLI produces). The client uses
//! it to render a schematic in a webview.

use serde::Deserialize;

use super::VHDLServer;
use vhdl_lang::HierarchyError;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataFlowParams {
    pub library: String,
    pub entity: String,
}

impl VHDLServer {
    pub fn data_flow(
        &self,
        params: &DataFlowParams,
    ) -> Result<serde_json::Value, HierarchyError> {
        let df = self
            .project
            .data_flow_recursive(&params.library, &params.entity)?;
        Ok(vhdl_lang::format_yosys(&df))
    }
}
