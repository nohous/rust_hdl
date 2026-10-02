// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

//! Custom LSP request `vhdl/dataFlow`.
//!
//! Given a `library.entity`, returns the architecture's data-flow
//! graph ([`vhdl_lang::DataFlow`] serialized as JSON). The client
//! renders it as a schematic in a webview.

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
    pub fn data_flow(&self, params: &DataFlowParams) -> Result<serde_json::Value, HierarchyError> {
        let df = self
            .project
            .data_flow_recursive(&params.library, &params.entity)?;
        Ok(serde_json::to_value(&df).expect("serialize dataflow"))
    }
}
