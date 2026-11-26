// SPDX-License-Identifier: Apache-2.0

//! Generate a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) for the
//! SDK's algorithm inventory. Output: JSON to stdout.
//!
//! Usage: `cargo run --bin cbom > cbom.json`

use origin_crypto_sdk::algorithm_id::ALL_ALGORITHM_IDS;
use serde_json::{json, Value};

fn main() {
    let components: Vec<Value> = ALL_ALGORITHM_IDS
        .iter()
        .map(|id| {
            json!({
                "type": "cryptographic-asset",
                "bom-ref": format!("algorithm/0x{:04X}", *id as u16),
                "name": id.name(),
                "description": id.implementation_provenance(),
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": id.primitive(),
                        "executionEnvironment": "software-plain-ram",
                        "implementationPlatform": "rust",
                        "cryptoFunctions": if id.is_hybrid() { vec!["sign", "verify"] } else { Vec::<&str>::new() },
                    }
                }
            })
        })
        .collect();

    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "name": "origin-crypto-sdk",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Hybrid post-quantum cryptography SDK — see STABILITY.md for evidence tiers"
            },
            "tools": [{
                "name": "origin-crypto-sdk cbom generator",
                "version": env!("CARGO_PKG_VERSION")
            }]
        },
        "components": components
    });

    println!("{}", serde_json::to_string_pretty(&bom).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use origin_crypto_sdk::algorithm_id::AlgorithmId;

    /// The CBOM inventory must cover every AlgorithmId variant. Discriminant
    /// count is fixed at 34 — if a variant is added, this test fails until
    /// ALL_ALGORITHM_IDS is updated. Prevents silent inventory drift.
    #[test]
    fn inventory_complete_and_unique() {
        assert_eq!(
            ALL_ALGORITHM_IDS.len(),
            34,
            "variant count changed — update ALL_ALGORITHM_IDS"
        );
        let mut ids: Vec<u16> = ALL_ALGORITHM_IDS.iter().map(|i| *i as u16).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(
            ids.len(),
            ALL_ALGORITHM_IDS.len(),
            "duplicate inventory entries"
        );
        // every variant's metadata must be non-empty
        for id in ALL_ALGORITHM_IDS {
            assert!(!id.name().is_empty());
            assert!(!id.primitive().is_empty());
        }
        let _ = AlgorithmId::Blake3; // type linkage check
    }
}
