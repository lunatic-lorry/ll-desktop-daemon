use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ores_adapter::OresLambdaAdapterV1;

pub const MAX_ORES_ADAPTER_BYTES: usize = 1024 * 1024;
pub const MAX_ORES_RECEIPT_BYTES: usize = 1024 * 1024;
const RECEIPT_SCHEMA: &str = "ores.lambda.wasm-artifact.receipt/v1";
const ADAPTER_SCHEMA: &str = "ores.lambda.adapter/v1";
const PROVIDER: &str = "lunatic_lorry";
const TARGET_TRIPLE: &str = "wasm32-wasip1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OresBuildEvidence {
    pub receipt_sha256: String,
    pub adapter_raw_sha256: String,
    pub artifact_sha256: String,
    pub wrapper_sha256: String,
    pub unit_manifest_sha256: String,
}

impl OresBuildEvidence {
    pub fn validate(&self) -> Result<()> {
        for (label, digest) in [
            ("receipt_sha256", self.receipt_sha256.as_str()),
            ("adapter_raw_sha256", self.adapter_raw_sha256.as_str()),
            ("artifact_sha256", self.artifact_sha256.as_str()),
            ("wrapper_sha256", self.wrapper_sha256.as_str()),
            ("unit_manifest_sha256", self.unit_manifest_sha256.as_str()),
        ] {
            validate_sha256(digest, label)?;
        }
        return Ok(());
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WasmArtifactReceipt {
    schema_version: String,
    generated_by: String,
    provider: String,
    runtime_repository: String,
    runtime_contract: String,
    adapter_contract: String,
    artifact_path: String,
    artifact_sha256: String,
    deploy_mutation_performed: bool,
    target_triple: String,
    adapter_path: String,
    adapter_sha256: String,
    source_path: String,
    source_sha256: String,
    cargo_manifest_path: String,
    cargo_package: String,
    cargo_target_name: String,
    wrapper_sha256: String,
    unit_manifest_sha256: String,
}

pub fn verify(
    structured_adapter: &OresLambdaAdapterV1,
    raw_adapter_bytes: &[u8],
    raw_receipt_bytes: &[u8],
    module_bytes: &[u8],
) -> Result<OresBuildEvidence> {
    if raw_adapter_bytes.is_empty() || raw_adapter_bytes.len() > MAX_ORES_ADAPTER_BYTES {
        bail!("raw ORES adapter bytes are outside the admitted size range");
    }
    if raw_receipt_bytes.is_empty() || raw_receipt_bytes.len() > MAX_ORES_RECEIPT_BYTES {
        bail!("raw ORES receipt bytes are outside the admitted size range");
    }

    structured_adapter.validate()?;
    let raw_adapter: OresLambdaAdapterV1 = serde_json::from_slice(raw_adapter_bytes)
        .context("raw ORES adapter bytes are not canonical adapter JSON")?;
    raw_adapter.validate()?;
    if raw_adapter.semantic_sha256()? != structured_adapter.semantic_sha256()? {
        bail!("structured ORES adapter does not match the exact raw adapter bytes");
    }

    let receipt: WasmArtifactReceipt = serde_json::from_slice(raw_receipt_bytes)
        .context("raw ORES receipt bytes are not valid receipt JSON")?;
    require(
        &receipt.schema_version,
        RECEIPT_SCHEMA,
        "receipt schema_version",
    )?;
    require(&receipt.generated_by, "ores-stack", "receipt generated_by")?;
    require(&receipt.provider, PROVIDER, "receipt provider")?;
    require(
        &receipt.target_triple,
        TARGET_TRIPLE,
        "receipt target_triple",
    )?;
    require(
        &receipt.adapter_contract,
        ADAPTER_SCHEMA,
        "receipt adapter_contract",
    )?;
    if receipt.deploy_mutation_performed {
        bail!("ORES WASM artifact receipt must remain immutable build evidence");
    }

    require(
        &receipt.source_path,
        raw_adapter.source(),
        "receipt source_path",
    )?;
    require(
        &receipt.source_sha256,
        raw_adapter.source_sha256(),
        "receipt source_sha256",
    )?;
    require(
        &receipt.runtime_repository,
        "lunatic-lorry/ll-lambdas",
        "receipt runtime_repository",
    )?;
    require(
        &receipt.runtime_contract,
        "lunatic-lorry.lambda-runtime/v1",
        "receipt runtime_contract",
    )?;

    let module_sha256 = sha256_hex(module_bytes);
    require(
        &receipt.artifact_sha256,
        &module_sha256,
        "receipt artifact_sha256",
    )?;
    let adapter_raw_sha256 = sha256_hex(raw_adapter_bytes);
    require(
        &receipt.adapter_sha256,
        &adapter_raw_sha256,
        "receipt adapter_sha256",
    )?;

    for (label, digest) in [
        ("artifact_sha256", receipt.artifact_sha256.as_str()),
        ("adapter_sha256", receipt.adapter_sha256.as_str()),
        ("source_sha256", receipt.source_sha256.as_str()),
        ("wrapper_sha256", receipt.wrapper_sha256.as_str()),
        (
            "unit_manifest_sha256",
            receipt.unit_manifest_sha256.as_str(),
        ),
    ] {
        validate_sha256(digest, label)?;
    }
    for (label, value) in [
        ("artifact_path", receipt.artifact_path.as_str()),
        ("adapter_path", receipt.adapter_path.as_str()),
        ("cargo_manifest_path", receipt.cargo_manifest_path.as_str()),
        ("cargo_package", receipt.cargo_package.as_str()),
        ("cargo_target_name", receipt.cargo_target_name.as_str()),
    ] {
        if value.trim().is_empty() || value.contains('\0') {
            bail!("ORES receipt {label} must be non-empty");
        }
    }

    let evidence = OresBuildEvidence {
        receipt_sha256: sha256_hex(raw_receipt_bytes),
        adapter_raw_sha256,
        artifact_sha256: module_sha256,
        wrapper_sha256: receipt.wrapper_sha256,
        unit_manifest_sha256: receipt.unit_manifest_sha256,
    };
    evidence.validate()?;
    return Ok(evidence);
}

fn require(actual: &str, expected: &str, label: &str) -> Result<()> {
    if actual != expected {
        bail!("{label} mismatch: expected {expected:?}, got {actual:?}");
    }
    return Ok(());
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    if !valid {
        bail!("ORES receipt {label} must be lowercase SHA-256");
    }
    return Ok(());
}

fn sha256_hex(bytes: &[u8]) -> String {
    return format!("{:x}", Sha256::digest(bytes));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn adapter_bytes() -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&json!({
            "schema_version": "ores.lambda.adapter/v1",
            "generated_by": "ores-stack",
            "provider": "lunatic_lorry",
            "runtime_repository": "lunatic-lorry/ll-lambdas",
            "runtime_contract": "lunatic-lorry.lambda-runtime/v1",
            "execution_boundary": "lunatic_process",
            "isolation_model": "fresh_wasm_actor_per_invocation",
            "artifact_kind": "wasm_module",
            "module_cache_policy": "module_bytes_or_compiled_module_allowed",
            "invocation_instance_reuse": "forbidden",
            "ambient_import_policy": "explicit_lunatic_capabilities_only",
            "durable_state": "external_only",
            "source": "src/routes/echo/lambda.rs",
            "source_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }))?;
        return Ok(bytes);
    }

    fn receipt_bytes(adapter: &[u8], module: &[u8]) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&json!({
            "schema_version": RECEIPT_SCHEMA,
            "generated_by": "ores-stack",
            "provider": PROVIDER,
            "runtime_repository": "lunatic-lorry/ll-lambdas",
            "runtime_contract": "lunatic-lorry.lambda-runtime/v1",
            "adapter_contract": ADAPTER_SCHEMA,
            "artifact_path": "build/lambda/lunatic_lorry/module.wasm",
            "artifact_sha256": sha256_hex(module),
            "deploy_mutation_performed": false,
            "target_triple": TARGET_TRIPLE,
            "adapter_path": "generated/lambda-adapters/lunatic_lorry/adapter.json",
            "adapter_sha256": sha256_hex(adapter),
            "source_path": "src/routes/echo/lambda.rs",
            "source_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "cargo_manifest_path": "Cargo.toml",
            "cargo_package": "fixture",
            "cargo_target_name": "ores_wasm_lambda_unit",
            "wrapper_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "unit_manifest_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        }))?;
        return Ok(bytes);
    }

    #[test]
    fn exact_receipt_binds_raw_adapter_and_module() -> Result<()> {
        let adapter_bytes = adapter_bytes()?;
        let structured: OresLambdaAdapterV1 = serde_json::from_slice(&adapter_bytes)?;
        let module = b"wasm-module";
        let receipt = receipt_bytes(&adapter_bytes, module)?;
        let evidence = verify(&structured, &adapter_bytes, &receipt, module)?;
        assert_eq!(evidence.adapter_raw_sha256, sha256_hex(&adapter_bytes));
        assert_eq!(evidence.artifact_sha256, sha256_hex(module));
        return Ok(());
    }

    #[test]
    fn receipt_rejects_reformatted_adapter_or_artifact_drift() -> Result<()> {
        let adapter_bytes = adapter_bytes()?;
        let structured: OresLambdaAdapterV1 = serde_json::from_slice(&adapter_bytes)?;
        let receipt = receipt_bytes(&adapter_bytes, b"wasm-module")?;

        let mut reformatted = adapter_bytes.clone();
        reformatted.push(b'\n');
        assert!(verify(&structured, &reformatted, &receipt, b"wasm-module").is_err());
        assert!(verify(&structured, &adapter_bytes, &receipt, b"other-module").is_err());
        return Ok(());
    }
}
