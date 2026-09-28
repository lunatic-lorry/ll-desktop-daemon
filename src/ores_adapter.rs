use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path};

pub const ORES_LAMBDA_ADAPTER_SCHEMA: &str = "ores.lambda.adapter/v1";
pub const ORES_GENERATOR: &str = "ores-stack";
pub const LL_PROVIDER: &str = "lunatic_lorry";
pub const LL_RUNTIME_REPOSITORY: &str = "lunatic-lorry/ll-lambdas";
pub const LL_RUNTIME_CONTRACT: &str = "lunatic-lorry.lambda-runtime/v1";
pub const LL_EXECUTION_BOUNDARY: &str = "lunatic_process";
pub const LL_ISOLATION_MODEL: &str = "fresh_wasm_actor_per_invocation";
pub const LL_ARTIFACT_KIND: &str = "wasm_module";
pub const LL_MODULE_CACHE_POLICY: &str = "module_bytes_or_compiled_module_allowed";
pub const LL_INSTANCE_REUSE: &str = "forbidden";
pub const LL_AMBIENT_IMPORT_POLICY: &str = "explicit_lunatic_capabilities_only";
pub const LL_DURABLE_STATE: &str = "external_only";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OresLambdaAdapterV1 {
    schema_version: String,
    generated_by: String,
    provider: String,
    runtime_repository: String,
    runtime_contract: String,
    execution_boundary: String,
    isolation_model: String,
    artifact_kind: String,
    module_cache_policy: String,
    invocation_instance_reuse: String,
    ambient_import_policy: String,
    durable_state: String,
    source: String,
    source_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OresDeploymentProvenance {
    pub adapter_sha256: String,
    pub source: String,
    pub source_sha256: String,
}

impl OresDeploymentProvenance {
    pub fn validate(&self) -> Result<()> {
        validate_sha256(&self.adapter_sha256)?;
        validate_source_path(&self.source)?;
        validate_sha256(&self.source_sha256)?;
        return Ok(());
    }
}

impl OresLambdaAdapterV1 {
    pub fn validate(&self) -> Result<()> {
        require_eq(
            "schema_version",
            &self.schema_version,
            ORES_LAMBDA_ADAPTER_SCHEMA,
        )?;
        require_eq("generated_by", &self.generated_by, ORES_GENERATOR)?;
        require_eq("provider", &self.provider, LL_PROVIDER)?;
        require_eq(
            "runtime_repository",
            &self.runtime_repository,
            LL_RUNTIME_REPOSITORY,
        )?;
        require_eq(
            "runtime_contract",
            &self.runtime_contract,
            LL_RUNTIME_CONTRACT,
        )?;
        require_eq(
            "execution_boundary",
            &self.execution_boundary,
            LL_EXECUTION_BOUNDARY,
        )?;
        require_eq("isolation_model", &self.isolation_model, LL_ISOLATION_MODEL)?;
        require_eq("artifact_kind", &self.artifact_kind, LL_ARTIFACT_KIND)?;
        require_eq(
            "module_cache_policy",
            &self.module_cache_policy,
            LL_MODULE_CACHE_POLICY,
        )?;
        require_eq(
            "invocation_instance_reuse",
            &self.invocation_instance_reuse,
            LL_INSTANCE_REUSE,
        )?;
        require_eq(
            "ambient_import_policy",
            &self.ambient_import_policy,
            LL_AMBIENT_IMPORT_POLICY,
        )?;
        require_eq("durable_state", &self.durable_state, LL_DURABLE_STATE)?;
        validate_source_path(&self.source)?;
        validate_sha256(&self.source_sha256)?;
        return Ok(());
    }

    pub fn semantic_sha256(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)?;
        return Ok(format!("{:x}", Sha256::digest(bytes)));
    }

    pub fn deployment_provenance(&self) -> Result<OresDeploymentProvenance> {
        self.validate()?;
        let provenance = OresDeploymentProvenance {
            adapter_sha256: self.semantic_sha256()?,
            source: self.source.clone(),
            source_sha256: self.source_sha256.clone(),
        };
        provenance.validate()?;
        return Ok(provenance);
    }
}

fn require_eq(name: &str, actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        bail!("ORES adapter {name} must be {expected:?}, found {actual:?}");
    }
    return Ok(());
}

fn validate_source_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    let valid = !value.is_empty()
        && !value.contains('\0')
        && !value.contains('\\')
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    if !valid {
        bail!("ORES adapter source must be a normalized repository-relative path");
    }
    return Ok(());
}

fn validate_sha256(value: &str) -> Result<()> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    if !valid {
        bail!("ORES SHA-256 values must be 64 lowercase hexadecimal characters");
    }
    return Ok(());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_adapter() -> OresLambdaAdapterV1 {
        return OresLambdaAdapterV1 {
            schema_version: ORES_LAMBDA_ADAPTER_SCHEMA.to_owned(),
            generated_by: ORES_GENERATOR.to_owned(),
            provider: LL_PROVIDER.to_owned(),
            runtime_repository: LL_RUNTIME_REPOSITORY.to_owned(),
            runtime_contract: LL_RUNTIME_CONTRACT.to_owned(),
            execution_boundary: LL_EXECUTION_BOUNDARY.to_owned(),
            isolation_model: LL_ISOLATION_MODEL.to_owned(),
            artifact_kind: LL_ARTIFACT_KIND.to_owned(),
            module_cache_policy: LL_MODULE_CACHE_POLICY.to_owned(),
            invocation_instance_reuse: LL_INSTANCE_REUSE.to_owned(),
            ambient_import_policy: LL_AMBIENT_IMPORT_POLICY.to_owned(),
            durable_state: LL_DURABLE_STATE.to_owned(),
            source: "src/routes/echo/lambda.rs".to_owned(),
            source_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
        };
    }

    #[test]
    fn exact_current_ores_adapter_is_admitted() -> Result<()> {
        return valid_adapter().validate();
    }

    #[test]
    fn deployment_provenance_binds_semantic_adapter_and_source() -> Result<()> {
        let adapter = valid_adapter();
        let provenance = adapter.deployment_provenance()?;
        provenance.validate()?;
        assert_eq!(provenance.adapter_sha256, adapter.semantic_sha256()?);
        assert_eq!(provenance.source, "src/routes/echo/lambda.rs");
        assert_eq!(
            provenance.source_sha256,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        return Ok(());
    }

    #[test]
    fn reuse_and_capability_widening_fail_closed() {
        let mut adapter = valid_adapter();
        adapter.invocation_instance_reuse = "allowed".to_owned();
        assert!(adapter.validate().is_err());

        let mut adapter = valid_adapter();
        adapter.source = "generated/provider-neutral.rs".to_owned();
        assert!(adapter.validate().is_ok());

        let mut adapter = valid_adapter();
        adapter.ambient_import_policy = "ambient_wasi".to_owned();
        assert!(adapter.validate().is_err());
    }
}
