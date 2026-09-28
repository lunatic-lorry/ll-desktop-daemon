use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::ores_adapter::OresDeploymentProvenance;

pub const DEPLOYMENT_MANIFEST_SCHEMA: &str = "lunatic-lorry.deployment/v1";
const MANIFEST_FILE: &str = "deployment.json";
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentManifest {
    pub schema_version: String,
    pub tenant_id: String,
    pub deployment_id: String,
    pub module_sha256: String,
    pub module_bytes: u64,
    pub ores_adapter_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ores_provenance: Option<OresDeploymentProvenance>,
}

impl DeploymentManifest {
    pub fn new(
        tenant_id: &str,
        deployment_id: &str,
        module: &[u8],
        ores_provenance: Option<OresDeploymentProvenance>,
    ) -> Result<Self> {
        let manifest = Self {
            schema_version: DEPLOYMENT_MANIFEST_SCHEMA.to_owned(),
            tenant_id: tenant_id.to_owned(),
            deployment_id: deployment_id.to_owned(),
            module_sha256: format!("{:x}", Sha256::digest(module)),
            module_bytes: module.len() as u64,
            ores_adapter_verified: ores_provenance.is_some(),
            ores_provenance,
        };
        manifest.validate(tenant_id, deployment_id)?;
        return Ok(manifest);
    }

    pub fn validate(&self, tenant_id: &str, deployment_id: &str) -> Result<()> {
        if self.schema_version != DEPLOYMENT_MANIFEST_SCHEMA {
            bail!("deployment manifest schema is unsupported");
        }
        if self.tenant_id != tenant_id || self.deployment_id != deployment_id {
            bail!("deployment manifest identity does not match storage path");
        }
        validate_sha256(&self.module_sha256)?;
        if self.module_bytes == 0 {
            bail!("deployment manifest module_bytes must be positive");
        }
        match (&self.ores_provenance, self.ores_adapter_verified) {
            (Some(provenance), true) => provenance.validate()?,
            (Some(_), false) => {
                bail!("deployment manifest cannot carry ORES provenance without verification");
            }
            (None, true) => {
                bail!("deployment evidence cannot claim ORES verification without provenance");
            }
            (None, false) => {}
        }
        return Ok(());
    }

    pub fn verify_module(&self, module: &[u8]) -> Result<()> {
        self.validate(&self.tenant_id, &self.deployment_id)?;
        if self.module_bytes != module.len() as u64 {
            bail!("deployment manifest module size does not match module.wasm");
        }
        let actual = format!("{:x}", Sha256::digest(module));
        if actual != self.module_sha256 {
            bail!("deployment manifest module digest does not match module.wasm");
        }
        return Ok(());
    }
}

pub async fn verify_existing_or_legacy(
    deployment: &Path,
    incoming: &DeploymentManifest,
    module: &[u8],
) -> Result<()> {
    let Some(existing) = read_if_present(deployment).await? else {
        if incoming.ores_adapter_verified {
            bail!(
                "legacy deployment has no persisted ORES provenance; delete and redeploy under a new immutable generation"
            );
        }
        return Ok(());
    };
    existing.validate(&incoming.tenant_id, &incoming.deployment_id)?;
    existing.verify_module(module)?;
    if existing != *incoming {
        bail!("deployment id already exists with different immutable manifest evidence");
    }
    return Ok(());
}

pub async fn verify_persisted_module_if_present(
    deployment: &Path,
    tenant_id: &str,
    deployment_id: &str,
    module: &[u8],
) -> Result<bool> {
    let Some(manifest) = read_if_present(deployment).await? else {
        return Ok(false);
    };
    manifest.validate(tenant_id, deployment_id)?;
    manifest.verify_module(module)?;
    return Ok(true);
}

async fn read_if_present(deployment: &Path) -> Result<Option<DeploymentManifest>> {
    let path = deployment.join(MANIFEST_FILE);
    let metadata = match tokio::fs::symlink_metadata(&path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("could not inspect deployment manifest"),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("deployment manifest must be a regular non-symlink file");
    }
    if metadata.len() > MAX_MANIFEST_BYTES as u64 {
        bail!("deployment manifest exceeds size limit");
    }
    let bytes = tokio::fs::read(&path)
        .await
        .context("could not read deployment manifest")?;
    let manifest: DeploymentManifest =
        serde_json::from_slice(&bytes).context("deployment manifest JSON is invalid")?;
    return Ok(Some(manifest));
}

pub async fn write_new(deployment: &Path, manifest: &DeploymentManifest) -> Result<()> {
    manifest.validate(&manifest.tenant_id, &manifest.deployment_id)?;
    let final_path = deployment.join(MANIFEST_FILE);
    if tokio::fs::symlink_metadata(&final_path).await.is_ok() {
        bail!("deployment manifest already exists");
    }
    let temporary = deployment.join(format!(".deployment-{}.tmp", Uuid::new_v4().simple()));
    let bytes = serde_json::to_vec_pretty(manifest)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        bail!("deployment manifest exceeds size limit");
    }
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .await
        .with_context(|| format!("could not create {}", temporary.display()))?;
    if let Err(error) = file.write_all(&bytes).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error).context("could not write temporary deployment manifest");
    }
    if let Err(error) = file.sync_all().await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error).context("could not sync temporary deployment manifest");
    }
    drop(file);
    match tokio::fs::hard_link(&temporary, &final_path).await {
        Ok(()) => {
            tokio::fs::remove_file(&temporary).await?;
            return Ok(());
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error).context("could not atomically publish deployment manifest");
        }
    }
}

fn validate_sha256(value: &str) -> Result<()> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    if !valid {
        bail!("deployment manifest SHA-256 must be 64 lowercase hexadecimal characters");
    }
    return Ok(());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> OresDeploymentProvenance {
        return OresDeploymentProvenance {
            adapter_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            source: "src/routes/echo/lambda.rs".to_owned(),
            source_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
        };
    }

    #[test]
    fn module_and_provenance_are_part_of_immutable_identity() -> Result<()> {
        let first = DeploymentManifest::new("tenant", "v1", b"wasm-a", Some(provenance()))?;
        first.verify_module(b"wasm-a")?;

        let mut changed = provenance();
        changed.source_sha256 =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned();
        let second = DeploymentManifest::new("tenant", "v1", b"wasm-a", Some(changed))?;
        assert_ne!(first, second);
        return Ok(());
    }

    #[test]
    fn tampered_module_or_invalid_provenance_fails_closed() -> Result<()> {
        let manifest = DeploymentManifest::new("tenant", "v1", b"wasm-a", Some(provenance()))?;
        assert!(manifest.verify_module(b"wasm-b").is_err());

        let mut invalid = manifest;
        invalid.ores_adapter_verified = false;
        assert!(invalid.validate("tenant", "v1").is_err());
        return Ok(());
    }

    #[tokio::test]
    async fn legacy_deployment_cannot_gain_ores_provenance_in_place() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("ll-manifest-legacy-{}", Uuid::new_v4().simple()));
        tokio::fs::create_dir_all(&root).await?;
        let incoming = DeploymentManifest::new("tenant", "v1", b"wasm-a", Some(provenance()))?;
        assert!(
            verify_existing_or_legacy(&root, &incoming, b"wasm-a")
                .await
                .is_err()
        );
        tokio::fs::remove_dir_all(root).await?;
        return Ok(());
    }

    #[tokio::test]
    async fn persisted_manifest_is_checked_on_redeploy_and_invocation() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("ll-manifest-persist-{}", Uuid::new_v4().simple()));
        tokio::fs::create_dir_all(&root).await?;
        let first = DeploymentManifest::new("tenant", "v1", b"wasm-a", Some(provenance()))?;
        write_new(&root, &first).await?;
        verify_existing_or_legacy(&root, &first, b"wasm-a").await?;
        assert!(verify_persisted_module_if_present(&root, "tenant", "v1", b"wasm-a").await?);
        assert!(
            verify_persisted_module_if_present(&root, "tenant", "v1", b"wasm-b")
                .await
                .is_err()
        );

        let mut changed = provenance();
        changed.source_sha256 =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned();
        let second = DeploymentManifest::new("tenant", "v1", b"wasm-a", Some(changed))?;
        assert!(
            verify_existing_or_legacy(&root, &second, b"wasm-a")
                .await
                .is_err()
        );
        tokio::fs::remove_dir_all(root).await?;
        return Ok(());
    }
}
