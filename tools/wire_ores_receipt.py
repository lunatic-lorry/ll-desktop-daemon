from pathlib import Path

main_path = Path("src/main.rs")
text = main_path.read_text()


def replace_once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    text = text.replace(old, new, 1)


replace_once("mod ores_adapter;", "mod ores_adapter;\nmod ores_receipt;", "module declaration")
replace_once(
    '''    #[serde(default)]\n    ores_adapter: Option<OresLambdaAdapterV1>,\n}''',
    '''    #[serde(default)]\n    ores_adapter: Option<OresLambdaAdapterV1>,\n    #[serde(default)]\n    ores_adapter_raw_base64: Option<String>,\n    #[serde(default)]\n    ores_receipt_raw_base64: Option<String>,\n}''',
    "deploy request evidence fields",
)
replace_once(
    '''    module_bytes: usize,\n    ores_adapter_verified: bool,\n}''',
    '''    module_bytes: usize,\n    ores_adapter_verified: bool,\n    ores_receipt_verified: bool,\n}''',
    "deploy response receipt state",
)
replace_once(
    '''    validate_wasm_module(&bytes)?;\n    state\n        .lunatic''',
    '''    validate_wasm_module(&bytes)?;\n    let ores_build_evidence = match (\n        request.ores_adapter.as_ref(),\n        request.ores_adapter_raw_base64.as_deref(),\n        request.ores_receipt_raw_base64.as_deref(),\n    ) {\n        (Some(adapter), Some(raw_adapter), Some(raw_receipt)) => {\n            let raw_adapter = BASE64.decode(raw_adapter.as_bytes()).map_err(|_| {\n                (\n                    StatusCode::BAD_REQUEST,\n                    "ores_adapter_raw_base64 is not valid base64".to_owned(),\n                )\n            })?;\n            let raw_receipt = BASE64.decode(raw_receipt.as_bytes()).map_err(|_| {\n                (\n                    StatusCode::BAD_REQUEST,\n                    "ores_receipt_raw_base64 is not valid base64".to_owned(),\n                )\n            })?;\n            Some(ores_receipt::verify(adapter, &raw_adapter, &raw_receipt, &bytes).map_err(\n                |error| {\n                    (\n                        StatusCode::BAD_REQUEST,\n                        format!("ORES WASM receipt validation failed: {error}"),\n                    )\n                },\n            )?)\n        }\n        (_, None, None) => None,\n        _ => {\n            return Err((\n                StatusCode::BAD_REQUEST,\n                "ORES receipt evidence requires ores_adapter plus exact raw adapter and receipt bytes"\n                    .to_owned(),\n            ));\n        }\n    };\n    state\n        .lunatic''',
    "server receipt verification",
)
replace_once(
    '''    let manifest = DeploymentManifest::new(\n        &request.tenant_id,\n        &request.deployment_id,\n        &bytes,\n        ores_provenance,\n    )''',
    '''    let manifest = DeploymentManifest::new_with_evidence(\n        &request.tenant_id,\n        &request.deployment_id,\n        &bytes,\n        ores_provenance,\n        ores_build_evidence.clone(),\n    )''',
    "manifest build evidence construction",
)
replace_once(
    '''        module_bytes: bytes.len(),\n        ores_adapter_verified: manifest.ores_adapter_verified,\n    }));''',
    '''        module_bytes: bytes.len(),\n        ores_adapter_verified: manifest.ores_adapter_verified,\n        ores_receipt_verified: ores_build_evidence.is_some(),\n    }));''',
    "response receipt state",
)
main_path.write_text(text)

manifest_path = Path("src/deployment_manifest.rs")
manifest = manifest_path.read_text()


def manifest_replace(old: str, new: str, label: str) -> None:
    global manifest
    count = manifest.count(old)
    if count != 1:
        raise SystemExit(f"manifest {label}: expected exactly one match, found {count}")
    manifest = manifest.replace(old, new, 1)


manifest_replace(
    "use crate::ores_adapter::OresDeploymentProvenance;",
    "use crate::{ores_adapter::OresDeploymentProvenance, ores_receipt::OresBuildEvidence};",
    "receipt import",
)
manifest_replace(
    '''    #[serde(default, skip_serializing_if = "Option::is_none")]\n    pub ores_provenance: Option<OresDeploymentProvenance>,\n}''',
    '''    #[serde(default, skip_serializing_if = "Option::is_none")]\n    pub ores_provenance: Option<OresDeploymentProvenance>,\n    #[serde(default, skip_serializing_if = "Option::is_none")]\n    pub ores_build_evidence: Option<OresBuildEvidence>,\n}''',
    "manifest receipt field",
)
manifest_replace(
    '''    pub fn new(\n        tenant_id: &str,\n        deployment_id: &str,\n        module: &[u8],\n        ores_provenance: Option<OresDeploymentProvenance>,\n    ) -> Result<Self> {\n        let manifest = Self {''',
    '''    pub fn new(\n        tenant_id: &str,\n        deployment_id: &str,\n        module: &[u8],\n        ores_provenance: Option<OresDeploymentProvenance>,\n    ) -> Result<Self> {\n        return Self::new_with_evidence(\n            tenant_id,\n            deployment_id,\n            module,\n            ores_provenance,\n            None,\n        );\n    }\n\n    pub fn new_with_evidence(\n        tenant_id: &str,\n        deployment_id: &str,\n        module: &[u8],\n        ores_provenance: Option<OresDeploymentProvenance>,\n        ores_build_evidence: Option<OresBuildEvidence>,\n    ) -> Result<Self> {\n        let manifest = Self {''',
    "constructor extension",
)
manifest_replace(
    '''            ores_adapter_verified: ores_provenance.is_some(),\n            ores_provenance,\n        };''',
    '''            ores_adapter_verified: ores_provenance.is_some(),\n            ores_provenance,\n            ores_build_evidence,\n        };''',
    "constructor evidence assignment",
)
manifest_replace(
    '''            (None, false) => {}\n        }\n        return Ok(());''',
    '''            (None, false) => {}\n        }\n        if let Some(evidence) = self.ores_build_evidence.as_ref() {\n            evidence.validate()?;\n            if !self.ores_adapter_verified || self.ores_provenance.is_none() {\n                bail!("ORES build evidence requires verified adapter provenance");\n            }\n            if evidence.artifact_sha256 != self.module_sha256 {\n                bail!("ORES build evidence artifact digest does not match module manifest");\n            }\n        }\n        return Ok(());''',
    "build evidence validation",
)
manifest_path.write_text(manifest)
