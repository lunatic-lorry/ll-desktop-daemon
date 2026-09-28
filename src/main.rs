mod ores_adapter;

use anyhow::{Context as _, Result, anyhow, bail};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use flags2env::BundledFlags2Env;
use ores_adapter::{
    LL_EXECUTION_BOUNDARY, LL_ISOLATION_MODEL, LL_RUNTIME_CONTRACT, OresLambdaAdapterV1,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::Semaphore,
    time::timeout,
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

const MAX_TIMEOUT_MS: u64 = 20 * 60 * 1_000;
const MAX_MODULE_BYTES: usize = 64 * 1024 * 1024;
const MAX_BODY_BYTES: usize = MAX_MODULE_BYTES * 2;
const MAX_PARALLELISM: usize = 256;
const MAX_INVOCATION_BYTES: usize = 10 * 1024 * 1024;
const MAX_WORKER_STDOUT_BYTES: usize = 10 * 1024 * 1024;
const MAX_WORKER_STDERR_BYTES: usize = 64 * 1024;
const WASM_HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
struct CliConfig {
    LL_DESKTOP_ADDR: String,
    LL_RUNTIME_COMMAND: String,
    LL_WORKER_ARGS_JSON: String,
    LL_MAX_PARALLEL_INVOCATIONS: i64,
    LL_DESKTOP_TOKEN_FILE: Option<String>,
    LL_DESKTOP_LOG: String,
}

#[derive(Debug)]
struct RuntimeConfig {
    addr: SocketAddr,
    worker_command: String,
    worker_args: Vec<String>,
    parallelism: usize,
    token_path: PathBuf,
    artifact_root: PathBuf,
    log_filter: String,
}

#[derive(Clone)]
struct AppState {
    token: Arc<str>,
    worker_command: Arc<str>,
    worker_args: Arc<Vec<String>>,
    artifact_root: Arc<PathBuf>,
    permits: Arc<Semaphore>,
    started_at: Instant,
    accepted: Arc<AtomicU64>,
    completed: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeployRequest {
    tenant_id: String,
    deployment_id: String,
    wasm_base64: String,
    #[serde(default)]
    ores_adapter: Option<OresLambdaAdapterV1>,
}

#[derive(Debug, Serialize)]
struct DeployResponse {
    tenant_id: String,
    deployment_id: String,
    sha256: String,
    module_bytes: usize,
    ores_adapter_verified: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DeploymentManifest {
    schema_version: String,
    tenant_id: String,
    deployment_id: String,
    module_sha256: String,
    module_bytes: u64,
    runtime_contract: String,
    execution_boundary: String,
    isolation_model: String,
    ores_adapter_verified: bool,
    ores_adapter_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InvocationRequest {
    invocation_id: String,
    tenant_id: String,
    deployment_id: String,
    payload_json: Value,
    timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct InvocationResponse {
    invocation_id: String,
    deployment_id: String,
    ok: bool,
    payload_json: Option<Value>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    runtime: &'static str,
    actor_reusable: bool,
    worker_mode: &'static str,
    config_source: &'static str,
    deployment_mode: &'static str,
    uptime_ms: u128,
    accepted: u64,
    completed: u64,
    failed: u64,
    available_slots: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = load_config()?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(&config.log_filter).context("invalid tracing filter")?)
        .init();

    let token = load_or_create_token(&config.token_path)?;
    tokio::fs::create_dir_all(&config.artifact_root).await?;
    validate_real_directory(&config.artifact_root, "artifact root").await?;
    let state = AppState {
        token: Arc::from(token),
        worker_command: Arc::from(config.worker_command),
        worker_args: Arc::new(config.worker_args),
        artifact_root: Arc::new(config.artifact_root),
        permits: Arc::new(Semaphore::new(config.parallelism)),
        started_at: Instant::now(),
        accepted: Arc::new(AtomicU64::new(0)),
        completed: Arc::new(AtomicU64::new(0)),
        failed: Arc::new(AtomicU64::new(0)),
    };

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/status", get(status))
        .route("/v1/doctor", get(status))
        .route("/v1/deploy", post(deploy))
        .route("/v1/invoke", post(invoke))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.addr).await?;
    tracing::info!(addr = %config.addr, "lunatic desktop daemon listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    return Ok(());
}

fn load_config() -> Result<RuntimeConfig> {
    let config_path = resolve_config_path()?;
    let config_path_text = config_path
        .to_str()
        .ok_or_else(|| anyhow!(".cli-flags.toml path is not UTF-8"))?;
    let parser = BundledFlags2Env::new();
    parser
        .audit_config(Some(config_path_text))
        .map_err(|error| anyhow!(error.to_string()))?;

    let argv = env::args().collect::<Vec<_>>();
    let parsed = parser
        .parse_structured(&argv, Some(config_path_text))
        .map_err(|error| anyhow!(error.to_string()))?;
    if !parsed.unknown_options.is_empty() {
        bail!(
            "unknown command-line options: {}",
            parsed.unknown_options.len()
        );
    }
    if !parsed.errors.is_empty() {
        bail!("invalid command-line values: {}", parsed.errors.join("; "));
    }
    if !parsed.extras.is_empty() {
        bail!("unexpected positional arguments: {}", parsed.extras.len());
    }

    let mut raw = env::vars().collect::<HashMap<_, _>>();
    raw.extend(parsed.provided_flags);
    let raw_config = parser
        .coerce::<CliConfig, _>(&raw, Some(config_path_text))
        .map_err(|error| anyhow!(error.to_string()))?;

    let addr = parse_loopback_addr(&raw_config.LL_DESKTOP_ADDR)?;
    let worker_command = raw_config.LL_RUNTIME_COMMAND.trim().to_owned();
    if worker_command.is_empty() {
        bail!("LL_RUNTIME_COMMAND may not be empty");
    }
    let worker_args = serde_json::from_str::<Vec<String>>(&raw_config.LL_WORKER_ARGS_JSON)
        .context("LL_WORKER_ARGS_JSON must be a JSON string array")?;
    if worker_args.len() > 128 || worker_args.iter().any(|value| value.len() > 16 * 1024) {
        bail!("worker argument vector exceeds desktop limits");
    }

    let parallelism = usize::try_from(raw_config.LL_MAX_PARALLEL_INVOCATIONS)
        .ok()
        .filter(|value| *value > 0 && *value <= MAX_PARALLELISM)
        .ok_or_else(|| {
            anyhow!("LL_MAX_PARALLEL_INVOCATIONS must be between 1 and {MAX_PARALLELISM}")
        })?;
    let token_path = match raw_config.LL_DESKTOP_TOKEN_FILE {
        Some(path) if !path.trim().is_empty() => expand_home(Path::new(&path))?,
        _ => default_token_path()?,
    };

    return Ok(RuntimeConfig {
        addr,
        worker_command,
        worker_args,
        parallelism,
        token_path,
        artifact_root: default_artifact_root()?,
        log_filter: raw_config.LL_DESKTOP_LOG,
    });
}

async fn health() -> &'static str {
    return "ok";
}

async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<StatusResponse>, (StatusCode, String)> {
    authorize(&headers, &state)?;
    return Ok(Json(StatusResponse {
        runtime: "lunatic_wasm",
        actor_reusable: false,
        worker_mode: "fresh_process",
        config_source: "flags-2-env",
        deployment_mode: "immutable_wasm_module",
        uptime_ms: state.started_at.elapsed().as_millis(),
        accepted: state.accepted.load(Ordering::Relaxed),
        completed: state.completed.load(Ordering::Relaxed),
        failed: state.failed.load(Ordering::Relaxed),
        available_slots: state.permits.available_permits(),
    }));
}

async fn deploy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeployRequest>,
) -> Result<Json<DeployResponse>, (StatusCode, String)> {
    authorize(&headers, &state)?;
    validate_identifier("tenant_id", &request.tenant_id)?;
    validate_identifier("deployment_id", &request.deployment_id)?;

    let (ores_adapter_verified, ores_adapter_sha256) = match request.ores_adapter.as_ref() {
        Some(adapter) => {
            adapter.validate().map_err(|error| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("ORES adapter validation failed: {error}"),
                )
            })?;
            let canonical = serde_json::to_vec(adapter).map_err(internal_error)?;
            (true, Some(format!("{:x}", Sha256::digest(&canonical))))
        }
        None => (false, None),
    };

    let bytes = BASE64.decode(request.wasm_base64.as_bytes()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "wasm_base64 is not valid base64".to_owned(),
        )
    })?;
    validate_wasm_module(&bytes)?;

    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let manifest = DeploymentManifest {
        schema_version: "lunatic-lorry.deployment/v1".to_owned(),
        tenant_id: request.tenant_id.clone(),
        deployment_id: request.deployment_id.clone(),
        module_sha256: sha256.clone(),
        module_bytes: u64::try_from(bytes.len()).map_err(internal_error)?,
        runtime_contract: LL_RUNTIME_CONTRACT.to_owned(),
        execution_boundary: LL_EXECUTION_BOUNDARY.to_owned(),
        isolation_model: LL_ISOLATION_MODEL.to_owned(),
        ores_adapter_verified,
        ores_adapter_sha256,
    };
    atomic_write_immutable_deployment(
        state.artifact_root.as_ref(),
        &request.tenant_id,
        &request.deployment_id,
        &bytes,
        &manifest,
    )
    .await
    .map_err(internal_error)?;

    return Ok(Json(DeployResponse {
        tenant_id: request.tenant_id,
        deployment_id: request.deployment_id,
        sha256,
        module_bytes: bytes.len(),
        ores_adapter_verified,
    }));
}

async fn invoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<InvocationRequest>,
) -> Result<Json<InvocationResponse>, (StatusCode, String)> {
    authorize(&headers, &state)?;
    validate_identifier("invocation_id", &request.invocation_id)?;
    validate_identifier("tenant_id", &request.tenant_id)?;
    validate_identifier("deployment_id", &request.deployment_id)?;

    let timeout_ms = request.timeout_ms.unwrap_or(30_000);
    if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("timeout_ms must be between 1 and {MAX_TIMEOUT_MS}"),
        ));
    }

    let permit = state
        .permits
        .clone()
        .acquire_owned()
        .await
        .map_err(internal_error)?;
    state.accepted.fetch_add(1, Ordering::Relaxed);

    let result = run_fresh_worker(&state, &request, Duration::from_millis(timeout_ms)).await;
    drop(permit);
    state.completed.fetch_add(1, Ordering::Relaxed);
    if result.is_err() {
        state.failed.fetch_add(1, Ordering::Relaxed);
    }

    let response = match result {
        Ok(payload_json) => InvocationResponse {
            invocation_id: request.invocation_id,
            deployment_id: request.deployment_id,
            ok: true,
            payload_json: Some(payload_json),
            error: None,
        },
        Err(error) => InvocationResponse {
            invocation_id: request.invocation_id,
            deployment_id: request.deployment_id,
            ok: false,
            payload_json: None,
            error: Some(error.to_string()),
        },
    };
    return Ok(Json(response));
}

async fn run_fresh_worker(
    state: &AppState,
    request: &InvocationRequest,
    deadline: Duration,
) -> Result<Value> {
    let manifest = verify_deployment(
        state.artifact_root.as_ref(),
        &request.tenant_id,
        &request.deployment_id,
    )
    .await?;
    let module_path = artifact_path(
        state.artifact_root.as_ref(),
        &request.tenant_id,
        &request.deployment_id,
    )?;
    if !manifest.ores_adapter_verified && manifest.ores_adapter_sha256.is_some() {
        bail!("deployment manifest carries adapter digest without verified adapter");
    }
    let metadata = tokio::fs::symlink_metadata(&module_path)
        .await
        .with_context(|| format!("deployment module {} is unavailable", module_path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "deployment module {} must be a regular file",
            module_path.display()
        );
    }
    let module_text = module_path
        .to_str()
        .ok_or_else(|| anyhow!("deployment module path is not UTF-8"))?;
    let mut worker_args = Vec::with_capacity(state.worker_args.len() + 1);
    let mut inserted_module = false;
    for argument in state.worker_args.iter() {
        if argument == "{module}" {
            worker_args.push(module_text.to_owned());
            inserted_module = true;
        } else {
            worker_args.push(argument.clone());
        }
    }
    if !inserted_module {
        worker_args.push(module_text.to_owned());
    }

    let payload = serde_json::to_vec(&request.payload_json)?;
    if payload.len() > MAX_INVOCATION_BYTES {
        bail!("invocation payload exceeds {MAX_INVOCATION_BYTES} bytes");
    }

    let mut child = Command::new(state.worker_command.as_ref())
        .args(worker_args)
        .env("LL_TENANT_ID", &request.tenant_id)
        .env("LL_DEPLOYMENT_ID", &request.deployment_id)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to start {}", state.worker_command))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("worker stdin unavailable"))?;
    stdin.write_all(&payload).await?;
    stdin.shutdown().await?;
    drop(stdin);

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("worker stdout unavailable"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("worker stderr unavailable"))?;

    let (status, stdout, stderr) = timeout(deadline, async {
        let (status, stdout, stderr) = tokio::join!(
            child.wait(),
            read_bounded(&mut stdout, MAX_WORKER_STDOUT_BYTES, "stdout"),
            read_bounded(&mut stderr, MAX_WORKER_STDERR_BYTES, "stderr"),
        );
        return Ok::<_, anyhow::Error>((status?, stdout?, stderr?));
    })
    .await
    .map_err(|_| anyhow!("invocation timed out; fresh WASM worker was terminated"))??;

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        let summary = stderr
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("worker exited unsuccessfully");
        bail!("worker failed: {}", truncate(summary, 512));
    }

    let stdout = String::from_utf8(stdout).context("worker stdout was not UTF-8")?;
    let payload_json = serde_json::from_str(stdout.trim()).context("worker stdout was not JSON")?;
    return Ok(payload_json);
}

async fn read_bounded<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut limited = reader.take(limit as u64 + 1);
    limited
        .read_to_end(&mut bytes)
        .await
        .with_context(|| format!("could not read worker {label}"))?;
    if bytes.len() > limit {
        bail!("worker {label} exceeds {limit} bytes");
    }
    return Ok(bytes);
}

fn validate_wasm_module(bytes: &[u8]) -> Result<(), (StatusCode, String)> {
    if bytes.len() < WASM_HEADER.len() || !bytes.starts_with(WASM_HEADER) {
        return Err((
            StatusCode::BAD_REQUEST,
            "module is not a WebAssembly 1 binary".to_owned(),
        ));
    }
    if bytes.len() > MAX_MODULE_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("module exceeds {MAX_MODULE_BYTES} bytes"),
        ));
    }
    return Ok(());
}

fn artifact_path(root: &Path, tenant_id: &str, deployment_id: &str) -> Result<PathBuf> {
    validate_path_component(tenant_id)?;
    validate_path_component(deployment_id)?;
    return Ok(root.join(tenant_id).join(deployment_id).join("module.wasm"));
}

fn manifest_path(root: &Path, tenant_id: &str, deployment_id: &str) -> Result<PathBuf> {
    validate_path_component(tenant_id)?;
    validate_path_component(deployment_id)?;
    return Ok(root.join(tenant_id).join(deployment_id).join("manifest.json"));
}

fn validate_path_component(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && value != "."
        && value != "..";
    if !valid {
        bail!("invalid deployment path component");
    }
    return Ok(());
}

async fn validate_real_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .with_context(|| format!("could not inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{label} {} must be a real directory", path.display());
    }
    return Ok(());
}

async fn ensure_real_directory(path: &Path, label: &str) -> Result<()> {
    match tokio::fs::create_dir(path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("could not create {label} {}", path.display()));
        }
    }
    return validate_real_directory(path, label).await;
}

async fn validate_deployment_directory(
    root: &Path,
    tenant_id: &str,
    deployment_id: &str,
    create: bool,
) -> Result<PathBuf> {
    validate_path_component(tenant_id)?;
    validate_path_component(deployment_id)?;
    validate_real_directory(root, "artifact root").await?;
    let canonical_root = tokio::fs::canonicalize(root)
        .await
        .context("could not resolve artifact root")?;

    let tenant = root.join(tenant_id);
    if create {
        ensure_real_directory(&tenant, "tenant deployment directory").await?;
    } else {
        validate_real_directory(&tenant, "tenant deployment directory").await?;
    }

    let deployment = tenant.join(deployment_id);
    if create {
        ensure_real_directory(&deployment, "deployment generation directory").await?;
    } else {
        validate_real_directory(&deployment, "deployment generation directory").await?;
    }

    let canonical_deployment = tokio::fs::canonicalize(&deployment)
        .await
        .context("could not resolve deployment generation directory")?;
    if !canonical_deployment.starts_with(&canonical_root) {
        bail!("deployment generation directory escapes artifact root");
    }
    return Ok(deployment);
}

async fn atomic_write_immutable_deployment(
    root: &Path,
    tenant_id: &str,
    deployment_id: &str,
    bytes: &[u8],
    manifest: &DeploymentManifest,
) -> Result<()> {
    let deployment = validate_deployment_directory(root, tenant_id, deployment_id, true).await?;
    let path = deployment.join("module.wasm");
    if let Ok(metadata) = tokio::fs::symlink_metadata(&path).await {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "deployment module {} must be a regular file",
                path.display()
            );
        }
        let existing = tokio::fs::read(&path).await?;
        if existing == bytes {
            return publish_immutable_manifest(root, tenant_id, deployment_id, manifest).await;
        }
        bail!("deployment id already exists with different module bytes");
    }

    let temporary = deployment.join(format!(".module-{}.tmp", Uuid::new_v4().simple()));
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .await
        .with_context(|| format!("could not create {}", temporary.display()))?;
    if let Err(error) = file.write_all(bytes).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error).context("could not write temporary deployment module");
    }
    if let Err(error) = file.sync_all().await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error).context("could not sync temporary deployment module");
    }
    drop(file);

    validate_deployment_directory(root, tenant_id, deployment_id, false).await?;
    match tokio::fs::hard_link(&temporary, &path).await {
        Ok(()) => {
            tokio::fs::remove_file(&temporary).await?;
            return publish_immutable_manifest(root, tenant_id, deployment_id, manifest).await;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = tokio::fs::remove_file(&temporary).await;
            let metadata = tokio::fs::symlink_metadata(&path).await?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!(
                    "deployment module {} must be a regular file",
                    path.display()
                );
            }
            let existing = tokio::fs::read(&path).await?;
            if existing == bytes {
                return publish_immutable_manifest(root, tenant_id, deployment_id, manifest).await;
            }
            bail!("deployment id already exists with different module bytes");
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error).context("could not atomically publish deployment module");
        }
    }
}

async fn publish_immutable_manifest(
    root: &Path,
    tenant_id: &str,
    deployment_id: &str,
    manifest: &DeploymentManifest,
) -> Result<()> {
    let deployment = validate_deployment_directory(root, tenant_id, deployment_id, false).await?;
    let path = manifest_path(root, tenant_id, deployment_id)?;
    let mut bytes = serde_json::to_vec_pretty(manifest)?;
    bytes.push(b'\n');

    if let Ok(metadata) = tokio::fs::symlink_metadata(&path).await {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("deployment manifest {} must be a regular file", path.display());
        }
        let existing = tokio::fs::read(&path).await?;
        if existing == bytes {
            return Ok(());
        }
        bail!("deployment id already exists with different manifest evidence");
    }

    let temporary = deployment.join(format!(".manifest-{}.tmp", Uuid::new_v4().simple()));
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

    validate_deployment_directory(root, tenant_id, deployment_id, false).await?;
    match tokio::fs::hard_link(&temporary, &path).await {
        Ok(()) => {
            tokio::fs::remove_file(&temporary).await?;
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = tokio::fs::remove_file(&temporary).await;
            let metadata = tokio::fs::symlink_metadata(&path).await?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("deployment manifest {} must be a regular file", path.display());
            }
            let existing = tokio::fs::read(&path).await?;
            if existing == bytes {
                return Ok(());
            }
            bail!("deployment id already exists with different manifest evidence");
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error).context("could not atomically publish deployment manifest");
        }
    }
}

async fn verify_deployment(
    root: &Path,
    tenant_id: &str,
    deployment_id: &str,
) -> Result<DeploymentManifest> {
    validate_deployment_directory(root, tenant_id, deployment_id, false).await?;
    let module_path = artifact_path(root, tenant_id, deployment_id)?;
    let manifest_path = manifest_path(root, tenant_id, deployment_id)?;

    for (path, label) in [
        (&module_path, "deployment module"),
        (&manifest_path, "deployment manifest"),
    ] {
        let metadata = tokio::fs::symlink_metadata(path)
            .await
            .with_context(|| format!("{label} {} is unavailable", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("{label} {} must be a regular file", path.display());
        }
    }

    let manifest_bytes = tokio::fs::read(&manifest_path).await?;
    if manifest_bytes.len() > 64 * 1024 {
        bail!("deployment manifest exceeds 65536 bytes");
    }
    let manifest: DeploymentManifest =
        serde_json::from_slice(&manifest_bytes).context("deployment manifest is invalid")?;
    if manifest.schema_version != "lunatic-lorry.deployment/v1"
        || manifest.tenant_id != tenant_id
        || manifest.deployment_id != deployment_id
        || manifest.runtime_contract != LL_RUNTIME_CONTRACT
        || manifest.execution_boundary != LL_EXECUTION_BOUNDARY
        || manifest.isolation_model != LL_ISOLATION_MODEL
    {
        bail!("deployment manifest does not match the Lunatic runtime contract");
    }

    let module = tokio::fs::read(&module_path).await?;
    if u64::try_from(module.len())? != manifest.module_bytes {
        bail!("deployment module size does not match manifest");
    }
    let actual = format!("{:x}", Sha256::digest(&module));
    if actual != manifest.module_sha256 {
        bail!("deployment module integrity check failed");
    }
    if manifest.ores_adapter_verified != manifest.ores_adapter_sha256.is_some() {
        bail!("deployment manifest adapter evidence is inconsistent");
    }
    return Ok(manifest);
}

fn truncate(value: &str, max_chars: usize) -> String {
    return value.chars().take(max_chars).collect();
}

fn authorize(headers: &HeaderMap, state: &AppState) -> Result<(), (StatusCode, String)> {
    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if provided == Some(state.token.as_ref()) {
        return Ok(());
    }
    return Err((StatusCode::UNAUTHORIZED, "unauthorized".to_owned()));
}

fn validate_identifier(name: &str, value: &str) -> Result<(), (StatusCode, String)> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && value != "."
        && value != "..";
    if valid {
        return Ok(());
    }
    return Err((StatusCode::BAD_REQUEST, format!("invalid {name}")));
}

fn parse_loopback_addr(value: &str) -> Result<SocketAddr> {
    let addr: SocketAddr = value
        .parse()
        .context("LL_DESKTOP_ADDR is not a socket address")?;
    if !is_loopback(addr.ip()) {
        bail!("LL_DESKTOP_ADDR must bind to loopback");
    }
    return Ok(addr);
}

fn is_loopback(ip: IpAddr) -> bool {
    return ip.is_loopback();
}

fn resolve_config_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os("LL_DESKTOP_FLAGS_CONFIG") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        bail!("LL_DESKTOP_FLAGS_CONFIG is not a readable file");
    }
    let current = env::current_dir()?.join(".cli-flags.toml");
    if current.is_file() {
        return Ok(current);
    }
    let executable = env::current_exe()?;
    if let Some(parent) = executable.parent() {
        let adjacent = parent.join(".cli-flags.toml");
        if adjacent.is_file() {
            return Ok(adjacent);
        }
    }
    bail!("cannot locate .cli-flags.toml");
}

fn default_token_path() -> Result<PathBuf> {
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .ok_or_else(|| anyhow!("HOME or USERPROFILE is required"))?;
    return Ok(PathBuf::from(home).join(".lunatic-lorry/daemon/token"));
}

fn default_artifact_root() -> Result<PathBuf> {
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .ok_or_else(|| anyhow!("HOME or USERPROFILE is required"))?;
    return Ok(PathBuf::from(home).join(".lunatic-lorry/deployments"));
}

fn expand_home(path: &Path) -> Result<PathBuf> {
    let text = path.to_string_lossy();
    if text == "~" || text.starts_with("~/") {
        let home = env::var_os("HOME")
            .or_else(|| env::var_os("USERPROFILE"))
            .ok_or_else(|| anyhow!("HOME or USERPROFILE is required"))?;
        let suffix = text.trim_start_matches('~').trim_start_matches('/');
        return Ok(PathBuf::from(home).join(suffix));
    }
    return Ok(path.to_path_buf());
}

fn load_or_create_token(path: &Path) -> Result<String> {
    if let Ok(token) = std::fs::read_to_string(path) {
        let token = token.trim();
        if token.len() >= 32 && !token.chars().any(char::is_whitespace) {
            return Ok(token.to_owned());
        }
        bail!("desktop daemon token file is malformed");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("token path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    std::fs::write(path, format!("{token}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    return Ok(token);
}

fn internal_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_loopback_bind() {
        assert!(parse_loopback_addr("127.0.0.1:8763").is_ok());
        assert!(parse_loopback_addr("0.0.0.0:8763").is_err());
    }

    #[test]
    fn identifiers_reject_path_traversal() {
        assert!(validate_identifier("deployment_id", "deployment-1").is_ok());
        assert!(validate_identifier("deployment_id", "..").is_err());
        assert!(validate_identifier("deployment_id", "tenant/escape").is_err());
    }

    #[test]
    fn wasm_header_is_required() {
        assert!(validate_wasm_module(WASM_HEADER).is_ok());
        assert!(validate_wasm_module(b"not-wasm").is_err());
    }

    #[tokio::test]
    async fn bounded_reader_rejects_one_byte_over_limit() {
        let mut exact = std::io::Cursor::new(vec![1_u8; 8]);
        assert_eq!(
            read_bounded(&mut exact, 8, "test")
                .await
                .expect("exact limit")
                .len(),
            8
        );

        let mut oversized = std::io::Cursor::new(vec![1_u8; 9]);
        assert!(read_bounded(&mut oversized, 8, "test").await.is_err());
    }

    #[test]
    fn invocation_and_worker_output_limits_match_lambda_runtime() {
        assert_eq!(MAX_INVOCATION_BYTES, 10 * 1024 * 1024);
        assert_eq!(MAX_WORKER_STDOUT_BYTES, MAX_INVOCATION_BYTES);
        assert!(MAX_WORKER_STDERR_BYTES < MAX_WORKER_STDOUT_BYTES);
    }

    #[test]
    fn truncates_worker_errors() {
        let value = "x".repeat(1024);
        assert_eq!(truncate(&value, 512).len(), 512);
    }
}
