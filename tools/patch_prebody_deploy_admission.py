from pathlib import Path

cargo = Path("Cargo.toml")
cargo_text = cargo.read_text()
needle = 'tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }\n'
replacement = needle + 'tower = { version = "0.5", features = ["limit"] }\n'
if cargo_text.count(needle) != 1:
    raise SystemExit("expected one tracing-subscriber dependency anchor")
cargo.write_text(cargo_text.replace(needle, replacement, 1))

flags = Path(".cli-flags.toml")
flags_text = flags.read_text()
flag_anchor = '''[flags.max-parallel]\nenv = "LL_MAX_PARALLEL_INVOCATIONS"\naliases = ["max-parallel"]\ntype = "integer"\ndefault = 8\nhelp = "Maximum concurrent fresh Lunatic WASM actors inside the resident daemon runtime."\n'''
flag_insert = flag_anchor + '''\n[flags.max-parallel-deploys]\nenv = "LL_MAX_PARALLEL_DEPLOYS"\naliases = ["max-parallel-deploys"]\ntype = "integer"\ndefault = 2\nhelp = "Maximum concurrent deployment bodies admitted for validation, compilation, and immutable publication."\n'''
if flags_text.count(flag_anchor) != 1:
    raise SystemExit("expected one max-parallel flag anchor")
flags.write_text(flags_text.replace(flag_anchor, flag_insert, 1))

path = Path("src/main.rs")
text = path.read_text()

def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match, found {count}: {old[:120]!r}")
    text = text.replace(old, new, 1)

replace_once(
    'use tracing_subscriber::EnvFilter;\n',
    'use tower::limit::ConcurrencyLimitLayer;\nuse tracing_subscriber::EnvFilter;\n',
)
replace_once(
    'const MAX_BODY_BYTES: usize = MAX_MODULE_BYTES * 2;\nconst MAX_PARALLELISM: usize = 256;\n',
    'const MAX_BODY_BYTES: usize = MAX_MODULE_BYTES * 2;\nconst MAX_DEPLOY_BODY_BYTES: usize = 96 * 1024 * 1024;\nconst MAX_PARALLELISM: usize = 256;\nconst MAX_PARALLEL_DEPLOYS: usize = 16;\n',
)
replace_once(
    '''    LL_MAX_PARALLEL_INVOCATIONS: i64,\n    LL_DESKTOP_TOKEN_FILE: Option<String>,''',
    '''    LL_MAX_PARALLEL_INVOCATIONS: i64,\n    LL_MAX_PARALLEL_DEPLOYS: i64,\n    LL_DESKTOP_TOKEN_FILE: Option<String>,''',
)
replace_once(
    '''    parallelism: usize,\n    token_path: PathBuf,''',
    '''    parallelism: usize,\n    parallel_deploys: usize,\n    token_path: PathBuf,''',
)
replace_once(
    '''    let state = AppState {\n        token: Arc::from(token),''',
    '''    let deploy_admission = ConcurrencyLimitLayer::new(config.parallel_deploys);\n    let state = AppState {\n        token: Arc::from(token),''',
)
replace_once(
    '''        .route("/v1/doctor", get(status))\n        .route("/v1/deploy", post(deploy))\n        .route("/v1/invoke", post(invoke))''',
    '''        .route("/v1/doctor", get(status))\n        // Bound large deployment requests before Axum buffers their JSON body\n        // and hold the admission permit through validation, compilation, and\n        // immutable publication.\n        .route(\n            "/v1/deploy",\n            post(deploy)\n                .layer::<_, std::convert::Infallible>(deploy_admission)\n                .layer(DefaultBodyLimit::max(MAX_DEPLOY_BODY_BYTES)),\n        )\n        .route("/v1/invoke", post(invoke))''',
)
replace_once(
    '''    let token_path = match raw_config.LL_DESKTOP_TOKEN_FILE {''',
    '''    let parallel_deploys = usize::try_from(raw_config.LL_MAX_PARALLEL_DEPLOYS)\n        .ok()\n        .filter(|value| *value > 0 && *value <= MAX_PARALLEL_DEPLOYS)\n        .ok_or_else(|| {\n            anyhow!(\n                "LL_MAX_PARALLEL_DEPLOYS must be between 1 and {MAX_PARALLEL_DEPLOYS}"\n            )\n        })?;\n    let token_path = match raw_config.LL_DESKTOP_TOKEN_FILE {''',
)
replace_once(
    '''        addr,\n        parallelism,\n        token_path,''',
    '''        addr,\n        parallelism,\n        parallel_deploys,\n        token_path,''',
)
replace_once(
    '''    #[test]\n    fn truncates_worker_errors() {''',
    '''    #[test]\n    fn deploy_body_limit_bounds_pre_compile_retention() {\n        assert!(MAX_DEPLOY_BODY_BYTES > MAX_MODULE_BYTES);\n        assert!(MAX_DEPLOY_BODY_BYTES < MAX_BODY_BYTES);\n        assert!(MAX_PARALLEL_DEPLOYS < MAX_PARALLELISM);\n    }\n\n    #[test]\n    fn truncates_worker_errors() {''',
)
path.write_text(text)
