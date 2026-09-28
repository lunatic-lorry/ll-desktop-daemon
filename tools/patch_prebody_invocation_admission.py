from pathlib import Path

cargo = Path("Cargo.toml")
cargo_text = cargo.read_text()
needle = 'tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }\n'
replacement = needle + 'tower = { version = "0.5", features = ["limit"] }\n'
if cargo_text.count(needle) != 1:
    raise SystemExit("expected one tracing-subscriber dependency anchor")
cargo.write_text(cargo_text.replace(needle, replacement, 1))

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
    'const MAX_INVOCATION_BYTES: usize = 10 * 1024 * 1024;\n',
    'const MAX_INVOCATION_BYTES: usize = 10 * 1024 * 1024;\nconst MAX_INVOCATION_BODY_BYTES: usize = 16 * 1024 * 1024;\n',
)
replace_once(
    '''    let state = AppState {\n        token: Arc::from(token),''',
    '''    let invoke_admission = ConcurrencyLimitLayer::new(config.parallelism);\n    let state = AppState {\n        token: Arc::from(token),''',
)
replace_once(
    '''        .route("/v1/deploy", post(deploy))\n        .route("/v1/invoke", post(invoke))\n        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))''',
    '''        .route("/v1/deploy", post(deploy))\n        // Admission wraps the invoke route before Axum's Json extractor buffers\n        // and deserializes the request body. The handler semaphore remains a\n        // second actor-execution guard; this outer limit bounds pre-execution\n        // request retention as well.\n        .route(\n            "/v1/invoke",\n            post(invoke)\n                .layer(invoke_admission)\n                .layer(DefaultBodyLimit::max(MAX_INVOCATION_BODY_BYTES)),\n        )\n        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))''',
)
replace_once(
    '''    #[test]\n    fn truncate_is_bounded() {''',
    '''    #[test]\n    fn invocation_body_limit_bounds_pre_actor_retention() {\n        assert!(MAX_INVOCATION_BODY_BYTES > MAX_INVOCATION_BYTES);\n        assert!(MAX_INVOCATION_BODY_BYTES < MAX_BODY_BYTES);\n        assert!(MAX_INVOCATION_BODY_BYTES <= MAX_INVOCATION_BYTES * 2);\n    }\n\n    #[test]\n    fn truncate_is_bounded() {''',
)
path.write_text(text)
