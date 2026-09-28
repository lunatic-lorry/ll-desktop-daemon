from pathlib import Path

path = Path("src/main.rs")
text = path.read_text()
old = '''    #[test]\n    fn invocation_body_limit_bounds_pre_actor_retention() {\n        assert!(MAX_INVOCATION_BODY_BYTES > MAX_INVOCATION_BYTES);\n        assert!(MAX_INVOCATION_BODY_BYTES < MAX_BODY_BYTES);\n        assert!(MAX_INVOCATION_BODY_BYTES <= MAX_INVOCATION_BYTES * 2);\n    }\n'''
new = '''    #[test]\n    fn invocation_body_limit_bounds_pre_actor_retention() {\n        let body_limit = std::hint::black_box(MAX_INVOCATION_BODY_BYTES);\n        let invocation_limit = std::hint::black_box(MAX_INVOCATION_BYTES);\n        let global_limit = std::hint::black_box(MAX_BODY_BYTES);\n        assert!(body_limit > invocation_limit);\n        assert!(body_limit < global_limit);\n        assert!(body_limit <= invocation_limit * 2);\n    }\n'''
if text.count(old) != 1:
    raise SystemExit(f"expected one invocation limit test, found {text.count(old)}")
path.write_text(text.replace(old, new, 1))
