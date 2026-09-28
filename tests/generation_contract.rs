use serde_json::Value;
use std::collections::BTreeSet;

#[test]
fn generation_contract_matches_runtime_invariants() -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string("ores-generation-contract.json")?;
    let document: Value = serde_json::from_str(&raw)?;

    assert_eq!(
        document.get("schema").and_then(Value::as_str),
        Some("ores.desktop-generation-consumer/v1")
    );

    let expected_lifecycle = [
        "prepare",
        "validate",
        "compile_build_generation",
        "stage",
        "health_check",
        "atomic_activate",
        "bounded_drain",
        "commit",
    ];
    let lifecycle = document
        .get("lifecycle")
        .and_then(Value::as_array)
        .ok_or("lifecycle must be an array")?;
    assert_eq!(lifecycle.len(), expected_lifecycle.len());
    for (actual, expected) in lifecycle.iter().zip(expected_lifecycle) {
        assert_eq!(actual.as_str(), Some(expected));
    }

    let revision = document
        .pointer("/authority/revision")
        .and_then(Value::as_str)
        .ok_or("authority.revision must be a string")?;
    assert_eq!(revision.len(), 40);
    assert!(
        revision
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    );

    assert_eq!(
        document
            .pointer("/rollback/required_before_commit")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        document
            .pointer("/rollback/retain_previous_generation")
            .and_then(Value::as_bool),
        Some(true)
    );

    assert_eq!(
        document
            .pointer("/request_semantics/new_requests")
            .and_then(Value::as_str),
        Some("active_generation")
    );
    assert_eq!(
        document
            .pointer("/request_semantics/existing_requests")
            .and_then(Value::as_str),
        Some("pinned_generation")
    );
    assert_eq!(
        document
            .pointer("/request_semantics/generation_identity_required")
            .and_then(Value::as_bool),
        Some(true)
    );

    assert_eq!(
        document
            .pointer("/routing/edge_proxy_route_authority")
            .and_then(Value::as_bool),
        Some(false)
    );
    let stable_edges = document
        .pointer("/routing/stable_edges")
        .and_then(Value::as_array)
        .ok_or("routing.stable_edges must be an array")?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    for required in ["nginx", "haproxy", "caddy"] {
        assert!(stable_edges.contains(required));
    }

    assert_eq!(
        document
            .pointer("/middleware/beam_code_reload_requires_drain_or_otp_proof")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        document
            .pointer("/verification/shared_conformance_required")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        document
            .pointer("/verification/product_e2e_required")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        document
            .pointer("/verification/promotion_state")
            .and_then(Value::as_str),
        Some("candidate")
    );

    return Ok(());
}
