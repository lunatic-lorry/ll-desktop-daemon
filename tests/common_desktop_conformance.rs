use ores_common_desktop_conformance::assert_router_only_activation;
use ores_common_desktop_router::{
    MiddlewareSpec, RouteDestination, RouterGeneration, RouterRoute, RouterState,
};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

const DIGEST_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DIGEST_B: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

fn generation(number: u64, revision: &str) -> RouterGeneration {
    return RouterGeneration {
        generation: number,
        route_catalog_sha256: DIGEST_A.to_string(),
        middleware_graph_sha256: DIGEST_B.to_string(),
        middleware: vec![MiddlewareSpec {
            middleware_id: "request-policy".to_string(),
            revision: revision.to_string(),
            digest: DIGEST_A.to_string(),
            order: 10,
        }],
        routes: vec![RouterRoute {
            route_id: "invoke".to_string(),
            host: "local.test".to_string(),
            path_prefix: "/invoke".to_string(),
            methods: BTreeSet::from(["POST".to_string()]),
            destination: RouteDestination::WorkerPool {
                pool_id: "isolated-workers".to_string(),
            },
            middleware_chain: vec!["request-policy".to_string()],
        }],
    };
}

#[test]
fn middleware_swap_does_not_touch_worker_processes() {
    let worker_changes = AtomicU64::new(0);
    let mut router = RouterState::default();
    assert!(router.activate(generation(1, "policy-a")).is_ok());

    let result = assert_router_only_activation(&mut router, generation(2, "policy-b"), || {
        return worker_changes.load(Ordering::SeqCst);
    });

    assert!(result.is_ok());
    assert_eq!(worker_changes.load(Ordering::SeqCst), 0);
}
