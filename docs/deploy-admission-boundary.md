# Deployment admission boundary

`ll-desktop-daemon` admits large deployment requests separately from actor invocation traffic.

The `/v1/deploy` route is guarded before Axum buffers and deserializes the JSON request body. The default deploy admission limit is 2 concurrent requests and is configurable with `LL_MAX_PARALLEL_DEPLOYS` / `--max-parallel-deploys`, with a hard maximum of 16.

The route has a 96 MiB HTTP body ceiling. This accommodates the base64-expanded form of the maximum 64 MiB WebAssembly module plus the deployment envelope while remaining below the daemon-wide 128 MiB fallback body limit.

A deploy admission permit is held through adapter/receipt validation, embedded Lunatic/Wasmtime compilation, and immutable artifact publication. Invocation admission and actor execution remain independently bounded so deployment pressure cannot redefine fresh-actor isolation semantics.
