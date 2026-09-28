# Invocation admission boundary

`ll-desktop-daemon` uses two distinct concurrency guards for local Lunatic Lambda invocation.

1. A route-local Tower concurrency limit admits requests before Axum buffers and deserializes the invocation JSON body. This bounds the number of large request bodies retained while waiting for runtime capacity.
2. The existing handler semaphore remains the actor-execution guard. An admitted invocation still acquires this permit before launching a fresh embedded Lunatic/Wasmtime actor.

The `/v1/invoke` route also has a dedicated 16 MiB HTTP body ceiling. The logical invocation payload remains bounded separately at 10 MiB. These are intentionally different limits because the JSON request includes envelope fields and JSON/base64/string encoding overhead beyond the logical payload.

This admission layer does not change actor reuse or isolation semantics: each invocation still launches a fresh actor, and compiled-module caching does not imply process/instance reuse.
