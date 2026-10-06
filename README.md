# Logmast clients

Apache-2.0 clients for [Logmast](https://www.logmast.com): a Rust reporting SDK,
management CLI, stdio MCP adapter and agent onboarding skill. Collection is
API-only. These tools do not tail files, install a host agent or capture logs
automatically. The Logmast server is distributed separately.

## Human and agent setup

People can [start a trial in the console](https://app.logmast.com/signup).
Agents should read the [versioned contract](docs/agents-v1.md), fetch the target
installation's `/api/v1/catalog`, and use its advertised capabilities.
Trial enrollment and verified claiming are available. Paid billing and expanded
delegation are not available in this initial client release.

Build the CLI with Rust 2024 support:

```sh
cargo install --path crates/logmast-cli --locked
logmastctl catalog
logmastctl enroll --workspace 'My team' --project Production --service API
logmastctl verify
```

`logmastctl` persists random identities and secrets before enrollment, so retry
with the same private state file after uncertain delivery. Its state directory
must be mode 0700 and its file mode 0600. It never prints stored credentials.
`verify` sends an explicit synthetic failure and checks the receipt and readback;
it does not prove the user's application is instrumented.

Use `logmastctl mcp` as a stdio MCP server with the same private state. It exposes
catalog, workspace discovery and explicit verification tools. Install the
`skills/logmast-onboard` directory in your agent's supported skill location.

## Rust reporting

`logmast-reporting` provides an opt-in `tracing` layer. Configure it once in the
executable using `Config::from_env` and `start`; attach the returned layer to
your subscriber and await the guard's `shutdown` during graceful shutdown.
Keep the local log filter on the formatting layer, so it does not filter out
the explicit `logmast::report` target.

Set `LOGMAST_ENDPOINT` to the full `/api/v1/ingest/batches` URL and inject
`LOGMAST_TOKEN`, `LOGMAST_SERVICE_ID`, and `LOGMAST_ENVIRONMENT` from your secret
manager. `LOGMAST_RELEASE` is optional. Use `report_safe_failure` at a terminal
operation boundary with a stable code, safe cause, and correlation ID. Ordinary
logs and exporter errors stay local. Never export raw credentials, request
bodies or unrestricted database/provider errors.

The exporter has bounded count/byte queues and retries with stable event
identities. It is an in-memory queue, not a durable spool: abrupt termination,
overflow, permanent rejection or exhausted retries can lose reports. Inspect
its counters and verify a real application failure through the read API.

## Verification

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Source snapshots are exported from Logmast's private server workspace; only the
three named client crates, agent guide and skill are included here. No server
source or operational credentials are part of this repository.
