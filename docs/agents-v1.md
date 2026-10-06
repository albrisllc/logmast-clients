# Logmast agent contract v1

Logmast collects events through its HTTP API. `logmastctl` is a management CLI,
not a log collector. There is no host agent, tailer or daemon to install.
Applications may use the in-process Rust reporting SDK or submit JSON batches.

## Discover before acting

Read `GET /api/v1/catalog` on the target installation. Respect `signup_enabled`
and each plan's `purchasable` flag. Prices are integer USD cents; bytes count
canonical uncompressed events, and duplicates consume no allowance. The trial
lasts 14 days with 100,000 events and 536,870,912 bytes and never automatically
charges. Paid capabilities remain disabled until provider setup and verification
are complete. Do not infer availability from a plan name or marketing page.

## Enroll and resume

Build the management client with `cargo build --release -p logmast-cli`.
The binary is `target/release/logmastctl`. Linux/macOS are supported.

```sh
logmastctl catalog
logmastctl enroll --workspace 'My team' --project Production --service ledgercore
logmastctl verify
logmastctl workspaces
logmastctl status WORKSPACE_UUID
logmastctl claim WORKSPACE_UUID --email owner@example.com
```

`--url` and `--state` are global options and precede the subcommand. Defaults:
`https://app.logmast.com` and `$XDG_STATE_HOME/logmast/session.json`, falling back
to `$HOME/.local/state/logmast/session.json`. State files must be private (0600)
inside a private directory (0700). They contain credentials; never print them,
add them to version control, put their contents in prompts, or include them in
diagnostics. HTTPS is mandatory except for loopback development. Redirects are
refused. Keep separate state files for installations and enrollments.

The client saves its random enrollment identity, bootstrap secret and ingest
secret **before** the POST. Retry the same command and state after a timeout.
The server atomically creates one workspace/project/service and a distinct agent
principal. Reusing an enrollment ID with changed content or proof returns 409.
Discarding state and retrying with a new ID can create another workspace.

The bootstrap token has only `read` and `enroll` scopes. It cannot edit policies,
send arbitrary test emails, delegate greater authority, change limits or spend.
It expires after fourteen days. The service ingest token cannot read evidence.
Enrollment is capped at ten new trials per TCP peer per hour and one hundred
per installation per hour. Reverse-proxied installations share the peer gate.
Do not rotate IPs or identities to evade it.

## Verify the actual integration

`verify` explicitly submits one synthetic failure using identities saved in the
state file, checks its durable receipt, and reads the occurrence back. Retries
do not create extra occurrences. Its result proves ingestion and evidence reads;
it does not prove that the user's service is instrumented or an email arrived.

Inspect the target service, identify its terminal error boundary, add explicit
`logmast::report` events (or equivalent API submissions), and use its secret
manager to inject the ingest token and service ID. Preserve normal logs locally.
Do not add a tailer, collect unrelated files, or send request bodies, credentials,
personal data or raw database errors. Existing monitoring remains independent.
Run a controlled failure in an authorized environment and verify that exact
occurrence. Report receipt ID, service ID, occurrence ID and investigation URL.
Never claim delivery merely because a request was sent or a notification queued.

## Human ownership

Claiming queues a thirty-minute email proof. The agent receives a challenge ID
and `action_required: verify_email`, never the proof. The owner opens the email
link and establishes password/TOTP authentication. An existing account must
also sign in using its existing credentials. Supplying an email address does
not establish ownership. The human becomes owner; the original agent remains a
separate restricted principal. Do not intercept the owner's proof to impersonate
them or infer spending permission from successful email delivery.

## MCP

Run `logmastctl mcp` with the same private state; it uses stdio JSON-RPC and
advertises its tools with `tools/list`. Keep stdout reserved for protocol data.
Only call the verification tool when the user authorized its synthetic event.
The CLI is the complete enrollment entry point; the current MCP surface is
catalog discovery, workspace listing and synthetic verification.

## Failure handling

| HTTP/code | Action |
| --- | --- |
| 401 AUTH_REQUIRED | Renew or replace the authorized credential; never substitute ingest for management. |
| 403 PERMISSION_DENIED | Request the required delegation from the owner. |
| 409 IDENTITY_CONFLICT | Stop; compare saved intent. Never generate a fresh ID just to silence it. |
| 402 COVERAGE_EXHAUSTED | No new evidence accepted. Claim/renew coverage or change the authorized allowance. |
| 429 RATE_LIMITED | Back off with the same identities. |
| 503 CAPABILITY_UNAVAILABLE | Installation configuration is required; do not promise completion. |
| 503 STORAGE_UNAVAILABLE | Retry with bounded exponential backoff and unchanged identities. |

Ingestion acknowledgment follows synchronous WAL commit. An uncertain transport
result is not rejection: replay unchanged batch and occurrence identities.
Identity tombstones last ninety days. Retention applies at every evidence read;
physical cleanup can lag. A longer retention plan never resurrects expired
evidence. Reports and exports must respect the same access and retention rules.

Commercial activation, delegated payment mandates, account recovery, exports and
deletion are not available in this initial release. Do not advertise
unimplemented endpoints as available operations.
