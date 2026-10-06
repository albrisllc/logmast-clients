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
Use `logmastctl schema` or `GET /openapi.json` for request schemas, permission
requirements and retry semantics. The catalog's `capabilities` object explicitly
marks delegated identities, checkout and unfinished lifecycle operations.

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
The CLI is the complete enrollment entry point. MCP also provides workspace
status and billing status reads. These reads never authorize or make a purchase.
With a delegated credential, verification still requires the original enrollment
state and its separately scoped ingest credential.

## Continue with delegated authority

After claiming, a human owner opens **Agents** in the console, chooses read-only
or management access and an expiry of one to ninety days, and downloads a
credential. Each grant creates a distinct agent principal. The owner can revoke
it immediately. Agents cannot become owners, mint management credentials, or
purchase coverage through these grants. An installation keeps at most one
hundred grants per workspace, including revoked grants.

Store the downloaded credential in a private directory, with directory mode
0700 and file mode 0600. Its format is
`{"version":1,"origin":"https://app.logmast.com","token":"<secret>"}`.
The CLI refuses a different origin, a symlink or an accessible file. Do not
paste the credential into a prompt or shell command.

```sh
logmastctl --credential /private/logmast/agent.json workspaces
logmastctl --credential /private/logmast/agent.json status WORKSPACE_UUID
logmastctl --credential /private/logmast/agent.json billing WORKSPACE_UUID
logmastctl --credential /private/logmast/agent.json control WORKSPACE_UUID \
  --command-file /private/logmast/create-service.json \
  --output /private/logmast/create-service-result.json
logmastctl --credential /private/logmast/agent.json mcp
```

For example, the command file can contain
`{"action":"create_service","project_id":"PROJECT_UUID","name":"API"}`.
The output can contain a service ingest credential and is therefore written to
a new private file; stdout prints only its location. Inject that ingest secret
into the application's secret manager. Never give the application management
authority. `--credential` also accepts `LOGMAST_CREDENTIAL`.

Control commands are **not generally idempotent**. The CLI makes one request.
After an uncertain result, inspect workspace policies and service inventory
before retrying creation or rotation. An empty output file means the result was
not saved, not that the server rejected the operation. Choose a new output path
only after reconciling that result. Enrollment and agent-grant creation have
their own persisted operation identities and are safe to replay unchanged.

For direct grant creation, generate and persist a random UUID and 32-byte
lowercase hexadecimal secret before POSTing `/api/v1/workspaces/{workspace}/agents`.
Keep the entire request, including expiry and ordered scopes, identical on retry.
`read` is required; `manage` permits administration within the member role.
Expiry must be in the future and at most ninety days away. Only a human owner
session can create a grant. An accepted `billing` scope does
not provide payment authority: purchases currently require a human owner.

## Billing handoff and reconciliation

Read `/api/v1/workspaces/{workspace}/billing` to inspect paid periods and recent
purchase operations. When purchasable, an authenticated human owner can request
checkout with a persisted UUID, plan/revision, `subscription` or `prepaid`, and
one to twelve months (subscriptions require one). The same ID and intent return
the same operation. The owner completes payment at the returned Stripe URL.
Do not infer payment from the return URL: reconcile and inspect operation status.

Provider-confirmed payment grants separate calendar-month allowances. Replayed
callbacks do not reset usage. Cancellation stops subscription renewal and keeps
already-paid coverage. A `review` state requires reconciliation or operator
review; never create a replacement charge to bypass an uncertain purchase.
Automated purchases using bounded mandates are not yet available.

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
