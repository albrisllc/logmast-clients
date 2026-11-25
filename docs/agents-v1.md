# Logmast agent contract v1

Logmast collects events through its HTTP API. `logmastctl` is a management CLI,
not a log collector. There is no host agent, tailer or daemon to install.
Applications may use the in-process Rust reporting SDK or submit JSON batches.

## Discover before acting

Read `GET /api/v1/catalog` on the target installation. Respect `signup_enabled`
and `capabilities.human_checkout`. The `pricing` object publishes the bands, in
integer micro-USD per unit, so you can compute a cost before sending. Bytes count
canonical uncompressed events, and duplicates consume no allowance. The trial
lasts 14 days with 100,000 events and 536,870,912 bytes and never automatically
charges. Until its owner's email is verified, a new workspace accepts only the
catalog's `provisional` allowance (1,000 events and 16,777,216 bytes): enough to
verify collection. Past it, ingestion answers `402 VERIFICATION_REQUIRED` until the
claim completes, which unlocks the full trial. Paid capabilities remain disabled until provider setup and verification
are complete. Do not infer availability from a plan name or marketing page.
Use `logmastctl schema` or `GET /openapi.json` for request schemas, permission
requirements and retry semantics. The catalog's `capabilities` object explicitly
marks delegated identities, checkout and unfinished lifecycle operations.

## Enroll and resume

Build the management client with `cargo build --release -p logmast-cli`.
The binary is `target/release/logmastctl`. Linux/macOS are supported.

```sh
logmastctl catalog
logmastctl enroll --workspace 'My team' --project Production --service api
logmastctl verify
logmastctl workspaces
logmastctl status WORKSPACE_UUID
logmastctl claim WORKSPACE_UUID --email owner@example.com
```

`--url`, `--state`, `--credential` and `--format` are global options, before or after the subcommand. Defaults:
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
It expires after fourteen days and survives the claim so verification can finish; the
owner sees it in the agent list as "Enrollment agent (bootstrap)" and can revoke it there.
The service ingest token cannot read evidence.
Enrollment is capped at ten new trials per client address per hour and one
hundred per installation per hour. The client address is the TCP peer or, behind
a trusted reverse proxy, the address that proxy reports; IPv6 clients count by
their /64 prefix. Do not rotate IPs or identities to evade it. Replaying one
enrollment is not a new trial, but a client address that sends more than thirty
enrollment requests in quick succession is refused with `429 ATTEMPT_LIMIT`
before the request is examined; one further request is allowed every two minutes.

Verification emails are limited as well, because they go to an address nobody
has verified: three an hour and six a day per workspace, six a day per recipient
address across workspaces, ten a day across the workspaces one client address
enrolled, and sixty an hour per installation. Over any of these the claim
request answers `429 ATTEMPT_LIMIT`. Its `Retry-After` is a floor, not a promise:
several of these limits are daily. Each service is enrolled as its own
workspace, so an owner claiming more than six in a day, or one address
enrolling more than ten, must spread them over several days.

A new workspace starts unverified: 1,000 events and 8 MiB in total, enough to
instrument a service and prove delivery. The enrollment response reports this as
`allowance`, the catalog as `unverified_allowance`, and both state what a claim
unlocks: the full trial of 100,000 events and 512 MiB. Past the allowance,
ingestion returns `402 VERIFICATION_REQUIRED`. Hand the owner the claim; retrying
or enrolling another workspace does not help.

## Verify the actual integration

`verify` explicitly submits one synthetic failure using a run persisted before
submission, checks its durable receipt, and reads the occurrence back. An
incomplete run resumes unchanged; after completion the next invocation creates
a fresh run. `verify --run-id UUID` addresses one run, and a completed run returns
historical proof explicitly. `verify --service UUID` does the same for a service
whose credential this machine holds (created, rotated or enrolled here). Retries
do not create extra occurrences. Its result proves ingestion and evidence reads;
it does not prove that the user's service is instrumented or an email arrived.

Inspect the target service, identify its terminal error boundary, add explicit
`logmast::report` events (or equivalent API submissions), and use its secret
manager to inject the ingest token and service ID. Preserve normal logs locally.
Do not add a tailer, collect unrelated files, or send request bodies, credentials,
personal data or raw database errors. Existing monitoring remains independent.
If the service already uses a Sentry SDK (Python, Node, Go), replace its DSN
with the enrollment's `sentry_dsn` (`logmastctl sentry-dsn --output FILE` writes
it privately) instead of adding new reporting code. Inject it like any secret,
and set `trace_propagation_targets` to the service's own hosts so the SDK does
not send the key to third parties. See [Use your Sentry SDK](https://www.logmast.com/docs/sentry/).
Run a controlled failure in an authorized environment and verify that exact
occurrence. Report receipt ID, service ID, occurrence ID and investigation URL.
Never claim delivery merely because a request was sent or a notification queued.
Read retained receipt processing and notification stages at
`GET /api/v1/workspaces/{workspace}/receipts/{receipt}`. SMTP acceptance is not
inbox confirmation. Read the separate [collection playbook](https://www.logmast.com/docs/agents/v1/collection/)
for the complete bounded procedure.

## Expected signals and checks

Discover `capabilities.checks` before configuring heartbeats, job completion,
or named application verification. Management authority configures a
service/environment definition through the `check` control action. Ingest-only
authority posts an immutable run to `/api/v1/ingest/check-ins`. Checks use interval
plus grace and a separate included allowance. They do not execute tests or remote
probes. A late accepted signal may have `applied: false`; acceptance alone does
not prove current liveness. See the [checks playbook](https://www.logmast.com/docs/agents/v1/checks/).

## Human ownership

Claiming queues a thirty-minute email proof. The agent receives a challenge ID
and `action_required: verify_email`, never the proof. The owner opens the email
link and establishes password/TOTP authentication. An existing account must
also sign in using its existing credentials. Supplying an email address does
not establish ownership. The human becomes owner; the original agent remains a
separate restricted principal. Do not intercept the owner's proof to impersonate
them or infer spending permission from successful email delivery.

## Continue with delegated authority

### Ask for access with `logmastctl login`

The preferred way for an agent to get authority is to ask for it. In the
repository, run:

```sh
logmastctl login --workspace WORKSPACE_UUID --project PROJECT_UUID --permission manage --days 1 --scope .
```

It prints a link and an eight-letter code and exits (as JSON when captured).
Relay only the link and code to the person; never ask them for a token. They
sign in, type the code at `/device`, check the computer and directory the CLI
reported, and approve, with their authenticator code for management. Then run
`logmastctl login --wait`, which returns once they decide (codes expire after
ten minutes). The CLI generated the token itself and sent only its hash, so the
token never passes through the person, the conversation or any response; it is
kept in a private file (mode 0600) and never printed.

- Ask for the least you need: `--permission read` is the default, `--days`
  defaults to 30, and `--project` and `--scope DIR` narrow the grant to one
  project and one directory tree. The approver may narrow further, never widen.
- If the approval names a different workspace or project than you asked for,
  the CLI revokes it and fails with `LOGIN_MISMATCH`.
- `logmastctl whoami` shows which credential and binding a command here would
  use. `logmastctl logout` revokes the login at Logmast and removes it.
- Credentials resolve in this order: `LOGMAST_AGENT_TOKEN`; `--credential`;
  the login whose scope is nearest, for the workspace the command or the
  directory's binding names; the enrollment state.
- Commands that act on a workspace use the one they name, else the directory's
  binding (`logmastctl setup`), else the credential's own workspace. After one
  `logmastctl login`, `logmastctl projects` needs no ID; with logins for several
  workspaces on this machine, name the workspace or bind the directory.
- `--scope` decides which login a directory uses; it is not a security boundary.
  The boundaries are the operating-system user, the grant's permission and
  project, and its expiry.

### Grants an owner copies

For CI, or where nobody can approve a code, a human owner opens **Access → Agents** in the console, chooses
read-only or management access and an expiry of one to 360 days (180 by default),
then uses **Copy token**. **Download JSON** is also available. Each grant creates
a distinct agent principal. The owner can revoke
it immediately. Agents cannot become owners, mint management credentials, or
purchase coverage through these grants. A workspace keeps at most one hundred active grants; revoked and expired grants do not count.
A grant can be limited to one project: the agent then sees and changes only that project's
services, credentials, rules, checks and evidence, and every workspace-wide route refuses it.
Prefer a project-limited grant for an agent that works in one repository.

With agent access, prefer the service commands over raw control files: run
`logmastctl setup --project PROJECT_UUID` in the repository, then
`logmastctl services create --name NAME --env-file PATH` and
`logmastctl verify --service SERVICE_UUID`. The CLI keeps each service's ingest
credential privately on this machine and never prints it; captured output is JSON.

Store the copied token in a secret manager and inject it into the CLI
process as `LOGMAST_AGENT_TOKEN`. Set `LOGMAST_URL` or `--url` to the authorized
installation; the default is `https://app.logmast.com`. The token is exactly
64 lowercase hexadecimal characters. The API uses the same token in
`Authorization: Bearer <token>`. Keep it out of prompts, shell history and logs.
`LOGMAST_TOKEN` is reserved for application ingestion and does not authenticate
the management CLI.

```sh
# LOGMAST_AGENT_TOKEN is supplied by your secret manager.
logmastctl workspaces
logmastctl status WORKSPACE_UUID
logmastctl billing WORKSPACE_UUID
logmastctl control WORKSPACE_UUID \
  --command-file /private/logmast/create-service.json \
  --output /private/logmast/create-service-result.json
```

The console keeps the pending token in the current tab for refresh/retry recovery
until **I have saved it** is selected. Copying or downloading does not dismiss it.
After confirmation, the server cannot show it again. Previously issued grants
keep their original expiry.

Alternatively, store the downloaded JSON in a private directory, with directory
mode 0700 and file mode 0600. Its format is
`{"version":1,"origin":"https://app.logmast.com","token":"<secret>"}`.
The CLI refuses a different origin, a symlink or an accessible file. Unset
`LOGMAST_AGENT_TOKEN` when using this file; supplying both token and file
credentials is an error.

```sh
logmastctl --credential /private/logmast/agent.json workspaces
logmastctl --credential /private/logmast/agent.json status WORKSPACE_UUID
logmastctl --credential /private/logmast/agent.json billing WORKSPACE_UUID
logmastctl --credential /private/logmast/agent.json control WORKSPACE_UUID \
  --command-file /private/logmast/create-service.json \
  --output /private/logmast/create-service-result.json
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
Expiry must be in the future and at most 360 days away. Only a human owner
session can create a grant. An accepted `billing` scope does
not provide payment authority: purchases currently require a human owner.

## Billing handoff and reconciliation

Paid use is a prepaid balance that metered ingestion draws down. One unit is each
started 4 KiB of an event; bands restart each UTC calendar month. Retries and
duplicates are free. Read `/api/v1/workspaces/{workspace}/billing` for the balance
and recent top-ups, or `.../enrollment`, whose `next_action` is `claim` or
`top_up` when a human action would unblock collection.

Only an authenticated human owner can add credit: checkout takes a persisted UUID
and whole US dollars (10 to 5,000), and the same ID and intent return the same
operation. The owner completes payment at the returned Stripe URL. Do not infer
payment from the return URL: reconcile and inspect operation status.

When the balance runs out, ingestion still answers 200. `stored_events` in the
acknowledgment says how many new events kept their payload; the rest were counted
only and cannot be recovered by a later top-up. The first occurrence of a new
failure is stored, up to 100 a month. Report a shortfall in `stored_events` to the
owner; do not retry it. A successful enrollment never implies spending authority.

## Failure handling

| HTTP/code | Action |
| --- | --- |
| 401 AUTH_REQUIRED | Renew or replace the authorized credential; never substitute ingest for management. |
| 403 PERMISSION_DENIED | Request the required delegation from the owner. |
| 409 IDENTITY_CONFLICT | Stop; compare saved intent. Never generate a fresh ID just to silence it. |
| 402 VERIFICATION_REQUIRED | The unverified allowance is used. Run `claim` with the owner's email; the proof goes to their inbox, never through you. Acceptance resumes once they complete it. |
| 402 COVERAGE_EXHAUSTED | The trial has ended or is used up. Hand the owner `next_action: top_up`; acceptance resumes after they add credit. |
| 429 RATE_LIMITED | Back off with the same identities. |
| 429 ATTEMPT_LIMIT | A signup, verification-email or delegation limit. Wait at least `Retry-After`; some of these limits are hourly or daily. |
| 503 CAPABILITY_UNAVAILABLE | Installation configuration is required; do not promise completion. |
| 503 STORAGE_UNAVAILABLE | Retry with bounded exponential backoff and unchanged identities. |

Ingestion acknowledgment follows synchronous WAL commit. An uncertain transport
result is not rejection: replay unchanged batch and occurrence identities.
Identity tombstones last ninety days. Retention applies at every evidence read;
physical cleanup can lag. A longer retention plan never resurrects expired
evidence. Reports and exports must respect the same access and retention rules.

Commercial activation, delegated payment mandates, self-service password
recovery and exports are not available in this initial release. Do not advertise
unimplemented endpoints as available operations. Deleting a workspace, inviting
members and reading the audit log exist but need a person: deletion and
invitations refuse API tokens and agents.
