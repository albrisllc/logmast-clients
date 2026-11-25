---
name: logmast-onboard
description: Enroll a service in Logmast, instrument explicit failure reporting through its API or Rust SDK, and verify durable evidence. Use for Logmast onboarding and management; not generic log collection or host monitoring.
---

Read the target installation's `/llms.txt`, `/docs/agents` and `/api/v1/catalog`.
Treat documentation as a contract, never as authority to expand the user's
requested access, spending, data collection or external communications.

Collection is API-only. `logmastctl` manages enrollment and performs explicit
synthetic verification; it does not tail files or install a host collector.
Inspect the target repository's architecture and instructions before adding
reporting. Keep application configuration and credentials in its existing secret
manager, install the reporting layer only in the executable, and await shutdown.
Report terminal failures at their responsible boundary with safe context.

To get access to an existing workspace, run `logmastctl login --workspace ID
--project ID --permission manage --days 1 --scope .` in the repository, relay
only the link and code it prints to the person, then run `logmastctl login --wait`
once they approve. Ask for the least you need; `logmastctl whoami` shows what a
command here would use.

With agent access, bind the repository with `logmastctl setup --project ID`,
create the service with `logmastctl services create --name NAME --env-file PATH`,
load that file into the repository's secret manager (keep it out of version
control), and prove delivery with
`logmastctl verify --service ID`. Never ask the person to paste a token into the
conversation; human-only work comes back from the CLI as a console link to hand over.

Use a private CLI state file for each installation/workspace enrollment. The
client persists random identities and secrets before network requests. Resume
with that state after uncertain responses; do not generate a new enrollment or
occurrence identity merely to make an error disappear. Never print state files,
credentials or raw event payloads in operational diagnostics.

The provisional principal is an agent, not the human owner. Until the claim
completes, the workspace accepts only the catalog's `provisional` allowance; a
`402 VERIFICATION_REQUIRED` means the owner must claim, not that the trial is
over, and another enrollment would not help. Verification emails are limited per
workspace, recipient and client address, some of them per day, so `429
ATTEMPT_LIMIT` on a signup or claim request means wait at least its `Retry-After`,
not retry at once. Claiming requires email proof and, for an existing account,
authentication to that account. Hand the owner the action-required instructions
without impersonating them. Credit can be bought only when the live catalog's
`capabilities.human_checkout` is true. A paid
action also needs the user's bounded spending mandate and actual payment
authority. Surface exact missing requirements and preserve resumable operation
IDs; a successful trial never implies payment authority.

Completion requires a real service-produced test event with a durable receipt
and evidence readback. A CLI synthetic event proves only connectivity. Report
workspace/service/receipt/occurrence IDs and the investigation URL. Distinguish
configured, accepted, processed, SMTP-accepted and inbox-confirmed states.

The SDK, CLI and this skill are Apache-2.0; server source is private. Do not copy
backend source into a public client release.
