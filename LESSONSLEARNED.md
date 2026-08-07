# LESSONSLEARNED.md

Tracked durable lessons for `nordility`.
Unlike `CHATHISTORY.md`, this file should keep only reusable lessons that should change how future sessions work in this repo.

## How To Use

- Read this file after `AGENTS.md` and before `CHATHISTORY.md` when resuming work.
- Add lessons that generalize beyond a single session.
- Keep entries concise and action-oriented.
- Do not use this file for transient status updates or full session logs.

## Lessons

- Document the repository around its real execution, curation, or integration flow instead of only the top-level folder list.
- Keep local-only, private, reference-only, or generated boundaries explicit so published or runtime behavior is not confused with offline material or non-committable inputs.
- Re-run repo-appropriate validation after changing generated artifacts, diagrams, workflows, or other CI-facing files so formatting and compatibility issues are caught before push.
- Treat `wg show interfaces` as discovery, not authority: derive a config-owned allowlist and explicitly reject provider-daemon interfaces before reading or mutating peer endpoints or fwmarks. Report policy routing restored only after both the interface mark and an exactly parsed priority/full-mark/main-table rule succeed.
- Before adding a global fwmark rule, inventory every WireGuard interface for mark collisions, tag the rule with a project-owned routing protocol, and roll back only that exact owned rule if verification or all authorized mutations fail.
- Never pass provider tokens through public CLI `argv` or the environment. For a pinned terminal flow, use a non-dumpable PTY helper that matches the exact prompt, proves echo is disabled before reading private stdin, wipes the token, suppresses output, and has no positional fallback.
- A loopback listener is not an authorization boundary for a privileged mutation API. Use a permissioned Unix socket for the trusted proxy and enforce browser Origin/Host/content-type checks.
- Root systemd services must execute a fixed root-owned staged runtime, not files in a user-writable Git checkout.
- A staged root service must not enable an optional sibling-repo feature unless that dependency is staged and secured too; default installed Nord services to a separately authenticated client instead of auto-pass login.
