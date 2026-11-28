# Recorded run: Acme Shop

A complete Gatecrasher session against the Acme Shop lab on self-hosted Flagsmith 2.295.2, captured unedited. Claude was on (through Claude Code), approvals were entered in the web UI with the environment name and the plan-hash suffix (typed by browser automation for this recording, so every step can be reproduced), and every change went through the official Flagsmith CLI.

| File | What it shows |
|---|---|
| [`audit.txt`](audit.txt) | The first audit: **8 ways in · 17 findings**, grouped by root cause, every exploit reproduced live, engine vs live parity 1000/1000, 1,421 requests (estimate printed first) |
| [`report.html`](report.html) | The self-contained HTML report after the fixes were verified (download and open in a browser) |
| [`report.md`](report.md) · [`report.json`](report.json) · [`report.sarif`](report.sarif) | The same report as Markdown, canonical JSON and SARIF for GitHub code scanning: 17 findings, 14 BLOCKED, 3 open |
| [`plans.txt`](plans.txt) | The fix plans: four Flagsmith changes, approved and verified, and three code changes left as guidance, each with a PR draft whose diff applies to the shop's `app.js` and `main.go` |
| [`audit-after-fixes.txt`](audit-after-fixes.txt) | The re-audit: **3 ways in · 3 findings**. Each is a browser choosing its own identifier, including the `internal_tools` rule that survives turning off client traits |

The hash-chained audit log for this run verified with 28 entries (plan, approve, apply, verify). It is not included here because it records the operator's local account name.

Keys and secrets never appear: the client key is shown as `<CLIENT_KEY>` and the payment secret as `[SECRET len=42 prefix=acme…]`.

Reproduce it: `make lab-up lab-seed`, `make shop &`, `bin/gatecrasher audit`, then approve the plans in `bin/gatecrasher serve` and run `bin/gatecrasher audit` again.
