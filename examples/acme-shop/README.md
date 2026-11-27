# Recorded run: Acme Shop

A complete Gatecrasher session against the Acme Shop lab on self-hosted Flagsmith 2.295.2, captured unedited.

| File | What it shows |
|---|---|
| [`audit.txt`](audit.txt) | The first audit: 16 ways in, every exploit reproduced live, engine vs live parity 1000/1000 |
| [`report.html`](report.html) | The self-contained HTML report (download and open in a browser) |
| [`report.md`](report.md) · [`report.json`](report.json) · [`report.sarif`](report.sarif) | The same report as Markdown, canonical JSON and SARIF for GitHub code scanning |
| [`plan.txt`](plan.txt) | The fix plans, including what each change would break in the storefront's code |
| [`fix-all.txt`](fix-all.txt) | The approval session: a human typed `Production` for each change; every finding re-checked EXPLOITABLE → BLOCKED |
| [`audit-after-fixes.txt`](audit-after-fixes.txt) | The re-audit: 16 → 2 ways in |
| [`audit-log.txt`](audit-log.txt) | The hash-chained audit log, verified |

Keys and secrets never appear: the client key is shown as `<CLIENT_KEY>` and the payment secret as `[SECRET len=42 prefix=acme…]`.

Reproduce it: `make lab-up lab-seed`, `make shop &`, then `bash scripts/demo.sh`.
