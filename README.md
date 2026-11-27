<div align="center">

# Gatecrasher

### What if your users changed `plan=silver` to `plan=gold`?

**The AI red-team agent for Flagsmith.** Gatecrasher attacks your own Flagsmith setup the way an outsider would, maps every flag value a user can reach with Flagsmith's own evaluation engine, and — after a human approves — fixes each hole and attacks again to prove it is closed.

[![CI](https://github.com/yarrasatwik/gatecrasher/actions/workflows/ci.yml/badge.svg)](https://github.com/yarrasatwik/gatecrasher/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Go](https://img.shields.io/badge/Go-single%20binary-00ADD8?logo=go&logoColor=white)
![Flagsmith](https://img.shields.io/badge/Flagsmith-self--hosted%202.295.2-6633ff)
![Toggle Wars](https://img.shields.io/badge/Toggle%20Wars-Track%2002%20%C2%B7%20Track%2003-7c3aed)

**Toggle Wars — The Flagsmith Experimentation Hackathon (WeMakeDevs × Flagsmith)**
Track 02 · AI Agents and Feature Flags  ·  Track 03 · Build on Open Source Flagsmith

<!-- VIDEO_URL -->

*Your flags are a security boundary. Gatecrasher proves whether it holds.*

<img src="docs/screenshots/approval.png" alt="A Gatecrasher approval card: turn off client-set traits and hide sensitive data on Production, the eight findings it fixes, and the two lines of app code it will affect" width="860">

</div>

## The problem

Feature flags quietly became access control: paid plans, admin tools, betas, pricing experiments. Flagsmith's own documentation describes exactly where that boundary needs care:

| Flagsmith documents that… | …so an outsider can |
|---|---|
| Client SDKs can set user traits without credentials, and **"Allow client SDKs to set user traits" is on by default** ([Security](https://docs.flagsmith.com/system-administration/security), [Segments](https://docs.flagsmith.com/managing-segments)) — their example is changing `plan=silver` to `plan=gold` | unlock paid or admin features with one forged trait |
| Client-side environment keys are **public by design** ([Integration overview](https://docs.flagsmith.com/clients/overview)) | read the key from your JS bundle and call Flagsmith as your app |
| Flags reach the browser unless marked **Server-side only** ([Managing features](https://docs.flagsmith.com/basic-features/managing-features)) | read secrets, internal URLs and unreleased product names |
| Identity responses include traits unless **"Hide sensitive data"** is on ([Security](https://docs.flagsmith.com/system-administration/security)) | read another user's phone number or lifetime value |
| Rollouts and variants hash an identifier **the client chooses** | re-roll into a 10% early-access rollout or the cheaper arm of a pricing experiment — and bias the experiment |

Gatecrasher is the first tool that tests this from **your users' side**. Approval and policy tools in the Flagsmith ecosystem control *who may change a flag*; Gatecrasher checks whether *users can get around* the flags you already have.

## See it work

A real run against the self-hosted lab (full output in [`examples/acme-shop`](examples/acme-shop)):

```text
$ gatecrasher audit
recon     client key found at app.js:4; 11 flags visible
attack    testing 18 trait hypotheses and configured test identities
map       engine found 5 reachable flag states
verify    cross-checking every engine result against the live Flags API (transient identities)
parity    engine vs live parity over 1000 random identities

  16 ways in    3 critical · 5 high · 6 medium · 2 low
  engine vs live parity: 1000/1000 agree

   CRIT  Secret in a client-visible flag value: payment_config
   CRIT  Forging role=admin unlocks admin_panel (segment "admins")                    ✓ reproduced live
   CRIT  Forging email=a@acmeshop.dev unlocks staff_preview (segment "staff")         ✓ reproduced live
   HIGH  Users can pick their own group in experiment "Pricing page price test"       ✓ reproduced live
   HIGH  Traits of ce***@acmeshop.dev are readable by anyone with the public client key ✓ reproduced live
   HIGH  Forging plan=gold unlocks premium_export (segment "gold_plan")               ✓ reproduced live
   ...

$ gatecrasher fix-all        # a human types "Production" to approve each change
  14 findings  EXPLOITABLE → BLOCKED   ·   fixes live in 0.5–3.5 s  ·   storefront still works

$ gatecrasher audit
  2 ways in    (identifier re-rolls — Gatecrasher drafts the server-side change for you)
```

| Every finding, explained and reproducible | Proof after the fix |
|---|---|
| <img src="docs/screenshots/report.png" alt="Report page: severity groups, plain-English explanation, copyable curl reproduction" width="420"> | <img src="docs/screenshots/after.png" alt="Verified plan: before/after table where every finding moved from EXPLOITABLE to BLOCKED with the replayed request as proof" width="420"> |

## What it does

- **Recon like an outsider.** Fetches your site, follows its scripts, extracts the Flagsmith client key and API host, and lists every flag a visitor receives.
- **Attacks safely.** Forged traits (each confirmed twice, minimal trait sets only), identifier re-rolls, test-identity lookups, config leaks and experiment rigging — all with transient identities that Flagsmith never stores.
- **Maps from the inside with Flagsmith's own engine.** Loads the environment document into the official SDK's evaluation engine, solves every segment rule (REGEX, PERCENTAGE_SPLIT, nested ALL/ANY/NONE, semver, modulo…) for the smallest forged input, and replays each answer against the live API.
- **Fixes with a human in the loop.** Each plan shows what changes, why, and which lines of *your* code it will affect, with a PR draft. A person types the environment name to approve; Gatecrasher applies it, waits until the live API stops reproducing the hole, re-attacks, and can roll back at any time.
- **Watches continuously.** A signed Flagsmith webhook re-maps every flag or segment change and alerts within seconds.
- **Fits your workflow.** CLI, web UI, GitHub Action with code-scanning alerts, Slack alerts, and a read-only MCP server so Claude Code or Cursor can ask *"is my Flagsmith setup safe?"*

## Architecture

```mermaid
flowchart LR
  subgraph Outside["Outside view · public key only"]
    R[Recon<br/>key from JS bundle] --> C[Classify<br/>rules + Claude]
    C --> A[Attack<br/>transient probes]
  end
  subgraph Inside["Inside view · read-only admin key"]
    M[Settings + segments] --> E[Flagsmith engine<br/>over environment document]
    E --> X[Live replay<br/>+ parity]
  end
  A --> F[One finding per hole<br/>deterministic severity]
  X --> F
  F --> P[Fix plans<br/>+ impact on your code]
  P --> H{{Human approves<br/>types environment name}}
  H --> W[Apply via Admin API]
  W --> V[Re-attack<br/>EXPLOITABLE → BLOCKED]
  V --> L[(Hash-chained<br/>audit log)]
  WH[Signed Flagsmith<br/>webhook] --> M
```

| Stage | View | Writes to Flagsmith? |
|---|---|---|
| **Recon → Attack** | Outside, public key only | Never |
| **Map** (engine + live replay + parity) | Inside, read-only admin key | Never |
| **Fix → Re-attack → Rollback** | Inside | **Only after a human approves** |
| **Watch** | Inside, signed webhook | Only after a human approves |

## How Flagsmith is used

| Flagsmith capability | What Gatecrasher does with it |
|---|---|
| Client-side environment key | Extracts it from the JS bundle, exactly like an outsider ([`recon`](internal/recon)) |
| Flags API | Public inventory, leak detection, Server-side only verification ([`sdk.go`](internal/flagsmith/sdk.go)) |
| Identities API with **transient identities** | Every probe, live replay and parity check — nothing is stored ([`attacks`](internal/attacks)) |
| Traits + "Allow client SDKs to set user traits" | Forgery tests, settings audit, the primary fix ([`mapper`](internal/mapper), [`fixes`](internal/fixes)) |
| "Hide sensitive data" | Identity trait and override exposure, and its fix ([`identities.go`](internal/app/identities.go)) |
| Server-side only features | Finds sensitive values that reach browsers; marks them server-only ([`planner.go`](internal/fixes/planner.go)) |
| Segments, rules, overrides, priorities | Constraint solver for every operator ([`mapper`](internal/mapper)) |
| Identity overrides | Mapped from the environment document ([`identities.go`](internal/app/identities.go)) |
| Remote config values | Secret, internal URL, PII, pricing and roadmap classification ([`secrets`](internal/secrets), [`ai`](internal/ai)) |
| Environment document + **official SDK evaluation engine** | Offline evaluation with `flagsmith-go-client/v5` v5.7.0's engine; 1000/1000 parity with the live API ([`engine.go`](internal/flagsmith/engine.go), [`parity`](internal/parity)) |
| **Flagsmith Experimentation** | Detects running experiments, flags rigging, protects them during fixes ([`audit.go`](internal/app/audit.go)) |
| Organisation webhooks (HMAC-signed) | Watch mode, signature verified exactly as Flagsmith signs ([`watch`](internal/watch)) |
| v2 feature versioning | Versioned writes where an environment uses them ([`applier.go`](internal/fixes/applier.go)) |
| Admin API | Inside view, approved writes, rollback ([`admin.go`](internal/flagsmith/admin.go)) |
| Self-hosted official Docker images | One-command lab, also run end to end in CI ([`lab/compose.yaml`](lab/compose.yaml)) |

Every endpoint was verified against a running Flagsmith before code relied on it — see [`docs/api-verification.md`](docs/api-verification.md) and the 29 recorded responses in [`tests/fixtures`](tests/fixtures).

## Who decides what

| Action | Decided by |
|---|---|
| Extract the key, fetch flags, classify values | Agent, on its own (read-only, like any visitor) |
| Generate attack ideas | AI (Claude), on its own |
| Run probes | Agent, on its own — transient identities, scope-locked |
| Whether a finding is real | **Deterministic code** — only a live probe or the engine can confirm it |
| Severity | Deterministic rules; the AI only explains in plain English |
| Any change to Flagsmith | **A human**, typing the environment name for Production |
| Changing a flag under a running experiment | **A human**, typing `contaminate-experiment` |
| Moving `setTrait` calls or secrets to your server | **A human** reviews the PR draft Gatecrasher writes |

## Built to be trusted

| Guarantee | How |
|---|---|
| Scope lock | Every request and redirect is checked against your allow-list; there is no override ([`scope`](internal/scope)) |
| No stored probe data | Transient identities only, prefixed `gc-probe-`; identity lookups only for configured test identities |
| The AI never acts | No tools, no credentials, redacted input, schema-checked output; a guard blocks any prompt containing key material ([`ai`](internal/ai)) |
| Approvals bound to state | Plan hash + live snapshot; stale plans are refused; approvals expire after 30 minutes ([`approvals.go`](internal/fixes/approvals.go)) |
| Keys never leave | Central redaction on every output — terminal, reports, AI prompts, MCP, audit log ([`redact`](internal/redact)) |
| Tamper-evident history | Hash-chained audit log, verified in the CLI and web UI ([`audit`](internal/audit)) |
| One-click undo | Rollback restores the exact before-state and is safe to repeat ([`rollback.go`](internal/fixes/rollback.go)) |
| Clean commits | Pre-commit hook blocks `.env*`, state files and key patterns ([`.githooks/pre-commit`](.githooks/pre-commit)) |

## Quick start

Needs Docker and Go 1.25+.

```bash
git clone https://github.com/yarrasatwik/gatecrasher && cd gatecrasher
make install      # builds bin/gatecrasher and enables the secret-blocking hook
make lab-up       # official self-hosted Flagsmith (Postgres, API, task processor)
make lab-seed     # the Acme Shop project with 12 planted misconfigurations; writes .env
make shop &       # the Acme Shop storefront on http://localhost:3030
make audit        # → reports/latest.{html,md,json,sarif}
```

Then fix and prove it:

```bash
bin/gatecrasher fix-all          # review each plan, type "Production" to approve
bin/gatecrasher serve --watch    # web UI on http://127.0.0.1:8787 + live alerts
make lab-reset                   # restore the lab
```

### For judges in 60 seconds

```bash
make verify                 # no Docker, no keys: vet + 400+ test cases + build
make lab-up lab-seed        # then, the full run (~3 minutes):
make shop &
make audit
```

Or open the recorded run: [`examples/acme-shop`](examples/acme-shop) — the HTML report, SARIF, the approval session and the before/after proof.

## Use it on your own Flagsmith

Works with Flagsmith Cloud and self-hosted.

1. Copy [`gatecrasher.example.yaml`](gatecrasher.example.yaml) to `gatecrasher.yaml`: your site, its hosts, your Flagsmith API host, project and environments.
2. Add keys to `.env` ([`.env.example`](.env.example)):
   - **Outside view:** none — Gatecrasher finds your public client key itself.
   - **Inside view:** `GATECRASHER_ORG_API_KEY` — a dedicated organisation key; read-only is enough for audits and CI.
   - **AI:** `ANTHROPIC_API_KEY` adds Claude for classification, attack ideas, explanations and PR drafts.
3. `gatecrasher audit` → `plan` → `approve --confirm <env>` → `apply` → `verify`.

### GitHub Action

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  flagsmith-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: yarrasatwik/gatecrasher@main
        with:
          api-url: https://edge.api.flagsmith.com/api/v1/
          org-api-key: ${{ secrets.FLAGSMITH_ORG_API_KEY }}
          project: My Project
          environment: Production
          fail-on: high
```

Findings appear in the repository's **Security → Code scanning** tab, with a job summary and a configurable failure threshold.

### MCP server for coding agents

```bash
claude mcp add gatecrasher -- gatecrasher mcp -config /path/to/gatecrasher.yaml
```

Tools: `gatecrasher_audit`, `gatecrasher_findings`, `gatecrasher_explain` — all read-only. Changes always go through the approval flow.

## Measured results

From real runs against self-hosted Flagsmith 2.295.2 — on Windows 11 with Docker Desktop and on GitHub's Ubuntu runners, where CI repeats every number on each pull request.

| Measure | Result |
|---|---|
| Planted misconfigurations found | **12 / 12**, zero false positives on control flags |
| Engine vs live API parity | **1000 / 1000** identities agree |
| Full audit (outside + inside) | **~10 s** · with 300-identity parity 13–25 s |
| Time for an approved fix to take effect on the live API | **0.5 – 3.5 s** |
| Ways in after approved fixes | **16 → 2** (the remaining two are code changes Gatecrasher drafts) |
| Watch alert after a dashboard change | **2.9 – 3.7 s** |
| Environment document freshness on self-hosted | median **0.08 s** after a write |
| Integration suite | 5 end-to-end scenarios against real Flagsmith on every PR |

## Tech stack

Go (single static binary) · official Flagsmith Go SDK evaluation engine · Flagsmith Admin, Flags and Identities APIs · Flagsmith Experimentation · Anthropic Claude (optional) · `net/http` + `html/template` + HTMX web UI · SARIF 2.1.0 · Model Context Protocol · Docker Compose with official Flagsmith images · GitHub Actions.

## Repository map

```
cmd/gatecrasher/     CLI: lab, audit, plan, approve, apply, verify, rollback, fix-all, serve, watch, ci, mcp
internal/app/        orchestrator: one finding per hole, live replay, fix loop, watch
internal/attacks/    outside probes (transient identities)
internal/mapper/     settings audit, rule solver, engine reachability
internal/flagsmith/  SDK API, Admin API, environment document, evaluation engine
internal/fixes/      plans, approvals, apply, rollback, impact analysis
internal/report/     HTML, Markdown, JSON, SARIF
internal/server/     web UI      internal/watch/  signed webhooks      internal/mcp/  MCP server
lab/                 self-hosted Flagsmith, Acme Shop seed and storefront
tests/integration/   end-to-end suite against real Flagsmith
examples/acme-shop/  a recorded run: reports, approval session, before/after
```

## Team

Built by [**yarrasatwik**](https://github.com/yarrasatwik) for Toggle Wars, 26–29 November 2026.

## License

[MIT](LICENSE)
