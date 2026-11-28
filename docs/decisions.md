# Decisions

Choices made while hardening Gatecrasher, and what the real Flagsmith API taught us. Each entry says what we
decided and why.

## Counting and status

- **"N ways in · M findings".** N counts exploitable root causes, M counts confirmed findings. One fixable
  thing (for example "Production lets clients set traits") is one way in, however many findings it causes.
- **Settings are causes, not extra ways in.** "Allow client SDKs to set user traits" and "Hide sensitive data"
  join the root cause of the exploit they enable. With no live exploit they are listed as hardening.
- **HIDDEN is open.** Server-side only stops client SDKs from receiving a flag. It does not stop re-rolling an
  identifier or forging a trait on a server path, so those findings verify as HIDDEN and stay open in every
  count. Re-roll findings get their own plan: assign identifiers on the server.
- **UNKNOWN is never safe.** A finding whose re-check could not run keeps its root cause open.
- **`client_sets_identifier: false` closes re-rolling.** If your server assigns identifiers, the config says so
  and re-roll findings are blocked.
- **found − blocked = remaining** is checked by `report.CheckTally` on every report, including the recorded one.

## The AI

- **Claude never decides what is real.** A classification that only the AI makes is listed under "Claude
  suggests reviewing", is not counted and gets no fix plan. It becomes a finding only when a deterministic rule
  agrees or a person confirms it in the web UI; the confirmation is written to the audit log and later audits
  read it back. Confirmations are keyed by finding ID, so they apply per environment.
- **Unreleased-product names** are decided by rules: a future date in the name, codename patterns
  (`project_*`, `*_launch_*`, `*_codename_*`), or words like `unreleased` and `stealth`. A flag that is on by
  default or behind a live rollout is already released. `secret` inside credential-style keys such as
  `api_secret` is not a roadmap signal.

## Secrets

- **Entropy alone is LOW "needs review"** (`POSSIBLE_SECRET`). CRITICAL needs a known secret format, a
  secret-named key, or a password inside a URL (any scheme). A private host in that URL also raises
  `INTERNAL_URL`.
- **Public-by-design keys are not secrets:** Stripe publishable keys, Firebase web API keys (restrict them by
  HTTP referrer), Mapbox public tokens, reCAPTCHA/hCaptcha site keys, Sentry DSNs, Algolia search-only keys,
  commit hashes and checksums, UUIDs, data URIs and image URLs. Output still redacts `pk_live_`/`pk_test_`.
- `POSSIBLE_SECRET` counts as a LOW finding but is never a way in on its own.

## Approval

- **Protected environments** come from `protected_environments` (the older `flagsmith.production_environments`
  still works). An environment named `Production` is always protected.
- **A person, not an agent, approves them.** The CLI refuses unless stdin and stdout are terminals, and refuses
  inside agent and CI sessions (`CI`, `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CURSOR_TRACE_ID`,
  `GITHUB_ACTIONS`, `GATECRASHER_AGENT`). The person types the environment name and the last 4 characters of
  the plan hash. `--confirm` works only for unprotected environments.
- **Web approval** keeps the typed environment name and adds a 3-second review delay, enforced on the server
  with a signed render time bound to the plan.
- **Audit log** records the channel (`tty`, `web`, or `cli` for unprotected environments), the OS user, and the
  claimed name when it differs.
- The integration suite approves in-process below the CLI gate, so CI exercises apply and rollback on
  Production without any bypass flag.

## Flagsmith behaviour we found

- **v2 feature versioning refuses `create-segment-override`.** New overrides go through
  `environments/<environment id>/features/<feature id>/versions/` with `publish_immediately`; the same path
  with the environment key returns 405.
- **After client traits are off, the live API ignores client-sent traits**, and Server-side only flags are never
  returned to client keys. Engine-vs-live parity models both, otherwise a locked-down environment reports 0/200.
- **Each Flagsmith API worker caches project segments for 5 minutes.** The cache is per process and cannot
  be configured, so after a segment is created or replaced, some workers still evaluate with the old segments.
  The lab runs one API worker (`GUNICORN_WORKERS: "1"`, 4 threads) so every answer matches the environment
  document it just wrote. On a multi-worker Flagsmith, parity can show mismatches for up to 5 minutes after a
  segment change; that is a real, temporary difference, and Gatecrasher reports it rather than hiding it.
  Applied fixes and lab resets also wait for several consecutive fresh answers before they count as live.
- **Identifier rules survive the client-traits fix.** A segment on `$.identity.identifier` stays forgeable while
  the browser chooses its own identifier; Gatecrasher reports it with a guidance plan.
- **Webhooks are retried by Flagsmith.** Deliveries are de-duplicated by body and event time for 10 minutes;
  events more than 10 minutes old are refused, and up to 1 minute of clock skew into the future is accepted
  because Docker and VM clocks drift.
- **`serve --watch` listens on `watch.listen`**, because that is where `watch.public_url` sends Flagsmith.

## Network

- **Key headers never follow redirects.** A request carrying `X-Environment-Key` or `Authorization` stops at a
  redirect with an error; any redirect that changes host or port also strips both headers.
- **Scope entries pin ports.** The lab allows `localhost:3030` and `localhost:8000`, not every port on
  localhost.
