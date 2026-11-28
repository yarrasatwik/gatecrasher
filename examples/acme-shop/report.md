# Gatecrasher security report

**3 ways in · 17 findings** · report `r-20261128-164821-dd149c` · 2026-11-28 16:48 UTC

critical 4 · high 5 · medium 6 · low 2 · info 0

- Target: http://localhost:3030
- Environment: Production
- AI mode: on (claude-sonnet-5-5 via Claude Code)

## Findings by root cause

A root cause is one thing to fix. A way in is a root cause that is exploitable now.

### Root cause: Browsers choose the identifier that unlocks internal_tools

`RC-A2E6FEBF` · CRITICAL · way in · 1 finding

#### [CRITICAL] Anyone can switch on internal tools by typing a staff-style email

`GC-32B2A0B1` · `IDENTIFIER_FORGERY` · subject `internal_tools` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** The production flag service decides who gets internal_tools based on the identifier a visitor supplies. Any identifier matching the staff pattern, such as a@acmeshop.dev, flips internal_tools from off to on. The client key is enough to try it, and no trait or login is involved.

**Why it matters.** The identifier is chosen by the caller and never verified, so turning off client traits does not close this gap.

**Business impact.** Outsiders could reach staff-only tools and whatever data or actions they expose, in production.

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

**Fix:** Stop granting access from a caller-supplied identifier. Decide staff access on the server after real authentication, or use a verified signed value, then retest. (plan `plan-6995c9d7`)

### Root cause: Production lets clients set traits

`RC-D41DCAF8` · CRITICAL · closed · 4 findings

#### [CRITICAL] Anyone can unlock the admin panel by claiming to be an admin

`GC-70850605` · `TRAIT_FORGERY` · subject `admins` · ✓ BLOCKED · detected by flagsmith-engine, live-probe

**What happened.** The system decides who gets the admin panel based on a "role" value the user's own app sends. Our test sent role=admin from outside, and the production flag admin_panel switched from off to on. No password or login was needed.

**Why it matters.** The app trusts a claim the user can make up themselves, so the admin check protects nothing.

**Business impact.** Any customer or attacker could reach admin features, risking data exposure, unauthorized changes, and compliance or reputational damage.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-a7609204-0087-4c7f-b0a2-6476e1a9d6d2","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "admin_panel" to an identity with trait/identifier role="admin" (segment "admins"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-a7609204-0087-4c7f-b0a2-6476e1a9d6d2","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-a7609204-0087-4c7f-b0a2-6476e1a9d6d2","traits":[{"id":null,"trait_key":"role","trait_value":"admin","transient":true}],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T20:39:02.996158Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":30,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T20:39:03.247648Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":7,"enabled":true,"reason":"TARGETING_MATCH; segment=admins","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T20:39:03.496434Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T20:39:03.731596Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"…
```

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-65b9a852a40e53b758ec355867a51b31","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-08aa2021dc661f0c39e857cbd3dd58e7","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Stop deciding admin access from user-supplied values. Base it on server-verified identity, and enforce admin permissions on the server too. (plan `plan-8f239e2c`)

#### [CRITICAL] Anyone can unlock staff-only features by typing a staff email

`GC-1A45D85C` · `TRAIT_FORGERY` · subject `staff` · ✓ BLOCKED · detected by flagsmith-engine, live-probe

**What happened.** The app trusts an email address supplied by the visitor's own device. An outsider sent the staff email a@acmeshop.dev with no verification, and the system switched the staff_preview feature from off to on in Production.

**Why it matters.** The staff segment is decided by unverified, user-supplied data, so anyone can claim to be staff.

**Business impact.** Unreleased staff-only features could be exposed to the public, leaking product plans and possibly bypassing intended access controls.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-10d2b266-c5fc-4a8b-a3a3-948be3308780","traits":[{"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "staff_preview" to an identity with trait/identifier email="a@acmeshop.dev" (segment "staff"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-10d2b266-c5fc-4a8b-a3a3-948be3308780","traits":[{"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-10d2b266-c5fc-4a8b-a3a3-948be3308780","traits":[{"id":null,"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T20:39:02.996158Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T20:39:03.247648Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":31,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T20:39:03.496434Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":8,"enabled":true,"reason":"TARGETING_MATCH; segment=staff","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T20:39:03.731596Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_valu…
```

</details>

**Fix:** Decide staff membership on your server from verified identity, not client-sent traits. Remove email-based staff targeting from client-visible rules. (plan `plan-8f239e2c`)

#### [HIGH] Anyone can unlock the paid export feature by claiming to be on the gold plan

`GC-688647D2` · `TRAIT_FORGERY` · subject `gold_plan` · ✓ BLOCKED · detected by flagsmith-engine, live-probe

**What happened.** Using only the public client key, an outsider sent a request stating their plan was "gold". The system accepted this and switched the premium_export feature from off to on. No login or payment check was involved.

**Why it matters.** The plan level is taken from information the user supplies, so it can't be trusted. Anyone can claim any plan.

**Business impact.** Free or lower-tier users can use a paid feature without paying, which means lost upgrade revenue and weaker value for paying customers.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-3b0f91a3-30a3-43c4-9838-d8d4fe6cdefa","traits":[{"trait_key":"plan","trait_value":"gold","transient":true}],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "premium_export" to an identity with trait/identifier plan="gold" (segment "gold_plan"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-3b0f91a3-30a3-43c4-9838-d8d4fe6cdefa","traits":[{"trait_key":"plan","trait_value":"gold","transient":true}],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-3b0f91a3-30a3-43c4-9838-d8d4fe6cdefa","traits":[{"id":null,"trait_key":"plan","trait_value":"gold","transient":true}],"flags":[{"id":29,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T20:39:02.996158Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":6,"enabled":true,"reason":"TARGETING_MATCH; segment=gold_plan","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T20:39:03.247648Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T20:39:03.496434Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T20:39:03.731596Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null…
```

</details>

**Fix:** Decide access to premium_export on the server using verified billing data, not user-supplied traits. Remove or restrict the gold_plan segment's reliance on client-provided values. (plan `plan-8f239e2c`)

#### [MEDIUM] Anyone can forge user traits in Production

`GC-A60CCA1A` · `SETTING_CLIENT_TRAITS_ON` · subject `allow_client_traits` · ✓ BLOCKED · detected by admin-settings

**What happened.** The Production environment lets client apps set their own user traits. Anyone with the public client key, which is visible in the app, can claim any trait they like.

**Why it matters.** Segments that decide who gets access by trait can be tricked. An outsider could label themselves as an admin or paying customer and be placed in that segment.

**Business impact.** People could unlock gated or paid features, beta programs, or internal tools without authorization, causing lost revenue and possible exposure of restricted functionality.

<details><summary>Evidence: setting</summary>

Environment "Production": dashboard setting "Allow client SDKs to set user traits" is ON (allow_client_traits). Anyone holding the public client key can set their own traits, so any segment keyed on a trait can be forged. Turn this setting off for every environment that uses segments for access control.

</details>

**Fix:** Turn off "Allow client SDKs to set user traits" in Production, and any other environment using trait-based segments for access control. Set traits from your trusted server instead. (plan `plan-8f239e2c`)

### Root cause: payment_config is served to browsers and contains a live secret

`RC-C11B4554` · CRITICAL · closed · 2 findings

#### [CRITICAL] Payment secret exposed in a public feature flag

`GC-8B6A1273` · `SECRET_IN_CLIENT_VALUE` · subject `payment_config` · ✓ BLOCKED · detected by deterministic

**What happened.** Anyone holding the client-side environment key can request the flag list and read the payment_config flag in Production. It contains what looks like a live payment provider API secret, plus a webhook address.

**Why it matters.** Client keys are meant to be visible in apps and browsers, so they are not private. Secrets stored in flag values are effectively public.

**Business impact.** Attackers could use the key to act as your payment account, causing fraud, financial loss, customer data exposure, and emergency cleanup costs.

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

**Fix:** Revoke and replace the exposed payment secret now, remove it from the flag, and store it in a server-side secrets manager. (plan `plan-a651a081`)

#### [HIGH] Secret payment setting is exposed to apps and browsers

`GC-0B5C5F67` · `FLAG_NOT_SERVER_ONLY` · subject `payment_config` · ✓ BLOCKED · detected by admin-settings

**What happened.** The production flag "payment_config" is classified as secret, but its "Server-side only" setting is off. Because of that, client SDKs, which run in users' browsers and apps, receive it.

**Why it matters.** Anyone who uses the app can potentially read the flag's contents. Secret values should only ever be delivered to your own servers.

**Business impact.** If the flag holds payment details or keys, outsiders could view or misuse them, risking fraud, compliance trouble, and customer trust. The evidence does not show what the value contains.

<details><summary>Evidence: setting</summary>

Feature "payment_config" is classified SECRET but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Turn on "Server-side only" for payment_config in the production dashboard. Then check what it contains and rotate any real secrets it held. (plan `plan-a651a081`)

### Root cause: Browsers choose the identifier that decides their group in the pricing_page experiment

`RC-D72363A6` · HIGH · way in · 1 finding

#### [HIGH] Visitors can choose their own price in the pricing test

`GC-DED120AC` · `EXPERIMENT_RIGGING` · subject `pricing_page` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** Anyone with the public client key can send any identifier they like and see which price variant it receives. By trying identifiers until they land in the low-price group, they can switch from price_high to price_low. Roughly half of the identifiers tried (50.5%) landed in the low-price group.

**Why it matters.** The experiment assumes users are assigned randomly. Letting people pick their group breaks that and corrupts the test results.

**Business impact.** Price-savvy visitors can get the cheaper price, reducing revenue, and the test data can no longer be trusted for pricing decisions.

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
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-5dedc56a56718a08e6a7b577a238f9df","traits":[],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Assign experiment groups on the server from trusted user IDs, not client-supplied identifiers, and enforce the price on the server when charging. (plan `plan-44408bad`)

### Root cause: Production returns stored identity data to anyone holding the client key

`RC-0D1B0E5B` · HIGH · closed · 4 findings

#### [HIGH] Customer traits readable with public client key

`GC-914405C1` · `IDENTITY_TRAIT_LEAK` · subject `ce***@acmeshop.dev` · ✓ BLOCKED · detected by live-probe, admin-settings

**What happened.** Anyone holding the public client key can request a customer's stored traits by email address. The test showed 3 traits returned for one production identity; values were masked in the evidence.

**Why it matters.** The public key is embedded in apps, so it is not secret. The "Hide sensitive data" setting is off, so personal data is served to outsiders.

**Business impact.** Customer personal data could be harvested, risking privacy-law penalties, loss of customer trust, and breach notification costs.

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

**Fix:** Turn on "Hide sensitive data" for the production environment, and review which traits are stored on identities. (plan `plan-8f239e2c`)

#### [HIGH] User profile data readable with a public key

`GC-1305BD20` · `IDENTITY_TRAIT_LEAK` · subject `qa***@acmeshop.dev` · ✓ BLOCKED · detected by live-probe

**What happened.** Anyone holding the public client key, which ships inside the app, can look up a user's stored profile traits by their identifier. We confirmed this in production for one test account; one trait was returned.

**Why it matters.** The public key is meant to be visible, so it should never unlock personal data. Anyone could look up users.

**Business impact.** Customer personal information could be harvested, creating privacy-law exposure, notification duties, and loss of customer trust.

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

**Fix:** Stop returning identity traits to public client keys, or require server-side authentication. Then review which traits are stored. (plan `plan-8f239e2c`)

#### [MEDIUM] Per-user beta setting can be read by anyone with the user ID

`GC-58B8A822` · `IDENTITY_OVERRIDE_LEAK` · subject `beta_dashboard` · ✓ BLOCKED · detected by flagsmith-engine, admin-settings, live-probe

**What happened.** Someone who knows a user's identifier and the public client key can request that user's settings and see that their beta_dashboard flag differs from the default. The actual values are masked in the evidence.

**Why it matters.** The 'Hide sensitive data' setting is off, so individual overrides are exposed rather than kept private.

**Business impact.** Unreleased features and user targeting could be revealed to outsiders or competitors. Risk is modest, since it requires a known identifier.

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

**Fix:** Turn on 'Hide sensitive data' for the Production environment so identity overrides are no longer served to clients. (plan `plan-8f239e2c`)

#### [MEDIUM] Production feature flag data is not hidden

`GC-9FE52BC7` · `SETTING_SENSITIVE_DATA_VISIBLE` · subject `hide_sensitive_data` · ✓ BLOCKED · detected by admin-settings

**What happened.** The "Hide sensitive data" setting is turned off in the Production environment. This means sensitive information tied to your feature flags is not masked in that environment.

**Why it matters.** Without masking, flag-related data that should stay private may be visible to anyone who can reach it. The evidence confirms the setting is off, but does not show that anyone has actually viewed or taken data.

**Business impact.** Customer or internal details could be exposed, raising privacy, compliance, and trust concerns if that data is seen by people who should not have it.

<details><summary>Evidence: setting</summary>

Environment "Production": dashboard setting "Hide sensitive data" is OFF (hide_sensitive_data). Sensitive data is not hidden in this environment. Turn this setting on.

</details>

**Fix:** Turn on "Hide sensitive data" in the Production environment's dashboard settings, then confirm it stays enabled. (plan `plan-8f239e2c`)

### Root cause: Browsers choose the identifier that decides early_access_ai

`RC-1C4189EB` · MEDIUM · way in · 1 finding

#### [MEDIUM] Anyone can retry identifiers until they unlock the early-access AI feature

`GC-B626FA94` · `PERCENTAGE_REROLL` · subject `early_access_ai` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** The early_access_ai flag is meant for a small test group (about 9% of users). Anyone with the public client key can send made-up user identifiers and see which ones get the feature switched on. After roughly 11 tries, one succeeds.

**Why it matters.** Access is decided by a user ID the caller chooses, so the test-group limit is not enforced against outsiders.

**Business impact.** Unreleased AI functionality can be seen or used by people who were never invited, risking leaks, unsupported usage, and a spoiled staged rollout.

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
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-85063dafe146214097000f496552304d","traits":[],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Don't rely on client-chosen identifiers for gated access. Check eligibility on the server using trusted account data, and keep unreleased features off the client-facing environment. (plan `plan-780d3357`)

### Root cause: internal_api_url is served to browsers and contains an internal URL

`RC-E570099E` · MEDIUM · closed · 2 findings

#### [MEDIUM] Internal admin address exposed in public feature flags

`GC-63E8DE85` · `INTERNAL_URL_LEAK` · subject `internal_api_url` · ✓ BLOCKED · detected by deterministic

**What happened.** Anyone holding the client key shipped to browsers can request the flag list and read a flag named internal_api_url. Its value points to a private network address for an admin endpoint.

**Why it matters.** It reveals where internal systems live and that an admin interface exists. That gives an attacker a map for further probing. The evidence does not show the address is reachable from outside.

**Business impact.** Easier targeting of internal infrastructure, and a possible step toward a larger breach if other weaknesses exist. Production is affected.

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

**Fix:** Remove internal_api_url from flags served to client keys and keep it in server-side configuration. Consider rotating or reviewing anything that relied on that address staying hidden. (plan `plan-e7a06dac`)

#### [LOW] Internal API address is exposed to client apps

`GC-03878136` · `FLAG_NOT_SERVER_ONLY` · subject `internal_api_url` · ✓ BLOCKED · detected by admin-settings

**What happened.** The flag "internal_api_url" in Production is not set to "Server-side only", so client SDKs receive it. Anyone using the public app or SDK key could potentially read this value.

**Why it matters.** The flag holds an internal URL that should stay private. Exposing it shows outsiders how your internal systems are named and laid out.

**Business impact.** Attackers could use the address to probe internal services, making targeted attacks easier. The evidence shows exposure, not an actual breach.

<details><summary>Evidence: setting</summary>

Feature "internal_api_url" is classified INTERNAL_URL but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Turn on "Server-side only" for this flag in the Production dashboard so client SDKs no longer receive it. Then check other internal-URL flags. (plan `plan-e7a06dac`)

### Root cause: project_nightjar_launch_2026_12_15 is served to browsers and contains an unreleased product name

`RC-F2DE0CCF` · MEDIUM · closed · 2 findings

#### [MEDIUM] Secret product launch name exposed in public flag list

`GC-07590992` · `UNRELEASED_PRODUCT_LEAK` · subject `project_nightjar_launch_2026_12_15` · ✓ BLOCKED · detected by deterministic

**What happened.** Anyone holding the client key used by your app can request the production flag list and see a flag named 'project_nightjar_launch_2026_12_15'. The name reveals an internal codename and a planned launch date of December 15, 2026. The flag's value was empty.

**Why it matters.** Flag names are sent to every client, so unreleased plans are visible to anyone who looks. Only the name leaked, not product details.

**Business impact.** Competitors, press, or investors could learn about the launch and its timing before you announce it, weakening your marketing plans and competitive position.

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

**Fix:** Rename the flag to a neutral name with no codename or date, and keep launch-related flags out of client-visible environments until release. (plan `plan-ab69ce83`)

#### [LOW] Secret launch flag is visible to client apps

`GC-64038665` · `FLAG_NOT_SERVER_ONLY` · subject `project_nightjar_launch_2026_12_15` · ✓ BLOCKED · detected by admin-settings

**What happened.** A flag named for an unreleased product is not set to "Server-side only" in Production, so client SDKs receive it. Anyone inspecting the app's flag data could see its name.

**Why it matters.** The flag name reveals an internal project name and a planned launch date. The evidence shows exposure of the name, not other values.

**Business impact.** Competitors or press could learn about the unannounced product and its timing before you announce it.

<details><summary>Evidence: setting</summary>

Feature "project_nightjar_launch_2026_12_15" is classified UNRELEASED_PRODUCT but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Turn on "Server-side only" for this flag in Production. Consider renaming it to something non-descriptive. (plan `plan-ab69ce83`)

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
| Forging role=admin unlocks admin_panel (segment "admins") (`GC-70850605`) | ✗ EXPLOITABLE | ✓ BLOCKED | curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-65b9a852a40e53b758ec355867a51b31","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}' → admin_panel is off (exploited state on) |
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

- Probes sent: 1421
  - attack: 403 requests
  - map: 9 requests
  - parity: 1000 requests
  - recon: 3 requests
  - verify: 6 requests
- Duration: 203.5 s
  - explain: 57.8 s
  - map: 51.3 s
  - recon: 94.4 s
- Engine parity: 1000/1000
- Engine: v5.7.0
- Tool: Gatecrasher dev
- Note: skipped out-of-scope script cdn.jsdelivr.net/npm/flagsmith@10.0.0/index.js: host not in allowed_domains
- Note: early_access_ai is behind a live percentage rollout, so real users already receive it: it is not reported as an unreleased product.
