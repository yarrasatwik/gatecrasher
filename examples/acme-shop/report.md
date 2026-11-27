# Gatecrasher security report

**16 ways in** · report `r-20261127-191524-324992` · 2026-11-27 19:15 UTC

critical 3 · high 5 · medium 6 · low 2 · info 0

- Target: http://localhost:3030
- Environment: Production
- AI mode: off (heuristics)

## Findings

### [CRITICAL] Secret in a client-visible flag value: payment_config

`GC-8B6A1273` · `SECRET_IN_CLIENT_VALUE` · subject `payment_config` · ✗ EXPLOITABLE · detected by deterministic

**What happened.** The flag payment_config serves a credential to every visitor.

**Why it matters.** Flag values in a client-side environment are public; a key stored there is already exposed.

**Business impact.** Someone could use the credential to act as your service.

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

**Fix:** Rotate the credential, then move it to server-side configuration or mark the flag server-side only.

### [CRITICAL] Forging role=admin unlocks admin_panel (segment "admins")

`GC-70850605` · `TRAIT_FORGERY` · subject `admins` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** Anyone can claim user attributes such as role=admin from the browser and Flagsmith accepts them, unlocking admin_panel.

**Why it matters.** The environment lets client-side code set traits, so targeting rules based on traits are not a security boundary.

**Business impact.** Paid or privileged features can be used without paying or being authorised.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-3489d293-7174-47bd-aabe-1c01515af216","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "admin_panel" to an identity with trait/identifier role="admin" (segment "admins"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-3489d293-7174-47bd-aabe-1c01515af216","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-3489d293-7174-47bd-aabe-1c01515af216","traits":[{"id":null,"trait_key":"role","trait_value":"admin","transient":true}],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T18:01:21.396897Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":30,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T18:01:21.583758Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":7,"enabled":true,"reason":"TARGETING_MATCH; segment=admins","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T18:01:21.752189Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T18:01:21.938841Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"…
```

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-f83663b4c1cd99851b79a7e8858e7a6a","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-5ee0a649065a6fd77169aefd1d04774a","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Turn off client-side traits for this environment, or move the decision to your server.

### [CRITICAL] Forging email=a@acmeshop.dev unlocks staff_preview (segment "staff")

`GC-1A45D85C` · `TRAIT_FORGERY` · subject `staff` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** Anyone can claim user attributes such as email=a@acmeshop.dev from the browser and Flagsmith accepts them, unlocking staff_preview.

**Why it matters.** The environment lets client-side code set traits, so targeting rules based on traits are not a security boundary.

**Business impact.** Paid or privileged features can be used without paying or being authorised.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-a4579772-20fe-4c67-8a54-26a9e3b98da6","traits":[{"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "staff_preview" to an identity with trait/identifier email="a@acmeshop.dev" (segment "staff"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-a4579772-20fe-4c67-8a54-26a9e3b98da6","traits":[{"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-a4579772-20fe-4c67-8a54-26a9e3b98da6","traits":[{"id":null,"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T18:01:21.396897Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T18:01:21.583758Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":31,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T18:01:21.752189Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":8,"enabled":true,"reason":"TARGETING_MATCH; segment=staff","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T18:01:21.938841Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_valu…
```

</details>

**Fix:** Turn off client-side traits for this environment, or move the decision to your server.

### [HIGH] Users can pick their own group in experiment "Pricing page price test" (pricing_page)

`GC-DED120AC` · `EXPERIMENT_RIGGING` · subject `pricing_page` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** An outsider can steer which variant of pricing_page they receive and feed results into the experiment.

**Why it matters.** Experiment results can be manipulated by anyone who knows the public key.

**Business impact.** Decisions based on the experiment may be wrong.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-map-0","traits":[],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Variant spread over 1000 identifiers: map[price_high:516 price_low:484]

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-map-0","traits":[],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-map-0","traits":[],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T18:01:21.396897Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T18:01:21.583758Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T18:01:21.752189Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T18:01:21.938841Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":33,"featur…
```

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-e337e89129bb67b8e520fb3e429aca2f","traits":[],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Keep experiment identifiers server-side and review the results for contamination.

### [HIGH] Sensitive flag "payment_config" is not "Server-side only"

`GC-0B5C5F67` · `FLAG_NOT_SERVER_ONLY` · subject `payment_config` · ✗ EXPLOITABLE · detected by admin-settings

**What happened.** The flag payment_config is visible to browsers but looks server-only.

**Why it matters.** Only flags marked server-side only are kept out of client responses.

**Business impact.** Server configuration is readable by anyone.

<details><summary>Evidence: setting</summary>

Feature "payment_config" is classified SECRET but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Mark the flag as server-side only.

### [HIGH] Traits of ce***@acmeshop.dev are readable by anyone with the public client key

`GC-914405C1` · `IDENTITY_TRAIT_LEAK` · subject `ce***@acmeshop.dev` · ✗ EXPLOITABLE · detected by live-probe, admin-settings

**What happened.** Looking up identity ce***@acmeshop.dev with the public key returned stored traits.

**Why it matters.** Public keys can read identity data when an identifier is known or guessable.

**Business impact.** Personal or commercial data about a customer is exposed.

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

**Fix:** Stop storing sensitive traits in Flagsmith or restrict identity reads.

### [HIGH] Traits of qa***@acmeshop.dev are readable by anyone with the public client key

`GC-1305BD20` · `IDENTITY_TRAIT_LEAK` · subject `qa***@acmeshop.dev` · ✗ EXPLOITABLE · detected by live-probe

**What happened.** Looking up identity qa***@acmeshop.dev with the public key returned stored traits.

**Why it matters.** Public keys can read identity data when an identifier is known or guessable.

**Business impact.** Personal or commercial data about a customer is exposed.

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

**Fix:** Stop storing sensitive traits in Flagsmith or restrict identity reads.

### [HIGH] Forging plan=gold unlocks premium_export (segment "gold_plan")

`GC-688647D2` · `TRAIT_FORGERY` · subject `gold_plan` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** Anyone can claim user attributes such as plan=gold from the browser and Flagsmith accepts them, unlocking premium_export.

**Why it matters.** The environment lets client-side code set traits, so targeting rules based on traits are not a security boundary.

**Business impact.** Paid or privileged features can be used without paying or being authorised.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-71ca5c19-fbb0-4924-9ad1-caccf7842ce0","traits":[{"trait_key":"plan","trait_value":"gold","transient":true}],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "premium_export" to an identity with trait/identifier plan="gold" (segment "gold_plan"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-71ca5c19-fbb0-4924-9ad1-caccf7842ce0","traits":[{"trait_key":"plan","trait_value":"gold","transient":true}],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-71ca5c19-fbb0-4924-9ad1-caccf7842ce0","traits":[{"id":null,"trait_key":"plan","trait_value":"gold","transient":true}],"flags":[{"id":29,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T18:01:21.396897Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":6,"enabled":true,"reason":"TARGETING_MATCH; segment=gold_plan","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T18:01:21.583758Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T18:01:21.752189Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T18:01:21.938841Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null…
```

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-aaac923b57c397c13bd693e8fef6f356","traits":[{"trait_key":"plan","trait_value":"gold","transient":true}],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-4f5f395e1c51756ea0ac82bd672abbe5","traits":[{"trait_key":"plan","trait_value":"gold","transient":true}],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Turn off client-side traits for this environment, or move the decision to your server.

### [MEDIUM] Identity override on beta_dashboard is readable by anyone who knows the identifier

`GC-58B8A822` · `IDENTITY_OVERRIDE_LEAK` · subject `beta_dashboard` · ✗ EXPLOITABLE · detected by flagsmith-engine, admin-settings, live-probe

**What happened.** Looking up identity beta_dashboard with the public key exposed per-user flag overrides.

**Why it matters.** Identity overrides reveal who has special access.

**Business impact.** Information about VIP users and their entitlements is exposed.

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

**Fix:** Remove sensitive identity overrides or avoid identifiers that are easy to guess.

### [MEDIUM] Internal URL leaked to every browser: internal_api_url

`GC-63E8DE85` · `INTERNAL_URL_LEAK` · subject `internal_api_url` · ✗ EXPLOITABLE · detected by deterministic

**What happened.** The flag internal_api_url reveals an internal address or hostname.

**Why it matters.** Internal URLs map your network and help targeted attacks.

**Business impact.** Attackers learn where internal systems live.

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

**Fix:** Remove the value from client-visible flags or mark the flag server-side only.

### [MEDIUM] Re-rolling the identifier unlocks early_access_ai (≈9% rollout, ~11 tries)

`GC-B626FA94` · `PERCENTAGE_REROLL` · subject `early_access_ai` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** A visitor can keep choosing new identifiers until they land in the rollout group for early_access_ai.

**Why it matters.** Percentage rollouts are decided by the identifier, which the client controls.

**Business impact.** Gated or early-access features can be reached on demand, and rollout numbers become unreliable.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-map-9","traits":[],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "early_access_ai" to an identity with trait/identifier identifier="gc-probe-map-9" (segment "canary_10"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-map-9","traits":[],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-map-9","traits":[],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T18:01:21.396897Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T18:01:21.583758Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T18:01:21.752189Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":32,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T18:01:21.938841Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":9,"enabled":true,"reason":"TARGETING_MATCH; segment=canary_10","variant…
```

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-0e62fd1fac37c9f62d74e98305802e65","traits":[],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Do not use percentage rollouts as access control; derive identifiers on the server.

### [MEDIUM] Production: "Allow client SDKs to set user traits" is ON

`GC-A60CCA1A` · `SETTING_CLIENT_TRAITS_ON` · subject `allow_client_traits` · ✗ EXPLOITABLE · detected by admin-settings

**What happened.** The environment allow_client_traits allows client-side traits.

**Why it matters.** Anyone with the public key can send traits that change flag results.

**Business impact.** Trait-based targeting can be bypassed.

<details><summary>Evidence: setting</summary>

Environment "Production": dashboard setting "Allow client SDKs to set user traits" is ON (allow_client_traits). Anyone holding the public client key can set their own traits, so any segment keyed on a trait can be forged. Turn this setting off for every environment that uses segments for access control.

</details>

**Fix:** Disable client traits after confirming no app code needs them.

### [MEDIUM] Production: "Hide sensitive data" is OFF

`GC-9FE52BC7` · `SETTING_SENSITIVE_DATA_VISIBLE` · subject `hide_sensitive_data` · ✗ EXPLOITABLE · detected by admin-settings

**What happened.** The environment hide_sensitive_data does not hide sensitive data.

**Why it matters.** Sensitive flag data is returned to client-side requests.

**Business impact.** Secrets and internal details reach browsers.

<details><summary>Evidence: setting</summary>

Environment "Production": dashboard setting "Hide sensitive data" is OFF (hide_sensitive_data). Sensitive data is not hidden in this environment. Turn this setting on.

</details>

**Fix:** Enable the hide sensitive data setting.

### [MEDIUM] Unreleased product leaked through flag: project_nightjar_launch_2026_12_15

`GC-07590992` · `UNRELEASED_PRODUCT_LEAK` · subject `project_nightjar_launch_2026_12_15` · ✗ EXPLOITABLE · detected by deterministic

**What happened.** The flag project_nightjar_launch_2026_12_15 names an unreleased product or launch date.

**Why it matters.** Flag names are visible to anyone with the public key.

**Business impact.** Competitors or press can learn about the launch early.

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

**Fix:** Rename the flag to something neutral or mark it server-side only.

### [LOW] Sensitive flag "internal_api_url" is not "Server-side only"

`GC-03878136` · `FLAG_NOT_SERVER_ONLY` · subject `internal_api_url` · ✗ EXPLOITABLE · detected by admin-settings

**What happened.** The flag internal_api_url is visible to browsers but looks server-only.

**Why it matters.** Only flags marked server-side only are kept out of client responses.

**Business impact.** Server configuration is readable by anyone.

<details><summary>Evidence: setting</summary>

Feature "internal_api_url" is classified INTERNAL_URL but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Mark the flag as server-side only.

### [LOW] Sensitive flag "project_nightjar_launch_2026_12_15" is not "Server-side only"

`GC-64038665` · `FLAG_NOT_SERVER_ONLY` · subject `project_nightjar_launch_2026_12_15` · ✗ EXPLOITABLE · detected by admin-settings

**What happened.** The flag project_nightjar_launch_2026_12_15 is visible to browsers but looks server-only.

**Why it matters.** Only flags marked server-side only are kept out of client responses.

**Business impact.** Server configuration is readable by anyone.

<details><summary>Evidence: setting</summary>

Feature "project_nightjar_launch_2026_12_15" is classified UNRELEASED_PRODUCT but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Mark the flag as server-side only.

## Environment security settings

| Environment | Client traits | Sensitive data hidden | Server-only flags | Client-visible flags |
|---|---|---|---|---|
| Production | ✗ Allowed | ✗ Visible | 0 | 11 |

## Reachability map

| Flag | Reachable value | Via | Engine-verified | Live-verified |
|---|---|---|---|---|
| premium_export | enabled | forged traits plan=gold, segment gold_plan | ✓ Yes | ✓ Yes |
| admin_panel | enabled | forged traits role=admin, segment admins | ✓ Yes | ✓ Yes |
| staff_preview | enabled | forged traits email=a@acmeshop.dev, segment staff | ✓ Yes | ✓ Yes |
| early_access_ai | enabled | identifier gc-probe-map-9, segment canary_10 | ✓ Yes | ✓ Yes |
| pricing_page | enabled, value price_low | identifier gc-probe-map-0 | ✓ Yes | ✓ Yes |

## Method and scope

Scope (the only hosts contacted):

- `localhost`
- `localhost:8000`

- Probes sent: 1352
- Duration: 31.0 s
  - explain: 6 ms
  - map: 19.6 s
  - recon: 11.4 s
- Engine parity: 1000/1000
- Engine: v5.7.0
- Tool: Gatecrasher dev
- Note: skipped out-of-scope script cdn.jsdelivr.net/npm/flagsmith@10.0.0/index.js: host not in allowed_domains
