# Flagsmith API verification (spec section 6)

Verified live against self-hosted **Flagsmith 2.295.2** (`flagsmith/flagsmith:2.295.2`,
Postgres, task processor, `EXPERIMENTATION_ENABLED=true`) at `http://localhost:8000/api/v1/`.
Every call below was run against the seeded Acme Shop lab. Redacted real responses are in
`tests/fixtures/*.json` (keys replaced by `REDACTED_*` placeholders, generated secret by
`acme_live_<redacted>`). The OpenAPI schema is `GET /api/v1/swagger.json`
(UI at `/api/v1/docs/`).

Auth shorthand: **client** = `X-Environment-Key: <client key>`, **server** =
`X-Environment-Key: ser.<key>`, **org** = `Authorization: Api-Key <org master key>`,
**token** = `Authorization: Token <user token>` (bootstrap only).

## Endpoints

| Purpose | Method and path | Auth | Verified notes | Fixture |
|---|---|---|---|---|
| Public flags | `GET flags/` | client | Bare JSON array. Item fields: `id, feature{id,name,created_date,description,initial_value,default_enabled,type}, feature_state_value, environment, identity, feature_segment, enabled, reason`. Server-key-only flags are absent. | `flags_client`, `flags_server_key` |
| Identity flags + traits | `GET identities/?identifier=<id>` | client | Returns `{identifier, traits[{id,trait_key,trait_value,transient}], flags[...]}`. Flag items add `reason` (for example `TARGETING_MATCH; segment=gold_plan`) and `variant`. **A GET for an unknown identifier creates the identity row** (get-or-create), so only look up configured test identities. Leaks every persisted trait (phone, lifetime_value, plan) to anyone holding the client key. | `identity_lookup_ceo` |
| Identify with traits (probe) | `POST identities/` body `{identifier, traits:[{trait_key, trait_value, transient?}], transient?}` | client | Works. **Top-level `transient: true` persists nothing** (no identity row, no traits on a later lookup). A per-trait `transient: true` alone still creates the identity row (its traits are not stored). Use top-level `transient: true`, plus per-trait `transient: true` as belt and braces. `reason` shows the matching segment. Trait values may be strings or numbers. | `identity_probe_transient`, `identity_probe_not_persisted` |
| Environment document | `GET environment-document/` | server (`ser.`) | 200. Top-level: `id, api_key, project{id,name,organisation,hide_disabled_flags,segments[{id,name,rules,feature_states}],enable_realtime_updates,server_key_only_feature_ids}, feature_states[{feature{id,name,type},enabled,django_id,feature_segment,featurestate_uuid,feature_state_value,multivariate_feature_state_values}], identity_overrides[{identifier,identity_features,identity_traits,...}], name, allow_client_traits, hide_sensitive_data, hide_disabled_flags, updated_at, use_identity_composite_key_for_hashing, use_identity_overrides_in_local_eval`. A client key gets **403**. | `environment_document` |
| Environment document (admin) | `GET environments/{client_key}/document/` | org | Same body as above. | - |
| Organisations | `GET organisations/` | org | Paginated `{count,next,previous,results}`. | `organisations` |
| Projects | `GET projects/?organisation=<id>` | org | Returns a **bare array** (not paginated). | `projects` |
| Environments | `GET environments/?project=<id>` | org | Paginated. Each env exposes `api_key` (the client key). | `environments` |
| Environment settings | `GET/PATCH environments/{client_key}/` | org | Fields confirmed: `allow_client_traits`, `hide_sensitive_data`, `hide_disabled_flags`, `use_v2_feature_versioning`, `use_identity_composite_key_for_hashing`, `use_mv_v2_evaluation`. PATCH of the two security booleans works and takes effect immediately. With `allow_client_traits=false`, `POST identities/` answers 200 but **drops the supplied traits** (response `traits: []`, forged segments do not match). | `environment_settings` |
| Features | `GET projects/{p}/features/?page_size=100`, `PATCH projects/{p}/features/{id}/` | org | `is_server_key_only` confirmed (writable via PATCH). Also `tags` (tag ids), `multivariate_options[{id,string_value,default_percentage_allocation}]`, `initial_value`, `default_enabled`, `description`, `num_segment_overrides`. Names must be lower case here (`only_allow_lower_case_feature_names`). A feature created at project level gets a state in every environment. With the flag server-only, the client key stops seeing it and the server key still does (verified), and `server_key_only_feature_ids` appears in the environment document. | `features` |
| Feature states | `GET environments/{key}/featurestates/?feature=<id>`, `PATCH environments/{key}/featurestates/{id}/` | org | PATCH body `{"enabled":bool,"feature_state_value":"<plain string>"}`. The value is a plain string in v1 (not the `{type,string_value}` object). Segment-override states carry `feature_segment=<id>`; identity overrides carry `identity`. | `featurestates` |
| Segments + rules | `GET/POST projects/{p}/segments/`, `PUT projects/{p}/segments/{id}/` | org | Rule tree `ALL -> ANY -> conditions[{property,operator,value}]`. `property` is **required and non-blank**, including for `PERCENTAGE_SPLIT` (use `$.identity.key`; omitting it is an HTTP 500). A PUT rewrites the rules (new rule ids). Experiment segments (`experiment-<n>-rollout`) are **hidden from this listing** but present in the environment document. | `segments` |
| Segment overrides | `GET features/feature-segments/?environment=<env id>&feature=<id>`, `POST environments/{key}/features/{fid}/create-segment-override/` | org | The POST needs `{"feature_segment":{"segment":<id>},"enabled":bool,"feature_state_value":{"type":"unicode","string_value":null}}`: `feature_state_value` is required even for boolean flags. The list uses the numeric **environment id**, not the key. | `feature_segments` |
| Identity overrides | `GET environments/{key}/identities/?q=<text>`, `GET/POST environments/{key}/identities/{iid}/featurestates/`, `PATCH .../{id}/` | org | POST body `{feature, enabled, environment, identity}`. In the list, `identity` is an object. Identity traits: `GET environments/{key}/identities/{iid}/traits/` (typed fields `string_value`, `integer_value`, ...). `GET environments/{key}/edge-identity-overrides` returns **HTTP 500** on this non-edge self-hosted install: do not use it. | `identities_admin`, `identity_featurestates`, `identity_traits_admin` |
| Environment server keys | `GET/POST environments/{key}/api-keys/` | org | POST `{name}` returns `{id,key,active,created_at,name,expires_at}`; the list returns the key value again. | `environment_api_keys` |
| v2 feature versioning | `POST environments/{key}/enable-v2-versioning/`, then `GET/POST environments/{env id}/features/{fid}/versions/`, `GET/PATCH .../versions/{uuid}/featurestates/`, `POST .../versions/{uuid}/publish/` | org | **Correction:** `use_v2_feature_versioning` is read-only in `PATCH environments/{key}/` (silently ignored, stays false). Enabling is an async POST (HTTP 202; the flag flips within about a second) and the version routes take the numeric **environment id**. In v2 the version's feature-state `feature_state_value` is an object `{type,string_value,integer_value,boolean_value}` (a plain string is rejected with 400). Default lab environments are **v1** (`use_v2_feature_versioning=false`), so writes are direct PATCHes. Publish answers `{"live_from": ...}`. | `feature_versions_v2`, `feature_version_publish` |
| Organisation master key | `POST organisations/{id}/master-api-keys/` body `{name,is_admin}` | token | Returns `key` (shown once, `XXXXXXXX.<32 chars>`) plus `prefix`. | - |
| Organisation webhooks | `GET/POST organisations/{id}/webhooks/`, `DELETE organisations/{id}/webhooks/{id}/` | org | POST `{url,enabled,secret}` returns `{id,url,enabled,secret,created_at,updated_at}`; DELETE answers 204. Private/internal targets are rejected unless allow-listed (see below). `POST webhooks/test/` answers 400 if nothing listens. | `organisation_webhook_create`, `organisation_webhooks_list` |
| Experimentation | `GET/POST environments/{key}/experiments/`, `POST .../{id}/start`, `pause`, `complete`, `GET .../{id}/`, `.../results/`; `GET/POST environments/{key}/experiment-metrics/` | org | See "Experiments" below. | `experiments`, `experiment_detail`, `experiment_results`, `experiment_metrics` |
| Audit log | `GET organisations/{id}/audit/`, `GET projects/{id}/audit/` | org | Both answer 200 but the list is **empty** on this install even after many writes. The generic `GET audit/` returns an **HTML 500**. Handle all three gracefully; use the webhook for change events. | `audit_org`, `audit_generic_error` |

## Corrections versus the spec

1. **Environment document** needs the **server** key, and `environments/{key}/document/` (org key) is the admin twin. Both
   return the same body; a client key is refused with 403.
2. **`GET projects/`** is a bare array, other list endpoints are paginated objects.
3. **`PERCENTAGE_SPLIT` conditions** must carry a non-blank `property` (`$.identity.key`).
4. **`create-segment-override`** requires `feature_state_value` even for boolean flags.
5. **v2 versioning** cannot be toggled by `PATCH`; use `enable-v2-versioning/` (async). Version routes use the numeric env id.
6. **Transient probes**: only the top-level `transient: true` avoids persisting the identity row.
7. **`GET identities/?identifier=`** creates an identity row for unknown identifiers.
8. **Audit log** is empty on self-hosted here; the generic `/audit/` endpoint errors.
9. **Webhook payload** is always `{"event_type":"AUDIT_LOG_CREATED","data":{...audit log record...}}`, even for flag, segment and
   environment changes; there is no separate flag-updated event type (see below).
10. **Percentage allocations**: starting an experiment zeroes `default_percentage_allocation` on the feature's options and on
    the environment base state, and moves the real 50/50 split into a hidden segment override
    (`experiment-<n>-rollout`, PERCENTAGE_SPLIT 100, multivariate 50/50). Measured over 200 fresh identities: 107 `price_low`, 93 `price_high`.

## Experiments (Flagsmith Experimentation)

Supported on self-hosted with `EXPERIMENTATION_ENABLED=true`; the lab runs one experiment per environment on `pricing_page`.

- Create: `POST environments/{key}/experiments/`
  `{feature:<id>, name, hypothesis, experiment_rollout:{enabled, rollout_percentage, feature_state_value:{type:"string",value:"price_high"}, multivariate_feature_state_values:[{multivariate_feature_option:<id>, percentage_allocation}]}}`
  (`experiment_rollout` is required; the value type enum is `integer|string|boolean`). Optional `metrics`.
- `POST .../experiments/{id}/start/` moves it from `created` to `running` (also `pause`, `complete`).
  Status enum: `created, running, paused, completed`. Only one active experiment per feature.
- While running, flags carry `metadata.experiment = {id, name, in_experiment: true}` in `identities/` responses and in the
  hidden segment's feature state in the environment document.
- `.../results/` returns `{"results": null}` until events are posted (no metrics configured in the lab).

## Webhook allow-list for `gatecrasher watch` (spec 8.12)

Flagsmith validates webhook URLs against internal/private addresses (`core.validators.validate_no_internal_address`), so
`http://10.0.3.7:9999/...` fails with HTTP 400 `URLs must not target internal or private network addresses.`
The allow-list is the environment variable **`SSRF_ALLOWED_HOSTS`** (comma separated, `*.suffix` supported). The lab sets
`SSRF_ALLOWED_HOSTS=host.docker.internal` for every Flagsmith service in `lab/compose.yaml`, and the compose file also maps
`host.docker.internal:host-gateway` for the API and task-processor containers. Verified: registering
`http://host.docker.internal:9999/hook` succeeds and Flagsmith delivers to a listener on the host.

Delivery details (verified by receiving real calls):

- Header **`X-Flagsmith-Signature`** = lowercase hex **HMAC-SHA256(secret, raw request body)**; recomputed and matched.
  `Content-Type: application/json`. Deliveries are made by the **task processor** container.
- Body `{"event_type":"AUDIT_LOG_CREATED","data":{author, created_date, environment{...}, id, log, ...}}`.
  `data.log` holds text such as `Remote config value updated for feature: banner_text`. A segment edit also produced one delivery.
  See `tests/fixtures/webhook_delivery_example.json`.

## Measured propagation on self-hosted (this lab, Windows + Docker Desktop)

Method: `PATCH` a feature state in Production, then poll every 100 ms from the write completing until the new value is visible
(8 trials; `lag.py` harness, not committed).

| Read path | min | median | max |
|---|---|---|---|
| `GET flags/` (client key, reads DB) | 0.02 s | 0.02 s | 0.03 s |
| `GET environment-document/` (server key) | 0.06 s | 0.08 s | 2.29 s (3 of 8 trials took 1.8 to 2.3 s, the rest under 0.1 s) |
| Segment rule edit visible in the environment document | 0.08 s | | |
| Org webhook delivered to a host listener | 1.40 s | 1.70 s | 1.97 s |

So on self-hosted the document lag is **seconds, not the 60 to 75 s seen on Cloud**. Keep the polling (max 150 s, configurable) but
expect convergence in under 3 s. The webhook-driven "alert in under 10 seconds" demo target is realistic: webhook arrival is about
2 s after the dashboard write, and the document needed for the map re-run is already fresh by then.

Other timings: cold lab (`down -v` then `up -d --wait`) about 75 s; first seed about 10 s; a no-op re-seed about 11 s.

## Lab-seed facts

- Only REST is used: `POST auth/users/` (signup), `auth/login/`, org, master key, project, environments, tags, segments, features,
  identities through the client key, overrides, experiments. `internal/lab` converges state; running it twice makes 0 changes
  (second run sends zero mutating requests; covered by a stub-server unit test).
- Lab credentials (admin password, org key, server keys, generated payment secret) are generated or read from Flagsmith on first run
  and kept in `lab/.state.json` (git-ignored, mode 0600). The generated payment secret (`acme_live_` + 32 hex) exists only there and in
  Flagsmith.
- With `payment_config` marked server-side only (`is_server_key_only=true`), `/api/checkout-config` in the shop kept returning the
  provider and webhook: verified live while the flag was hidden from the client key.
