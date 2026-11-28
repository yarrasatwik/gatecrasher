# Findings catalog

Severity is decided by deterministic rules in [`internal/severity`](../internal/severity) — never by the AI. The AI (or a template, in "AI off" mode) only writes the plain-English explanation.

| Finding type | What it means | Detected by | Severity | Fix Gatecrasher plans |
|---|---|---|---|---|
| `SECRET_IN_CLIENT_VALUE` | A flag value that every browser receives contains a credential (API secret, token, private key), or a server-side key is shipped in the JS bundle. | Deterministic secret detector (+ AI) | **Critical** | Mark the feature *Server-side only*; PR draft moving the value to server config; "rotate this secret" instruction |
| `TRAIT_FORGERY` | Sending a trait from the client (e.g. `role=admin`) switches a flag on. Confirmed with two fresh transient identities; only the minimal trait set is reported. | Live probe and/or Flagsmith engine + live replay | **Critical** for admin/staff/security-control flags; **High** for paid features | Turn off *Allow client SDKs to set user traits*; PR draft moving `setTrait` calls to your server (impact analysis lists every call site) |
| `EXPERIMENT_RIGGING` | A user can choose their own arm of a running Flagsmith Experimentation experiment by re-rolling the identifier or forging a trait. | Engine + live probe + Experimentation API | **High** on pricing/revenue flags, else Medium | Server-assigned identifiers (PR draft); restart the experiment after the fix. Never stopped automatically |
| `IDENTITY_TRAIT_LEAK` | The public identities endpoint returns another user's traits (PII). Tested only on configured test identities; values are masked in reports. | Live lookup (test identities) + settings | **High** | Turn on *Hide sensitive data* |
| `PII_IN_CLIENT_VALUE` | Personal data in a client-visible flag value. | Classifier | **High** | *Server-side only* + PR draft |
| `INTERNAL_URL_LEAK` | Private IPs or internal hostnames in client-visible values. | Classifier | Medium | *Server-side only* + PR draft |
| `UNRELEASED_PRODUCT_LEAK` | Codenames and launch dates in flag names or values. | Classifier | Medium | *Server-side only*; rename guidance |
| `PRICING_LEAK` | Pricing data in client-visible values. | Classifier | Medium | *Server-side only* + PR draft |
| `IDENTIFIER_FORGERY` | A segment rule tests the identifier itself (e.g. `$.identity.identifier` REGEX `.*@acmeshop\.dev$`) and the client chooses its own identifier, so picking a matching one switches a flag on. No trait is involved: this survives turning off client traits. | Flagsmith engine + live replay with a transient identifier | **Critical** for admin/staff/security-control flags; **High** otherwise | Guidance + PR draft only: assign identifiers on the server and stop targeting on identifier patterns. No Flagsmith setting closes it |
| `PERCENTAGE_REROLL` | A percentage rollout can be won by retrying identifiers (hit rate and expected tries are reported, with a working identifier as proof). | Engine + live probe | Medium | Server-assigned identifiers (PR draft) |
| `VARIANT_REROLL` | A multivariate value can be chosen by re-rolling the identifier. | Engine + live probe | Medium | Server-assigned identifiers (PR draft) |
| `IDENTITY_OVERRIDE_LEAK` | Identity overrides reveal targeted flags to anyone who knows the identifier. | Engine (environment document) + live lookup | Medium | Turn on *Hide sensitive data* |
| `SEGMENT_FORGEABLE` | A segment's conditions can be satisfied by attacker-controlled input but no live proof was possible. Reported as UNKNOWN, never as safe. | Engine | Medium | Same as trait forgery |
| `SETTING_CLIENT_TRAITS_ON` | *Allow client SDKs to set user traits* is on. | Admin settings | Medium when forgeable segments exist, else Low | Turn it off |
| `SETTING_SENSITIVE_DATA_VISIBLE` | *Hide sensitive data* is off. | Admin settings | Medium when traits are exposed, else Low | Turn it on |
| `FLAG_NOT_SERVER_ONLY` | A flag classified sensitive is not *Server-side only*. | Admin settings + classifier | High if it holds a secret, else Low | Mark it *Server-side only* |

## Statuses

- **EXPLOITABLE** — reproduced (live probe, or engine result confirmed by a live replay).
- **UNKNOWN** — the engine says it is reachable but the live API did not confirm, or the check is not possible. Never presented as safe.
- **BLOCKED** — after a fix, the exact same check no longer reproduces.
