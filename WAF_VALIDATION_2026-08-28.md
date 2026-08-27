# WAF enforcement validation — 2026-08-28

## Scope and final state

- Target: `sws.grauwolf32.tech` through Application Load Balancer
- Security profile: `fevkqrqgh8l7naetijqh`
- WAF profile: `fevmrn97327rctdd4sme`
- Log group: `e23it9714l3tfcu5nsn1`
- OWASP CRS: `4.0.0`, paranoia level `1`, anomaly threshold `5`
- Enforcement: enabled for all five rules (`dry_run = false`)
- Request body inspection: first `8 KiB`; larger bodies are denied
- HTTP/2 false positive `920280`: disabled globally
- Confirmed gRPC HTTP/2/protobuf false positives excluded only when
  `Content-Type` starts with `application/grpc`: `920180`, `920270`, `920280`,
  `920420`, `921150`
- `/healthz`, `/readyz`, `/api...`, and gRPC use API mode; other traffic uses
  FULL mode with browser CAPTCHA.

The profile was calibrated in dry-run before enforcement. Benign HTTP requests
scored zero. Untuned benign gRPC calls scored 16–21 because generic CRS rules
interpreted HTTP/2/protobuf framing as protocol violations. After the narrow
exclusion, all benign gRPC calls scored zero while the gRPC XSS marker retained
three attack signatures and a score of 15.

## Post-enforcement test matrix

| Scenario | Result | SWS evidence |
|---|---:|---|
| HTTPS `/healthz` and `/readyz` | `200`, origin | `ALLOW`, score 0 |
| HTTP `/healthz` | `200`, origin | `ALLOW`, score 0 |
| Normal HTTP/HTTPS API, login, form | `200`, origin | `ALLOW`, score 0 |
| Multipart below 8 KiB | `200`, origin | `ALLOW`, score 0 |
| Slow endpoint (`250 ms`) | `200`, origin | `ALLOW`, score 0 |
| Deliberate origin status | `418`, origin | SWS `ALLOW`; origin returned 418 |
| Benign gRPC health/Ping/Echo/Watch | `OK` | four `ALLOW`, score 0 |
| Browser-like curl to `/` | `302` | `CAPTCHA` by `waf-browser` |
| XSS over HTTPS and HTTP | `403`, edge | `DENY`, score 20, rules 941100/941110/941160/941390 |
| SQL injection | `403`, edge | `DENY`, score 5, rule 942100 |
| JSON path traversal | `403`, edge | `DENY`, score 20, rules 930100/930110/930120/932160 |
| URI path traversal | `403`, edge | `DENY`, score 10, rules 930100/930110 |
| Shell/RCE marker | `403`, edge | `DENY`, score 10, rules 930120/932160 |
| Composite XSS/SQLi/LFI/RCE | `403`, edge | `DENY`, score 55 |
| Scanner User-Agent | `403`, edge | `DENY`, score 5, rule 913100 |
| `TRACE` method | `403`, edge | `DENY`, score 5, rule 911100 |
| Log4Shell marker in a header | `403`, edge | `DENY`, score 5, rule 944150 |
| Multipart above 8 KiB | `403`, edge | `DENY` by body-size policy |
| gRPC XSS Echo | `PermissionDenied` / `403` | `DENY`, score 15, rules 941100/941110/941160 |
| Weak `hello; id` marker | `200`, origin | `ALLOW`, score 0 |

Every edge-denied HTTP response lacked `X-Lab-Response`. The weak command marker
is not recognized by CRS 4.0 at paranoia level 1; the lab origin handles it as
inert text and performs no command execution.

## Log correlation

For the post-enforcement window beginning `2026-08-27T21:12:12Z`:

- SWS: 188 records — 175 `ALLOW`, 12 `DENY`, 1 `CAPTCHA`.
- Marked validation traffic: 30 SWS records.
- Non-test traffic: 158 requests, all `ALLOW`, all to `/api/stats`; no observed
  false deny in this window.
- ALB: 348 records — 335 status 200, 11 status 403, one 302, one 418. The 403,
  302, and 418 responses correspond to controlled WAF/CAPTCHA/origin tests;
  `error_details` was empty.
- Both backend systemd services were `active`; neither journal contained a
  warning or error after enforcement.
- Origin journals contained all allowed marked requests and no denied HTTP
  request IDs. For the malicious gRPC test, health and Ping reached origin, but
  the denied Echo did not.
- ALB status was `ACTIVE`; both HTTP and gRPC targets were `HEALTHY` in
  `ru-central1-a` and `ru-central1-b`.

## Verification commands

- `terraform fmt -check -recursive`: passed
- `terraform validate`: passed
- final `terraform plan -detailed-exitcode`: exit 0, no changes
- `go test -count=1 ./...`: passed
- `ansible-playbook --syntax-check ansible/deploy.yml`: passed
- Terraform diff check: passed

## Remaining operational constraints

- FULL-mode browser traffic can receive CAPTCHA; this is expected. Health,
  readiness, API, and gRPC routes avoid CAPTCHA by using API mode.
- Requests above 8 KiB are intentionally rejected. A real upload endpoint needs
  a separately designed policy rather than a broad exception.
- HTTP port 80 remains enabled without redirection, although the same WAF policy
  is enforced on it.
- OWASP CRS does not decode protobuf schemas. The current gRPC protection is
  heuristic and complements, rather than replaces, application authentication,
  authorization, rate limiting, and message validation.

## Supplemental managed rule set comparison

Yandex Ruleset 0.1.1 was subsequently tested against this OWASP CRS 4.0.0
baseline with the same 37-case matrix and full HTTP/SWS-log correlation. OWASP
blocked 21/23 attack cases; Yandex blocked 17/23. Both produced one false
positive among 11 benign cases. The active profile was returned to OWASP after
the comparison. In the post-restore background window, 84/84 non-test requests
were allowed with score zero and no WAF match. Full methodology and artifacts are in
[`YANDEX_RULESET_COMPARISON_2026-08-28.md`](YANDEX_RULESET_COMPARISON_2026-08-28.md).
