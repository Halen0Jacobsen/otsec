# OT tooling foundation

## Architecture decision

Retain Java/Spring Boot, PostgreSQL, Keycloak, Mosquitto, and Python simulators
from the existing project charter. Add a Python tooling companion for passive
normalization and planning. SQLite is local prototype storage. This increment
establishes data contracts, not the entire release scope.

```text
Zeek JSONL -> local CLI -> bounded validation -> SQLite -> loopback operator UI
                              |
                    scope + tool capability + policy -> proposal + audit

Planned: Keycloak -> Spring Boot -> PostgreSQL
                       ^    |
          HTTPS/MQTT collectors + gateway
                            |
                 approvals -> queue -> isolated tool workers
```

## Contracts

- Environment: unique identity/name, immutable lab/production mode and canonical CIDR.
- Asset: environment + observed IP, first/last observation. Not authenticated device identity.
- Observation: timestamp, endpoints, responder port, service hint, boundary flag.
- Plan: environment, tool, action, literal target IP, timestamp, policy outcome.
  `proposed` and `blocked-by-policy` are the only states; approvals/execution are absent.
- Audit: local operator, action, resource, result, UTC timestamp. Successful writes
  and policy blocks are recorded. Validation failures currently return CLI errors.

## Initial threat register

| Threat | Mitigation / evidence | Remaining work |
| --- | --- | --- |
| Spoofed observations | Treat imported logs as untrusted passive evidence | Authenticated collector and device identity |
| Malformed input / partial writes | Bounds and validation before transaction; negative tests | Authenticated telemetry schemas |
| Scope crossing | Environment keys and target allowlist; isolation tests | Zones and multiple subnets |
| Unintended tool execution | Explicit capabilities; plans only; policy tests | Approved isolated workers |
| Browser script injection | textContent and restrictive CSP | Browser inspection |
| DNS rebinding / remote access | Loopback binding, exact Host validation; HTTP tests | Identity/TLS before shared deployment |
| Audit alteration / repudiation | Local SQLite records | Verified principals, protected central retention |
| Availability abuse | 5 MiB import, 10,000 rows, UI result limits | Rate limits, retention, worker cancellation |

The prototype depends on local operating-system isolation. It has no user/device
authentication, RBAC, TLS, MQTT listener, scheduler, or live sensor feed. Local
processes can read the dashboard; database owners can edit audit history. Do not
expose it via a proxy or use it as a production deployment.

## Integration sequence

1. Zeek JSONL import is implemented. Add an authenticated collector and checkpointing next.
2. Malcolm/Arkime: evaluate using existing capture/search views rather than duplicating them.
3. Wazuh: normalize alerts from approved endpoints; do not assume agents can run on PLCs.
4. ZAP: lab web applications first. Add application/URL identity, maintenance windows,
   bounded requests and result normalization before execution. IP-only plans are not ZAP jobs.
5. Custom tools: typed inputs, explicit capabilities, dry-run previews, timeouts,
   output bounds, evidence references and rollback. Avoid arbitrary shell-command APIs.

Repositories from the user's GitHub list appear in the adapter registry. Listing
them does not certify compatibility or licensing. GRFICSv3 is a candidate separate
lab; verify topology and operating requirements before adoption. Development
pipeline candidates include DependencyCheck, find-sec-bugs, SonarQube,
ggshield/trufflehog, and ScanCode; evaluate against the final Java backend.

## Delivery gates

1. Spring Boot environment/asset APIs, PostgreSQL migrations, Keycloak, viewer/operator/
   approver/admin roles, and negative authorization tests.
2. Registered devices, authenticated HTTPS/MQTT telemetry, TLS, managed credentials,
   invalid-device rejection and normalized events.
3. Collectors, findings, correlation and alert delivery.
4. Queue and isolated workers; approval bound to immutable plan hash; recheck policy
   during execution; maintenance windows, concurrency, timeouts and cancellation.
5. Remediation previews, approvals, rollback and post-change checks. Production
   active scans remain disabled until reviewed per environment.
6. SAST, SCA, CycloneDX SBOM, container scanning, requirement traceability and evidence.

## Requirement traceability (partial)

| Requirement | Prototype evidence | Release gap |
| --- | --- | --- |
| SecReq-012/013/014 | Input/range validation, atomic import tests | Complete telemetry schemas |
| SecReq-018/019 | Successful-write and policy-block audit | Verified actor and protected retention |
| SecReq-023 | Import and UI bounds | Collector rate limits |
| SecReq-028 | Focused regression tests | Full release traceability |
| SecReq-001–011 | Deferred | Identity, authorization, devices, encrypted transport |
| SecReq-015/016/020 | No app secrets needed; request logs suppressed | Managed integration secrets |
| SecReq-017/021/022 | External-boundary review flag only | Auth-failure events, detections and alerting |
| SecReq-024–027/029 | Existing GitLab security templates retained | Verified pipeline, SCA/SBOM/container evidence and remediation |

## Operator UI and report ingestion update

The local UI now supports environment creation, evidence imports and proposal creation.
Same-origin JSON writes require exact Host/Origin and a custom request header. The
local operator is still not an authenticated user; shared deployment requires the
identity, RBAC and TLS release gates above. Input-size limits and socket timeouts
bound incoming requests. No scanner executes through the API.

Working offline adapters now include ZAP Traditional JSON, Dependency-Check JSON,
SpotBugs/Find Security Bugs XML, and SonarQube issues JSON. See IntegrationContracts.md
for supported fields and limitations. Normalized findings and report import history
use separate tables and participate in the import/audit transaction. XML entities
and DOCTYPE are rejected. Free text must be reviewed for secrets before importing.

The UI follows the user-supplied current Widespread Custom brand system in [BrandSystem.md](BrandSystem.md). It uses warm paper, olive primary actions/sidebar, restrained gold accents, subtle borders, limited radii and locally bundled Inter typography. The white WCD logo remains on the olive sidebar.
