# Verification

## Local checks

From repository root:

```powershell
$env:PYTHONPATH = "$PWD/tooling"
python -m unittest discover -s tooling/tests -v
node --check tooling/otsec/web/app.js
git diff --check
```

Node is optional development tooling, not an application runtime requirement.
The regression suite creates temporary SQLite databases and an ephemeral loopback
HTTP server. Windows sandbox restrictions may require approved access to temporary
directories. No test contacts or changes OT devices or external scanner services.

## Coverage

| Suite | Verified behavior |
| --- | --- |
| test_core.py | Environment validation/isolation, allowlists, persistence, audits, atomic Zeek imports, malformed input, duplicate suppression, external review signals and production scan policy |
| test_reports.py | Five supported report adapter formats, source severity mapping, stripped ZAP credentials/query/markup, malformed input/XML entity rejection, empty report handling, atomic state and deduplication |
| test_server.py | GET snapshot, Host rejection, write request boundary, environment creation, production policy decisions, report imports, malformed bodies, foreign-Origin rejection, CSP and local font serving |

There are 15 unittest test methods. The latest local run is recorded in the delivery
message; this document defines how to reproduce it rather than assuming all future
commits pass. A Windows loopback connection-aborted error occurred once during
development; the unchanged suite passed on rerun. Investigate if it recurs.

## Browser verification performed

- Overview and integration catalog render with real local data.
- Synthetic Dependency-Check file import succeeds through the browser dialog.
- Findings severity filter narrows the displayed rows.
- Finding details show source, application, resource, rule and recommended action.
- Current WCT colors, logo, locally served Inter fonts and restrained
  corners were visually checked in the in-app browser.

Screenshots and demo database remain local under ignored data/; they are not
release evidence for real vulnerabilities. Browser automation is not part of CI.

## GitLab pipeline

The repository retains GitLab's SAST and secret-detection templates. A tooling-tests
job runs the unittest suite in python:3.14-slim with PYTHONPATH set to tooling.
Successful local tests do not establish hosted pipeline success. Runner availability,
template compatibility and actual analyzer results must be verified in GitLab.
SCA, CycloneDX SBOM and container scanning remain planned release controls.

## Unverified areas

Actual ZAP/Dependency-Check/SpotBugs/SonarQube execution, live API connections,
representative user reports across tool versions, Linux/macOS runtime, production
identity/RBAC/TLS, live collectors, MQTT, PostgreSQL, worker scheduling/approval/
rollback and production operational performance are not implemented or verified.
