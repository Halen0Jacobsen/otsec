# Java enterprise API

The legacy routes below are also implemented by the Java server. Java adds `GET /api/csrf`; obtain its `headerName`/`token` with the session cookie and attach that header to POST requests. Enterprise reads require VIEWER, OPERATOR or ADMIN; imports/plans require OPERATOR or ADMIN; environment creation requires ADMIN. Browser login uses `/oauth2/authorization/keycloak`. See [enterprise setup](Enterprise.md). The legacy access model described below applies only to Python.

# Local HTTP API

Base URL: `http://127.0.0.1:8080`, or the selected port. This API belongs to the local
development companion. It has no authenticated user or device identity and must
not be exposed as a shared or production service.

## Request boundary

All routes require the exact Host `127.0.0.1:PORT`. POST routes additionally require:

```text
Origin: http://127.0.0.1:PORT
Content-Type: application/json
X-OTSec-Request: local-ui
Content-Length: <positive size, no more than 6 MiB>
```

The browser supplies Origin automatically. The custom header is a same-origin
browser request control, not a password or authentication credential. No CORS
permission is emitted. Local processes can supply these headers themselves.
Connections have a 10-second socket timeout; the HTTP server handles requests
serially. This is not a production availability implementation.

## Routes

| Method | Route | Behavior |
| --- | --- | --- |
| GET | `/` | Operator HTML workspace |
| GET | `/app.js`, `/style.css`, `/wct-logo.png`, allowlisted `/fonts/*.ttf` | Static application assets |
| GET | `/api/status` | Current bounded snapshot |
| POST | `/api/environments` | Register an environment |
| POST | `/api/import` | Import Zeek observations or supported security reports |
| POST | `/api/plans` | Record proposal/policy decision; never execute |

GET snapshot fields: `environments`, `assets`, `observations`, `plans`, `audit`,
`tools`, `findings`, `report_imports`, `severity_counts`, `counts`. Counts are global;
record limits are 500 for assets/findings and 100 for observations/plans/audit/imports.
Environment and tool lists are not paginated. See core.py for field definitions.

## Register an environment

```json
{"name":"lab","mode":"lab","cidr":"192.168.10.0/24"}
```

Success: `{"result":{"id":"<UUID>","name":"lab","mode":"lab","cidr":"192.168.10.0/24"}}`.
`mode` is `lab` or `production`; name is unique and CIDR must be canonical.

## Import evidence

```json
{"environment":"lab","tool":"dependency-check","application":"Control API","content":"{\"dependencies\":[]}"}
```

`content` is a UTF-8 report represented as a JSON string, not a file path or URL.
The server never fetches a supplied URL or reads a caller-selected path. For Zeek,
use `tool: "zeek"` and JSONL content; `application` is not needed. Decoded report
content is limited to 5 MiB even though the outer JSON request limit is 6 MiB.
JSON escaping may make a file near the limit too large for the HTTP envelope;
use the CLI or split such files rather than increasing the limit.

Report success:

```json
{"result":{"imported":0,"duplicates":0,"report_id":"<UUID>"}}
```

Zeek success omits report_id. Inputs validate before transaction writes.
Original file contents are not stored; normalized evidence, import history and
audit records are. Review reports for secrets before submitting.

## Create a proposal

```json
{"environment":"lab","tool":"zaproxy","action":"scan","target":"192.168.10.20"}
```

Success: `{"result":{"id":"<UUID>","state":"proposed","executed":false}}`.
Production scans use `state: "blocked-by-policy"`, also with HTTP 200 because the
policy decision was recorded successfully. `custom` + `remediate` produces a
proposal in either policy. Target must be a literal IP inside the environment CIDR.
No execute, approve, arbitrary-command or remote-scanner endpoint exists.

## Errors and response protections

- HTTP 400: invalid JSON, missing/invalid inputs or unsupported report. POST JSON
  response uses `{"error":"<message>"}`. Validation failure does not create rows.
- HTTP 403: Host/Origin/header boundary rejected; standard HTTP error page.
- HTTP 404: unknown route; standard HTTP error page.
- HTTP 413: unsupported request size; standard HTTP error page.
- Other unsupported methods receive the standard HTTP server error response.
- Unexpected storage/transport failures are not normalized into a stable API error
  contract yet. Clients should handle non-JSON failure responses.

Successful responses disable caching and set nosniff. GET responses additionally
apply a restrictive same-origin CSP, prohibit framing and disallow object content.
Audit actor remains `local-operator`. Authentication/RBAC/TLS and protected denied-
access auditing must be added before remote deployment.
