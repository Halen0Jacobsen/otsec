# OTSec

Local OT and application security workspace with separate lab and production policies. The Python companion supplements the planned Java/Spring Boot, PostgreSQL, Keycloak and Mosquitto platform.

## Run

Python 3.11+, no third-party Python packages required. From the repository root in PowerShell:

```powershell
$env:PYTHONPATH = "$PWD/tooling"
python -m otsec serve
```

Open http://127.0.0.1:8080. Configure environments and import evidence directly in the browser. Use `serve --port 8081` to select another port. Stop with Ctrl+C. On Linux/macOS, use `export PYTHONPATH="$PWD/tooling"` instead.

## Workflow

1. Add an environment with a lab/production policy and canonical CIDR.
2. Import evidence: select environment, source tool, application label and report file.
3. Review findings by severity, tool and application; open a finding for evidence and remediation guidance.
4. Create a scoped action proposal. Proposals never execute tools or change devices; production scan proposals are recorded as blocked.

The environment selector applies across views. Search/category filters narrow integrations; severity/tool/search filters narrow findings. Tables explicitly show their loaded-result limits. Reports are assigned to an operator-selected application and environment, not inferred from the network CIDR. This association is not authenticated application identity.

## Working integrations

| Tool | Supported input | Current behavior |
| --- | --- | --- |
| Zeek | JSONL conn.log | Scoped asset discovery and connection observations |
| ZAP | Traditional JSON report | Site-level alert evidence, source severity and recommended solutions |
| OWASP Dependency-Check | JSON report | Vulnerabilities associated with dependency filenames |
| SpotBugs | BugCollection XML with messages | Rule, priority, Java class and diagnostic message |
| Find Security Bugs | SpotBugs XML with plugin findings | Same parser, distinct source attribution |
| SonarQube | api/issues/search JSON response | Issues by rule, component and legacy severity |

All scanners run externally; imports do not check whether tools are installed. Setup guidance and official documentation are available per integration. SonarQube pages must be exported/imported separately; security hotspots are not supported. Unknown or newer severity formats are labeled UNKNOWN. SpotBugs priority maps to HIGH/MEDIUM/LOW for review; it is not a CVSS score.

Malcolm, Arkime, Wazuh, ScanCode, TruffleHog and ggshield are listed as planned connectors. Custom tooling supports remediation proposals only. Secret scan ingestion is pending a redacted evidence contract. The existing local `zeek/` checkout is ignored and preserved.

## CLI and synthetic examples

```powershell
$env:PYTHONPATH = "$PWD/tooling"
python -m otsec environment lab --mode lab --cidr 192.168.10.0/24
python -m otsec import-zeek lab tooling/examples/conn.jsonl
python -m otsec import-report lab --tool dependency-check --application "Demo API (synthetic)" tooling/examples/dependency-check-demo.json
python -m otsec import-report lab --tool zaproxy --application "Demo API (synthetic)" tooling/examples/zap-demo.json
python -m otsec plan lab --tool zaproxy --action scan --target 192.168.10.20
python -m otsec status
```

Examples are synthetic, not real security findings. Other samples include `spotbugs-demo.xml` and `sonarqube-demo.json`. `python -m otsec --db data/another.db status` selects another database.

## Input and trust boundaries

Imports are limited to 5 MiB and 10,000 records/findings. Zeek requires `ts`, `id.orig_h`, `id.resp_h`, integer `id.resp_p`, and optional service, with at least one endpoint in the environment CIDR. Invalid imports are rejected before writing state. Repeated normalized findings are deduplicated within source/application/environment. Successful zero-finding reports are recorded as import history, not proof of security. Suppressed findings, issue lifecycle, and automatic resolution are not modeled.

Original reports are not retained. Only selected normalized evidence is stored. ZAP site credentials, query parameters and fragments are removed; request/response bodies and alert instances are not imported. Descriptions and other free text are not guaranteed to be secret-free: review files before importing. XML entities/DOCTYPE are rejected. All displayed evidence uses DOM textContent.

The dashboard binds to 127.0.0.1 and checks Host. Writes require same-origin requests, JSON content type and a custom header; foreign origins are rejected. Browser forms and the CLI act as the local operator. This is not authentication: local processes can access the database/API, and the owner can edit audit history. Do not expose it through a proxy. No authenticated user/device identity, RBAC, TLS, scheduler, live collector, scanner execution, protected audit retention or production deployment is provided yet.

## Verification

```powershell
$env:PYTHONPATH = "$PWD/tooling"
python -m unittest discover -s tooling/tests -v
node --check tooling/otsec/web/app.js
```

Tests cover atomic imports, formats, malformed input, deduplication, scope isolation, policies, persisted state, audit, HTTP writes/origin boundaries and font serving. GitLab CI runs Python tests alongside the existing security templates; hosted CI is unverified until publication.

Fonts are bundled locally with open font licenses in `tooling/otsec/web/fonts`. No external font requests are made by the app. The interface follows the user-supplied current Widespread Custom brand system: warm paper #f4f1ea, deep olive #26351f, restrained gold #9d7744, muted grey/olive #68685f, white WCD logo on olive, subtle rules, limited corner radii and minimal shadows. Typography uses locally bundled Inter, with Plex Mono for technical identifiers. See [current brand system](Documents/BrandSystem.md).

See [architecture and delivery gates](Documents/ToolingFoundation.md) and [integration contracts](Documents/IntegrationContracts.md). Existing project and security requirements remain release targets.

## Documentation index

- [All documents](Documents/README.md)
- [Operations, CLI and troubleshooting](Documents/Operations.md)
- [Local HTTP API](Documents/API.md)
- [Verification and CI](Documents/Verification.md)
- [Source map and adapter development](tooling/README.md)
- [Contribution guidance](CONTRIBUTING.md)

Bundled fonts include their SIL Open Font License notices. The WCD logo is a user-provided brand asset. Application/logo redistribution terms have not been selected; third-party tool licenses remain independent.
