# Integration contracts

All imports are offline; no scanner executable is invoked. An application label associates reports with an environment chosen by the local operator. Scope allowlists gate action proposals and Zeek observations; source-code reports are not restricted to IP addresses.

| Adapter | Required structure | Mapping | Official reference |
| --- | --- | --- | --- |
| zaproxy | site[] containing @name and alerts[]; pluginid, riskcode, name/alert | risk 0/1/2/3 → INFO/LOW/MEDIUM/HIGH; site URL stripped of credentials/query/fragment | https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/ |
| dependency-check | dependencies[]; fileName; optional vulnerabilities[] containing name | source severity, filename, vulnerability description | https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html |
| spotbugs | BugCollection / BugInstance; type, priority | priority 1/2/3 → HIGH/MEDIUM/LOW; Class classname; LongMessage/ShortMessage | https://spotbugs.readthedocs.io/en/latest/running.html |
| find-sec-bugs | Same SpotBugs XML, produced with security plugin | Same normalization; source identified separately by operator | https://spotbugs.readthedocs.io/en/stable/ |
| sonarqube | issues[]; message, component, rule | Legacy BLOCKER/CRITICAL/MAJOR/MINOR/INFO → CRITICAL/HIGH/MEDIUM/LOW/INFO | https://docs.sonarsource.com/sonarqube-server/extension-guide/web-api |

Unknown source severity is UNKNOWN. SonarQube pagination/hotspots are not automated. Findings do not auto-resolve when a later report omits them. ZAP occurrences are collapsed to site/alert evidence; instance URLs/requests/responses are not retained. SpotBugs same-rule/class/message findings collapse; detailed source-line identity is pending. Changing normalized evidence may create a new finding rather than update history.

The UI exposes setup guidance, format, source documentation, import and finding details. Planned connectors are clearly identified and have no import action. ScanCode/license results and secret scanner output remain pending; secret output requires deliberate redaction before storage.

Import validation occurs before one transaction that saves normalized findings, import history, and an audit event. Empty well-formed reports produce history with zero findings. Malformed reports produce no writes. UTF-8 input, 5 MiB content bounds, 10,000 finding limit and bounded text fields limit resource use; DOCTYPE/entities are forbidden. Original files and request/response content are not stored. Selected free-text fields may still contain sensitive material and must be reviewed by the operator.

Local UI writes require exact Host/Origin, JSON and X-OTSec-Request. No CORS permission is emitted. These controls prevent ordinary cross-site browser writes but do not authenticate a local process. Before production use, replace local actor identity with Keycloak/RBAC and protected audit storage, and add collector authentication/TLS.

Verification: synthetic fixtures in tooling/examples and tooling/tests/test_reports.py; HTTP boundaries and writes in tooling/tests/test_server.py. External scanners, live service APIs, hosted CI and representative user reports have not been tested.
