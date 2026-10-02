"""Explicit adapter registry: capabilities are data, never shell commands."""
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Adapter:
    id: str
    name: str
    capability: str
    status: str
    repository: str
    category: str = "Network & OT"
    description: str = ""
    report_format: str = ""
    setup: str = ""
    docs: str = ""


ADAPTERS = (
    Adapter("zeek", "Zeek", "passive-monitoring", "jsonl-import", "https://github.com/Halen0Jacobsen/zeek"),
    Adapter("malcolm", "Malcolm", "traffic-analysis", "planned", "https://github.com/Halen0Jacobsen/Malcolm"),
    Adapter("arkime", "Arkime", "packet-investigation", "planned", "https://github.com/Halen0Jacobsen/arkime"),
    Adapter("wazuh", "Wazuh", "endpoint-monitoring", "planned", "https://github.com/Halen0Jacobsen/wazuh"),
    Adapter("zaproxy", "ZAP", "application-scan", "report-import", "https://github.com/Halen0Jacobsen/zaproxy", "Application security", "Review web application alerts and recommended fixes.", "Traditional JSON", "Export a Traditional JSON report from ZAP's Report Generation add-on. Import it here with an application label. Active scan execution is not connected.", "https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/"),
    Adapter("dependency-check", "OWASP Dependency-Check", "dependency-analysis", "report-import", "https://github.com/Halen0Jacobsen/DependencyCheck", "Java & supply chain", "Review vulnerable Java libraries and dependency evidence.", "JSON", "Run your installed Dependency-Check with --format JSON and import dependency-check-report.json. Vulnerability database setup and scanner execution remain external.", "https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html"),
    Adapter("spotbugs", "SpotBugs", "static-analysis", "report-import", "https://github.com/spotbugs/spotbugs", "Java & supply chain", "Inspect bytecode analysis results by class, rule and severity.", "XML with messages", "Generate SpotBugs XML using -xml:withMessages. Import the BugCollection report. The scanner runs externally on compiled Java classes.", "https://spotbugs.readthedocs.io/en/latest/running.html"),
    Adapter("find-sec-bugs", "Find Security Bugs", "static-analysis", "report-import", "https://github.com/Halen0Jacobsen/find-sec-bugs", "Java & supply chain", "Review security detectors for Java and JVM applications.", "SpotBugs XML", "Enable the Find Security Bugs plugin in SpotBugs, generate XML with messages and select this adapter when importing. Shared BugCollection format; no separate scanner is invoked.", "https://spotbugs.readthedocs.io/en/stable/"),
    Adapter("sonarqube", "SonarQube", "static-analysis", "report-import", "https://github.com/Halen0Jacobsen/sonarqube", "Java & supply chain", "Consolidate exported issues from your code quality service.", "Issues API JSON", "Export all pages of api/issues/search and import each page. Security hotspots use a different API and are not included. Server connection and token management are pending.", "https://docs.sonarsource.com/sonarqube-server/extension-guide/web-api"),
    Adapter("scancode", "ScanCode Toolkit", "license-analysis", "planned", "https://github.com/Halen0Jacobsen/scancode-toolkit", "Java & supply chain", "License and third-party package inventory.", "", "Collector and report normalization are pending."),
    Adapter("trufflehog", "TruffleHog", "secret-detection", "planned", "https://github.com/Halen0Jacobsen/trufflehog", "Java & supply chain", "Repository secret detection.", "", "A redacted findings contract is required before importing secret scan output."),
    Adapter("ggshield", "ggshield", "secret-detection", "planned", "https://github.com/Halen0Jacobsen/ggshield", "Java & supply chain", "Pre-commit and CI secret checks.", "", "Runner configuration and redacted findings ingestion are pending."),
    Adapter("custom", "Custom tooling", "remediation-proposal", "plan-only", ""),
)


def catalog():
    return [asdict(adapter) for adapter in ADAPTERS]


def get_adapter(identifier):
    for adapter in ADAPTERS:
        if adapter.id == identifier:
            return adapter
    raise ValueError("Unknown tool adapter")
