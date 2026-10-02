"""Bounded, offline report normalization. Raw requests and secrets are not retained."""
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit, urlunsplit

MAX_BYTES = 5 * 1024 * 1024
MAX_FINDINGS = 10000
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}


def text(value, limit=2000):
    if not isinstance(value, str):
        raise ValueError("Report text fields must be strings")
    if len(value) > limit * 4:
        raise ValueError("Report field exceeds supported length")
    return re.sub(r"<[^>]*>", "", value).strip()[:limit]


def objects(value):
    if not isinstance(value, list) or len(value) > MAX_FINDINGS:
        raise ValueError("Expected a bounded list in report")
    if not all(isinstance(item, dict) for item in value):
        raise ValueError("Expected report objects")
    return value


def safe_url(value):
    parsed = urlsplit(text(value))
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("ZAP site must be an HTTP(S) URL")
    # Drop credentials, query parameters and fragments from stored evidence.
    port = parsed.port
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return urlunsplit((parsed.scheme, host + (f":{port}" if port else ""), parsed.path, "", ""))


def finding(title, severity, resource, rule, description="", solution=""):
    severity = text(severity, 30).upper()
    return {"title": text(title, 240), "severity": severity if severity in SEVERITIES else "UNKNOWN",
            "resource": text(resource, 500), "rule": text(rule, 240),
            "description": text(description), "solution": text(solution)}


def normalize(tool, content):
    if not isinstance(content, bytes) or not content or len(content) > MAX_BYTES:
        raise ValueError("Report must be between 1 byte and 5 MiB")
    result = []
    try:
        source = content.decode("utf-8-sig")
        if tool in ("spotbugs", "find-sec-bugs"):
            if "<!DOCTYPE" in source.upper() or "<!ENTITY" in source.upper():
                raise ValueError("XML declarations and entities are not supported")
            root = ET.fromstring(source)
            if root.tag != "BugCollection":
                raise ValueError("Expected a SpotBugs BugCollection")
            for bug in root.findall("BugInstance"):
                resource = bug.find("Class")
                priority = bug.get("priority", "")
                if priority not in ("1", "2", "3"):
                    raise ValueError("Invalid SpotBugs priority")
                result.append(finding(bug.findtext("LongMessage") or bug.findtext("ShortMessage") or bug.attrib["type"],
                                      {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}[priority],
                                      resource.get("classname", "unknown") if resource is not None else "unknown",
                                      bug.attrib["type"]))
        else:
            data = json.loads(source)
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON report object")
            if tool == "zaproxy":
                for site in objects(data["site"]):
                    resource = safe_url(site["@name"])
                    for alert in objects(site["alerts"]):
                        risk = str(alert["riskcode"])
                        if risk not in ("0", "1", "2", "3"):
                            raise ValueError("Invalid ZAP risk code")
                        result.append(finding(alert.get("name") or alert["alert"], {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}[risk], resource, str(alert["pluginid"]), alert.get("desc", ""), alert.get("solution", "")))
            elif tool == "dependency-check":
                for dependency in objects(data["dependencies"]):
                    for vulnerability in objects(dependency.get("vulnerabilities", [])):
                        result.append(finding(vulnerability["name"], vulnerability.get("severity", "UNKNOWN"), dependency["fileName"], vulnerability["name"], vulnerability.get("description", ""), "Review the dependency and upgrade to a verified unaffected version."))
            elif tool == "sonarqube":
                for issue in objects(data["issues"]):
                    severity = {"BLOCKER": "CRITICAL", "CRITICAL": "HIGH", "MAJOR": "MEDIUM", "MINOR": "LOW", "INFO": "INFO"}.get(issue.get("severity"), "UNKNOWN")
                    result.append(finding(issue["message"], severity, issue["component"], issue["rule"]))
            else:
                raise ValueError("This tool does not support report import")
        if len(result) > MAX_FINDINGS or any(not row["title"] or not row["rule"] for row in result):
            raise ValueError("Report exceeds finding limit or contains empty identifiers")
        return result
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError, ET.ParseError):
        raise ValueError("Invalid or unsupported report; no findings imported. Check the selected tool and report format.") from None
