import json
import tempfile
import unittest
from pathlib import Path

from otsec.core import Store
from otsec.reports import normalize

ZAP = {"site": [{"@name": "https://operator:secret@192.168.10.20/app?token=secret", "alerts": [{"pluginid": "10020", "alert": "Frame protection missing", "riskcode": "2", "desc": "<p>Review browser framing policy.</p>", "solution": "<p>Set frame-ancestors.</p>"}]}]}
DEPENDENCY = {"dependencies": [{"fileName": "example-library.jar", "vulnerabilities": [{"name": "DEMO-001", "severity": "HIGH", "description": "Synthetic dependency finding"}]}]}
SPOTBUGS = b'<BugCollection><BugInstance type="SQL_INJECTION_JDBC" priority="1"><Class classname="example.Controller"/><LongMessage>Review parameter binding.</LongMessage></BugInstance></BugCollection>'
SONAR = {"issues": [{"message": "Review this code path", "severity": "MAJOR", "component": "control-api:Controller.java", "rule": "java:demo"}]}


class ReportTests(unittest.TestCase):
    def test_supported_formats_and_severity(self):
        for tool, source, severity in [('zaproxy', ZAP, 'MEDIUM'), ('dependency-check', DEPENDENCY, 'HIGH'), ('sonarqube', SONAR, 'MEDIUM')]:
            with self.subTest(tool=tool):
                rows = normalize(tool, json.dumps(source).encode())
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]['severity'], severity)
        for tool in ('spotbugs', 'find-sec-bugs'):
            self.assertEqual(normalize(tool, SPOTBUGS)[0]['rule'], 'SQL_INJECTION_JDBC')

    def test_zap_strips_markup_and_url_credentials(self):
        row = normalize('zaproxy', json.dumps(ZAP).encode())[0]
        self.assertEqual(row['resource'], 'https://192.168.10.20/app')
        self.assertEqual(row['description'], 'Review browser framing policy.')
        self.assertNotIn('secret', json.dumps(row))

    def test_malformed_xml_and_reports_are_rejected(self):
        cases = [('spotbugs', b'<!DOCTYPE BugCollection [<!ENTITY x "bad">]><BugCollection/>'), ('spotbugs', b'<wrong/>'), ('zaproxy', b'{"site":null}'), ('zaproxy', b'{"site":[{"@name":"file:///etc/passwd","alerts":[]}]}'), ('dependency-check', b'{"dependencies":[{"fileName":"x","vulnerabilities":[{}]}]}'), ('sonarqube', b'[]'), ('sonarqube', b'{"issues":[{"message":{},"component":"x","rule":"x"}]}')]
        for tool, content in cases:
            with self.subTest(tool=tool), self.assertRaises(ValueError):
                normalize(tool, content)

    def test_empty_report_is_valid_but_wrong_format_is_not(self):
        self.assertEqual(normalize('dependency-check', b'{"dependencies":[]}'), [])
        with self.assertRaises(ValueError):
            normalize('dependency-check', b'{}')

    def test_atomic_storage_deduplication_and_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'reports.db')
            try:
                store.add_environment('lab','lab','192.168.10.0/24')
                store.add_environment('plant','production','10.20.0.0/24')
                content = json.dumps(DEPENDENCY).encode()
                self.assertEqual(store.import_report('lab','dependency-check','API',content)['imported'],1)
                self.assertEqual(store.import_report('lab','dependency-check','API',content)['duplicates'],1)
                self.assertEqual(store.import_report('plant','dependency-check','API',content)['imported'],1)
                with self.assertRaises(ValueError):
                    store.import_report('lab','dependency-check','API',b'{"dependencies":[{"fileName":"x","vulnerabilities":[{}]}]}')
                self.assertEqual(store.snapshot()['counts']['findings'],2)
                self.assertEqual(store.snapshot()['counts']['report_imports'],3)
                self.assertEqual(store.snapshot()['severity_counts']['HIGH'],2)
            finally:
                store.close()
