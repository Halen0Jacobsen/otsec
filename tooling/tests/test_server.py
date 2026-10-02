import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from http.server import HTTPServer
from pathlib import Path
from otsec.core import Store
from otsec.server import make_handler


class ServerTests(unittest.TestCase):
    def test_read_model_and_http_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "test.db"
            store = Store(database)
            store.add_environment("lab", "lab", "192.168.10.0/24")
            store.close()
            server = HTTPServer(("127.0.0.1", 0), make_handler(database))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                connection.request("GET", "/api/status")
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read())["counts"]["environments"], 1)
                connection.request("GET", "/", headers={"Host": "attacker.example"})
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                response.read()
                connection.request("POST", "/api/status", body=b"{}")
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                response.read()
                connection.request("GET", "/")
                response = connection.getresponse()
                self.assertIn("frame-ancestors 'none'", response.getheader("Content-Security-Policy"))
                self.assertIn(b"OTSec", response.read())
                headers = {'Origin': f'http://127.0.0.1:{server.server_port}', 'Content-Type': 'application/json', 'X-OTSec-Request': 'local-ui'}
                connection.request('POST', '/api/environments', body=json.dumps({'name':'plant','mode':'production','cidr':'10.20.0.0/24'}), headers=headers)
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read())['result']['mode'], 'production')
                connection.request('POST', '/api/plans', body=json.dumps({'environment':'plant','tool':'zaproxy','action':'scan','target':'10.20.0.15'}), headers=headers)
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read())['result']['state'], 'blocked-by-policy')
                connection.request('POST', '/api/import', body=json.dumps({'environment':'plant','tool':'dependency-check','application':'API','content':'{"dependencies":[]}'}), headers=headers)
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read())['result']['imported'], 0)
                connection.request('POST', '/api/import', body='[]', headers=headers)
                response = connection.getresponse()
                self.assertEqual(response.status, 400)
                response.read()
                hostile = dict(headers, Origin='http://attacker.example')
                connection.request('POST', '/api/environments', body='{}', headers=hostile)
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                response.read()
                connection.request('GET', '/fonts/inter-400.ttf')
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertTrue(response.read())
                connection.close()
            finally:
                server.shutdown()
                thread.join()
                server.server_close()
