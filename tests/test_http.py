import base64
import http.client
import os
import tempfile
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from sentinel.core import initialize
from sentinel import server


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.password = root / 'password'
        self.password.write_text('test-secret')
        self.db = root / 'state.db'
        initialize(self.db)
        self.env = patch.dict(os.environ, {'SENTINEL_PASSWORD_FILE': str(self.password)})
        self.env.start()
        self.database = patch.object(server, 'DB', self.db)
        self.database.start()
        self.http = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        self.worker = threading.Thread(target=self.http.serve_forever)
        self.worker.start()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.worker.join()
        self.database.stop()
        self.env.stop()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.http.server_port)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            status, data = response.status, response.read()
            return status, data
        finally:
            conn.close()

    def auth(self):
        return {'Authorization': 'Basic ' + base64.b64encode(b'admin:test-secret').decode()}

    def test_inventory_requires_authentication(self):
        self.assertEqual(self.request('GET', '/api/state')[0], 401)
        self.assertEqual(self.request('GET', '/api/state', headers=self.auth())[0], 200)

    def test_mutations_require_custom_request_header(self):
        headers = self.auth() | {'Content-Type': 'application/json'}
        self.assertEqual(self.request('POST', '/api/schedule', '{"enabled":true}', headers)[0], 403)

    def test_external_targets_rejected_without_launch(self):
        headers = self.auth() | {'Content-Type': 'application/json', 'X-Sentinel-Request': '1'}
        with patch('sentinel.discovery.subprocess.Popen') as launch:
            self.assertEqual(self.request('POST', '/api/discovery', '{"scope":"8.8.8.8"}', headers)[0], 400)
            launch.assert_not_called()

    def mutation_headers(self):
        return self.auth() | {'Content-Type':'application/json','X-Sentinel-Request':'1'}

    def test_password_change_invalidates_previous_password(self):
        payload=json.dumps({'current_password':'test-secret','new_password':'replacement-test-password'})
        self.assertEqual(self.request('POST','/api/password',payload,self.mutation_headers())[0],200)
        self.assertEqual(self.request('GET','/api/state',headers=self.auth())[0],401)
        headers={'Authorization':'Basic '+base64.b64encode(b'admin:replacement-test-password').decode()}
        self.assertEqual(self.request('GET','/api/state',headers=headers)[0],200)
        self.assertNotIn('replacement-test-password',(self.db.parent/'auth.json').read_text())

    def test_password_change_requires_correct_current_password(self):
        payload=json.dumps({'current_password':'wrong','new_password':'replacement-test-password'})
        self.assertEqual(self.request('POST','/api/password',payload,self.mutation_headers())[0],400)
        self.assertEqual(self.request('GET','/api/state',headers=self.auth())[0],200)

    def test_settings_validate_before_writing(self):
        headers=self.mutation_headers()
        self.assertEqual(self.request('POST','/api/settings','{"max_hosts":999}',headers)[0],400)
        self.assertEqual(self.request('POST','/api/settings','{"max_hosts":1,"discovery_interval_hours":6}',headers)[0],200)
        status,body=self.request('GET','/api/settings',headers=self.auth())
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['max_hosts'],1)
        self.assertEqual(json.loads(body)['discovery_interval_hours'],6)

    def test_local_service_token_cannot_change_settings(self):
        token=self.db.parent/'service-token'
        token.write_text('test-service-token')
        with patch.dict(os.environ,{'SENTINEL_SERVICE_TOKEN_FILE':str(token)}):
            headers={'Authorization':'Bearer test-service-token'}
            self.assertEqual(self.request('GET','/api/state',headers=headers)[0],200)
            self.assertEqual(self.request('GET','/api/settings',headers=headers)[0],401)
            self.assertEqual(self.request('POST','/api/settings','{}',headers)[0],401)
