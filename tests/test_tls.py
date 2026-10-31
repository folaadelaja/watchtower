import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from sentinel.server import Handler, TLSHTTPServer


class TLSIsolationTests(unittest.TestCase):
    def test_unfinished_tls_probe_does_not_block_other_clients(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'),'-days','1','-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root/'cert.pem',root/'key.pem')
            server=TLSHTTPServer(('127.0.0.1',0),Handler,context)
            worker=threading.Thread(target=server.serve_forever)
            worker.start()
            stalled=socket.create_connection(('127.0.0.1',server.server_port))
            try:
                with self.assertRaises(urllib.error.HTTPError) as failure:
                    urllib.request.urlopen(f'https://127.0.0.1:{server.server_port}/',context=ssl._create_unverified_context(),timeout=2)
                self.assertEqual(failure.exception.code,401)
                failure.exception.close()
            finally:
                stalled.close()
                server.shutdown()
                server.server_close()
                worker.join()
