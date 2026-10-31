import socket
import threading
import unittest
from sentinel.engine import Engine, EngineError, command, target_hosts


class ProtocolTests(unittest.TestCase):
    def test_single_host_has_no_cidr_suffix_for_greenbone(self):
        self.assertEqual(target_hosts('192.168.10.30/32,192.168.20.0/24'), '192.168.10.30,192.168.20.0/24')

    def exchange(self, response):
        local, remote = socket.socketpair()
        local.settimeout(2)
        def peer():
            with remote:
                remote.recv(4096)
                for piece in response:
                    remote.sendall(piece)
        thread = threading.Thread(target=peer)
        thread.start()
        try:
            with local:
                return Engine(local).request(command('get_version'))
        finally:
            thread.join()

    def test_fragmented_xml_response(self):
        root = self.exchange([b'<get_version_response status="200"><version>', b'22.7</version></get_version_response>'])
        self.assertEqual(root.findtext('version'), '22.7')

    def test_engine_failure_is_not_success(self):
        with self.assertRaisesRegex(EngineError, 'Authentication failed'):
            self.exchange([b'<authenticate_response status="400" status_text="Authentication failed"/>'])

    def test_truncated_response_is_not_success(self):
        with self.assertRaisesRegex(EngineError, 'closed'):
            self.exchange([b'<get_version_response status="200">'])
