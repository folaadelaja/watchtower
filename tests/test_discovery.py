import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from sentinel.core import connect, initialize
from sentinel.discovery import DiscoveryManager


class DiscoveryControlTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.db=Path(self.temp.name)/'state.db'
        initialize(self.db)
        self.manager=DiscoveryManager(lambda:self.db)
        self.real_popen=subprocess.Popen

    def tearDown(self):
        if self.manager.current and self.manager.process and self.manager.process.poll() is None:
            self.manager.control(self.manager.current['id'],'stop')
            self.wait(lambda:self.manager.current is None)
        self.temp.cleanup()

    def wait(self, condition, seconds=6):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            if condition():return
            time.sleep(.02)
        self.fail('Discovery did not reach the expected state')

    def launch(self, *args, **kwargs):
        code='import time; time.sleep(1); print(\'<nmaprun><host><status state="up"/><address addrtype="ipv4" addr="192.168.10.30"/></host></nmaprun>\')'
        return self.real_popen([sys.executable,'-c',code],**kwargs)

    def test_pause_resume_completes_and_imports_inventory(self):
        with patch('sentinel.discovery.subprocess.Popen',side_effect=self.launch):
            self.assertTrue(self.manager.start('192.168.10.30'))
            self.wait(lambda:self.manager.process is not None)
            job_id=self.manager.current['id']
            self.manager.control(job_id,'pause')
            time.sleep(.15)
            with connect(self.db) as db:
                self.assertEqual(db.execute('SELECT status FROM discoveries').fetchone()[0],'paused')
            self.manager.control(job_id,'resume')
            self.wait(lambda:self.manager.current is None)
            with connect(self.db) as db:
                self.assertEqual(db.execute('SELECT status FROM discoveries').fetchone()[0],'done')
                self.assertEqual(db.execute('SELECT count(*) FROM assets').fetchone()[0],1)

    def test_stop_paused_discovery_does_not_import_partial_results(self):
        with patch('sentinel.discovery.subprocess.Popen',side_effect=self.launch):
            self.manager.start('192.168.10.30')
            self.wait(lambda:self.manager.process is not None)
            job_id=self.manager.current['id']
            self.manager.control(job_id,'pause')
            self.manager.control(job_id,'stop')
            self.wait(lambda:self.manager.current is None)
            with connect(self.db) as db:
                self.assertEqual(db.execute('SELECT status FROM discoveries').fetchone()[0],'stopped')
                self.assertEqual(db.execute('SELECT count(*) FROM assets').fetchone()[0],0)
