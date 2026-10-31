"""A controllable discovery process; paused time does not consume its scan timeout."""
import os
import signal
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from .core import connect, now, record_assets, validate_scope


class DiscoveryManager:
    def __init__(self, database):
        self.database = database
        self.lock = threading.RLock()
        self.process = None
        self.current = None
        self.cancelled = False
        self.stop_at = None

    def start(self, scope, rate=20):
        scope = validate_scope(scope)
        with self.lock:
            if self.current is not None:
                return False
            with connect(self.database()) as db:
                job_id = db.execute('INSERT INTO discoveries(started,scope,status) VALUES(?,?,?)', (now(), scope, 'running')).lastrowid
            self.current = {'id': job_id, 'status': 'running'}
            self.cancelled = False
            self.stop_at = None
        threading.Thread(target=self.run, args=(job_id, scope, rate), daemon=True).start()
        return True

    def update(self, status):
        self.current['status'] = status
        with connect(self.database()) as db:
            db.execute('UPDATE discoveries SET status=? WHERE id=?', (status, self.current['id']))

    def control(self, job_id, action):
        if action not in ('pause', 'resume', 'stop'):
            raise ValueError('Unknown discovery action')
        with self.lock:
            if not self.current or self.current['id'] != job_id or self.process is None or self.process.poll() is not None:
                raise ValueError('This discovery is no longer active or is still preparing')
            status = self.current['status']
            if action == 'pause' and status == 'running':
                os.killpg(self.process.pid, signal.SIGSTOP)
                self.update('paused')
            elif action == 'resume' and status == 'paused':
                os.killpg(self.process.pid, signal.SIGCONT)
                self.update('running')
            elif action == 'stop' and status in ('running', 'paused'):
                self.cancelled = True
                self.stop_at = time.monotonic()
                if status == 'paused':
                    os.killpg(self.process.pid, signal.SIGCONT)
                os.killpg(self.process.pid, signal.SIGTERM)
                self.update('stopping')
            else:
                raise ValueError('That action is not available in the current scan state')

    def run(self, job_id, scope, rate):
        status, error = 'failed', None
        proc = None
        try:
            proc = subprocess.Popen(['nmap', '-sn', '-n', '--max-retries', '1', '--max-rate', str(rate), '-oX', '-', *scope.split(',')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            with self.lock:
                self.process = proc
            active_time, previous = 0, time.monotonic()
            while True:
                try:
                    output, stderr = proc.communicate(timeout=0.5)
                    break
                except subprocess.TimeoutExpired:
                    current = time.monotonic()
                    with self.lock:
                        if self.current['status'] != 'paused':
                            active_time += current - previous
                        if self.stop_at and current - self.stop_at > 5:
                            os.killpg(proc.pid, signal.SIGKILL)
                    previous = current
                    if active_time > 600:
                        raise TimeoutError('Discovery exceeded ten minutes of active scan time')
            with self.lock:
                cancelled = self.cancelled
            if cancelled:
                status = 'stopped'
            else:
                if proc.returncode != 0:
                    raise RuntimeError('Discovery process failed; inspect the service logs')
                xml = ET.fromstring(output)
                assets = []
                for host in xml.findall('host'):
                    if host.find('status').get('state') == 'up':
                        address = host.find("address[@addrtype='ipv4']")
                        if address is not None:
                            hostname = host.find('hostnames/hostname')
                            assets.append((address.get('addr'), hostname.get('name', '') if hostname is not None else ''))
                record_assets(self.database(), assets)
                status = 'done'
        except Exception as exc:
            error = str(exc)[:500]
        finally:
            if proc and proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate()
            with self.lock:
                with connect(self.database()) as db:
                    db.execute('UPDATE discoveries SET status=?,finished=?,error=? WHERE id=?', (status, now(), error, job_id))
                self.process = None
                self.current = None
