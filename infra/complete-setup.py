"""Persist initial validation and install weekly assessments once feeds are ready."""
import json
import logging
import os
import time
import base64
import ssl
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo
from sentinel import engine
from sentinel.server import import_reports, rows, configuration

logging.basicConfig(level=logging.INFO)
path = Path('/var/lib/sentinel/setup-progress.json')
state = json.loads(path.read_text()) if path.exists() else {'phase': 'waiting_for_profiles', 'weekly_tasks': {}}


def save():
    state['updated'] = datetime.now(ZoneInfo('America/New_York')).isoformat()
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, indent=2))
    temporary.replace(path)


while True:
    try:
        if not state.get('validation_task'):
            with engine.session() as client:
                configs = client.request(engine.command('get_configs', filter='rows=-1'))
                if not any(c.findtext('name') == 'Full and fast' for c in configs.findall('config')):
                    state['phase'] = 'waiting_for_profiles'
                    save()
                    time.sleep(30)
                    continue
            result = engine.create_assessment('192.168.10.30', 'Full and fast', start_now=False)
            state['validation_task'] = result['task_id']
            state.pop('last_error', None)
            state['phase'] = 'validation_created'
            save()
        if state['phase'] == 'validation_created':
            with engine.session() as client:
                client.request(engine.command('start_task', task_id=state['validation_task']))
            state['phase'] = 'validation_running'
            save()
        if not state.get('validation_completed'):
            with engine.session() as client:
                result = client.request(engine.command('get_tasks', task_id=state['validation_task']))
                status = result.findtext('task/status', '')
                state['validation_status'] = status
                state.pop('last_error', None)
                save()
                if status in ('Stopped', 'Interrupted'):
                    state['phase'] = 'validation_paused'
                    save()
                    time.sleep(30)
                    continue
                if status == 'Internal Error':
                    raise RuntimeError('Validation assessment failed; inspect the engine logs')
                if status != 'Done':
                    state['phase'] = 'validation_running'
                    save()
                    time.sleep(30)
                    continue
            import_reports()
            with engine.session() as client:
                result = client.request(engine.command('get_tasks', task_id=state['validation_task']))
                last_report = result.find('task/last_report/report')
                report_id = last_report.get('id') if last_report is not None else None
            if not report_id or not rows('SELECT id FROM reports WHERE id=?', (report_id,)):
                raise RuntimeError('Validation report is not yet imported into the dashboard')
            token = Path('/etc/sentinel/service-token').read_text().strip()
            for route in ('/reports/summary', '/reports/findings.csv'):
                request = urllib.request.Request('https://192.168.10.30:8443' + route, headers={'Authorization': 'Bearer ' + token})
                with urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=30) as response:
                    if response.status != 200 or not response.read():
                        raise RuntimeError('Validation report export failed')
            state['report_exports_verified'] = True
            state['validation_completed'] = True
            state['phase'] = 'creating_weekly_schedules'
            save()
        zone = ZoneInfo('America/New_York')
        current = datetime.now(zone)
        for name, scope, hour in [('LAN', '192.168.10.0/24', 2), ('HomeLab', '192.168.30.0/24', 4), ('IoT', '192.168.20.0/24', 6)]:
            if name in state['weekly_tasks']:
                continue
            start = current.replace(hour=hour, minute=0, second=0, microsecond=0) + timedelta(days=(6-current.weekday()) % 7)
            if start <= current:
                start += timedelta(days=7)
            config = configuration()
            state['weekly_tasks'][name] = engine.create_assessment(scope, 'Full and fast', weekly=True, start_now=False, start_at=start, max_hosts=config['max_hosts'], max_checks=config['max_checks'])
            state['weekly_tasks'][name]['first_run'] = start.isoformat()
            save()
        state['phase'] = 'complete'
        state.pop('last_error', None)
        save()
        break
    except Exception as exc:
        state['last_error'] = str(exc)[:300]
        save()
        logging.exception('Initial scanner setup is awaiting readiness or investigation')
        if state.get('validation_status') == 'Internal Error':
            raise
        time.sleep(30)
