"""Single-user homelab controller: inventory, schedules, engine status, and reports."""
import base64
import hashlib
import hmac
import json
import logging
import os
import ssl
import subprocess
import threading
import time
import re
from urllib.parse import parse_qs, urlsplit
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from . import auth, engine, reporting, scheduling
from .discovery import DiscoveryManager
from .core import SEGMENTS, SEVERITY_BANDS, connect, csv_export, decorate_finding, initialize, now, record_assets, scope_segments, validate_scope

ROOT = Path(__file__).parent
DB = Path(os.environ.get("SENTINEL_DB", "/var/lib/sentinel/state.db"))
STOP = threading.Event()
LOG = logging.getLogger("sentinel")
DISCOVERY = DiscoveryManager(lambda: DB)


def rows(sql, args=()):
    with connect(DB) as db:
        return [dict(r) for r in db.execute(sql, args)]


def setup_state():
    try:
        return json.loads((DB.parent / "setup-progress.json").read_text())
    except (OSError, ValueError):
        return {"phase": "not_started"}


def discover(scope):
    return DISCOVERY.start(scope, configuration()['discovery_rate'])


def configuration():
    values = {r['key']: r['value'] for r in rows('SELECT * FROM settings')}
    return {'discovery_enabled': values.get('discovery_enabled') == 'true',
            'discovery_interval_hours': int(values.get('discovery_interval_hours', '24')),
            'discovery_rate': int(values.get('discovery_rate', '20')),
            'max_hosts': int(values.get('max_hosts', '2')),
            'max_checks': int(values.get('max_checks', '4'))}


def update_configuration(payload):
    limits = {'discovery_interval_hours': (1,168), 'discovery_rate': (1,100), 'max_hosts': (1,8), 'max_checks': (1,8)}
    if not isinstance(payload, dict) or set(payload) - (set(limits) | {'discovery_enabled'}):
        raise ValueError('Unknown setting')
    for key, value in payload.items():
        if key == 'discovery_enabled':
            if not isinstance(value, bool):
                raise ValueError('Discovery enabled must be boolean')
        elif type(value) is not int or not limits[key][0] <= value <= limits[key][1]:
            raise ValueError(f'{key} must be between {limits[key][0]} and {limits[key][1]}')
    with connect(DB) as db:
        for key, value in payload.items():
            db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)', (key, json.dumps(value)))
        if 'discovery_enabled' in payload or 'discovery_interval_hours' in payload:
            interval = payload.get('discovery_interval_hours', configuration()['discovery_interval_hours'])
            db.execute("INSERT OR REPLACE INTO settings VALUES('next_discovery',?)", (str(time.time()+interval*3600),))
    return configuration()


def engine_state():
    state = engine.status()
    controls = {r['task_id']:r['intent'] for r in rows('SELECT * FROM task_controls')}
    for task in state['tasks']:
        raw, intent = task['status'], controls.get(task['id'])
        task['engine_status'] = raw
        if intent == 'pause' and raw in ('Stopped','Interrupted'):
            task['status'] = 'Paused'
        elif intent in ('pause','stop') and raw in ('Running','Requested','Queued'):
            task['status'] = 'Pausing' if intent == 'pause' else 'Stopping'
        elif raw in ('Stop Requested','Stop Waiting'):
            task['status'] = 'Pausing' if intent == 'pause' else 'Stopping'
        task['can_resume'] = raw in ('Stopped','Interrupted')
    with connect(DB) as db:
        for task in state['tasks']:
            if task.get('schedule_id') and task.get('schedule'):
                metadata={'task_id':task['id'],'schedule_id':task['schedule_id'],'name':task['name'],'scope':task['scope'],'segments':task['segments'],'profile':task['profile'],'enabled':True,**task['schedule']}
                metadata['name']=task['name']
                if metadata['name'].startswith('Watchtower ·'):
                    metadata['name']=f"{' + '.join(task['segments']) or 'Custom'} {metadata['recurrence']} scan"
                db.execute('INSERT OR REPLACE INTO managed_schedules VALUES(?,?,?)',(task['id'],task['schedule_id'],json.dumps(metadata)))
    task_map={task['id']:task for task in state['tasks']}
    schedules=[]
    for row in rows('SELECT * FROM managed_schedules'):
        if row['task_id'] not in task_map:continue
        data=json.loads(row['data'])
        data['enabled']=bool(task_map[row['task_id']].get('schedule_id'))
        if not data['enabled']:data['next_run']=None
        schedules.append(data)
    order={name:index for index,name in enumerate(SEGMENTS)}
    state['schedules']=sorted(schedules,key=lambda item:(min([order.get(s,99) for s in item['segments']] or [99]),item['name']))
    return state


def save_scan_schedule(payload):
    from .core import scope_segments
    start=scheduling.parse_start(payload['start'])
    recurrence=payload['recurrence']
    if recurrence not in scheduling.RECURRENCES:raise ValueError('Choose once, daily, or weekly')
    scope=validate_scope(payload['scope'])
    segments=scope_segments(scope)
    if not isinstance(payload.get('name',''),str):raise ValueError('Schedule name must be text')
    name=payload.get('name','').strip() or f"{' + '.join(segments) or 'Custom'} {recurrence} scan"
    if not 1<=len(name)<=100 or not name.isprintable():raise ValueError('Use a schedule name of 1–100 printable characters')
    task_id=payload.get('task_id')
    if task_id:
        saved=rows('SELECT * FROM managed_schedules WHERE task_id=?',(task_id,))
        if not saved:raise ValueError('Schedule not found; refresh the schedule list')
        previous=json.loads(saved[0]['data'])
        if engine.target_hosts(previous['scope'])!=engine.target_hosts(scope):raise ValueError('Create a new schedule to change its target')
        schedule_id=saved[0]['schedule_id']
        engine.edit_schedule(task_id,schedule_id,name,start,recurrence)
        enabled=previous['enabled']
    else:
        config=configuration()
        result=engine.create_assessment(scope,payload.get('profile','Full and fast'),start_now=False,start_at=start,recurrence=recurrence,display_name=name,max_hosts=config['max_hosts'],max_checks=config['max_checks'])
        task_id,schedule_id=result['task_id'],result['schedule_id']
        enabled=True
    data={'task_id':task_id,'schedule_id':schedule_id,'name':name,'scope':scope,'segments':segments,'profile':payload.get('profile','Full and fast'),'enabled':enabled,**scheduling.describe(scheduling.calendar(start,recurrence))}
    with connect(DB) as db:db.execute('INSERT OR REPLACE INTO managed_schedules VALUES(?,?,?)',(task_id,schedule_id,json.dumps(data)))
    return data


def set_scan_schedule_enabled(task_id, enabled):
    if not isinstance(enabled,bool):raise ValueError('Enabled must be boolean')
    saved=rows('SELECT * FROM managed_schedules WHERE task_id=?',(task_id,))
    if not saved:raise ValueError('Schedule not found; refresh the list')
    data=json.loads(saved[0]['data'])
    if enabled:
        if data['recurrence']=='once':scheduling.parse_start(data['start_local'])
        engine.attach_schedule(task_id,saved[0]['schedule_id'],data['recurrence'])
    else:engine.disable_schedule(task_id)
    data['enabled']=enabled
    with connect(DB) as db:db.execute('UPDATE managed_schedules SET data=? WHERE task_id=?',(json.dumps(data),task_id))
    return {'enabled':enabled}


def import_reports(force=False):
    with engine.session() as client:
        reports = client.request(engine.command("get_reports", filter="rows=100 sort-reverse=date", details="0"))
        for outer in reports.findall("report"):
            rid = outer.get("id")
            inner = outer.find("report")
            report = inner if inner is not None else outer
            status = report.findtext("scan_run_status", outer.findtext("scan_run_status", "Unknown"))
            task = outer.findtext("task/name", report.findtext("task/name", ""))
            if not rid:
                continue
            imported = rows("SELECT imported,scope,task_id FROM reports WHERE id=?", (rid,))
            if status != "Done" or (not force and imported and imported[0]["imported"]):
                continue
            detail = client.request(engine.command("get_reports", report_id=rid, details="1", ignore_pagination="1", filter="rows=-1 min_qod=70"))
            results = detail.findall(".//results/result")
            task_node = outer.find('task')
            task_id = task_node.get('id','') if task_node is not None else ''
            scope = imported[0]['scope'] if imported else ''
            target = detail.find('.//report/task/target')
            if not scope and target is not None and target.get('id'):
                target_data = client.request(engine.command('get_targets',target_id=target.get('id')))
                scope = target_data.findtext('target/hosts','')
            if not scope:
                scope = ','.join(sorted({(r.findtext('host') or '').strip() for r in results if r.findtext('host')})) or 'Target unavailable'
            with connect(DB) as db:
                db.execute("INSERT OR REPLACE INTO reports(id,task,status,scan_start,scan_end,imported,scope,task_id) VALUES(?,?,?,?,?,?,?,?)", (rid, task, status, report.findtext("scan_start", ""), report.findtext("scan_end", ""), now(),scope,task_id))
                db.execute('DELETE FROM report_findings WHERE report_id=?',(rid,))
                for result in results:
                    host = (result.findtext("host") or "").strip()
                    try:
                        validate_scope(host)
                    except ValueError:
                        continue
                    nvt = result.find("nvt")
                    oid = nvt.get("oid", "") if nvt is not None else ""
                    port = result.findtext("port", "")
                    fid = hashlib.sha256(f"{host}|{port}|{oid or result.findtext('name', '')}".encode()).hexdigest()
                    tags = nvt.findtext("tags", "") if nvt is not None else ""
                    solution = next((t.split("=", 1)[1] for t in tags.split("|") if t.startswith("solution=")), "")
                    if nvt is not None:
                        solution = nvt.findtext('solution/description') or nvt.findtext('solution') or solution
                    cves = set()
                    if nvt is not None:
                        for ref in nvt.findall('.//ref'):
                            if ref.get('type','').lower()=='cve' and re.fullmatch(r'CVE-\d{4}-\d{4,}',ref.get('id','')):
                                cves.add(ref.get('id'))
                        cves.update(re.findall(r'CVE-\d{4}-\d{4,}',nvt.findtext('cve','')))
                    cve_json = json.dumps(sorted(cves))
                    name,evidence,severity = result.findtext('name',''),result.findtext('description',''),float(result.findtext('severity','0'))
                    db.execute('''INSERT INTO findings(id,host,port,name,severity,evidence,solution,report_id,first_seen,last_seen,cves)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id)
                      DO UPDATE SET name=excluded.name,severity=excluded.severity,evidence=excluded.evidence,
                      solution=excluded.solution,report_id=excluded.report_id,last_seen=excluded.last_seen,cves=excluded.cves''',
                      (fid,host,port,name,severity,evidence,solution,rid,now(),now(),cve_json))
                    snapshot_id=result.get('id') or hashlib.sha256(f'{fid}|{evidence}|{severity}'.encode()).hexdigest()
                    db.execute('''INSERT INTO report_findings(report_id,finding_id,host,port,name,severity,evidence,solution,cves)
                      VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(report_id,finding_id) DO UPDATE SET
                      name=excluded.name,severity=excluded.severity,evidence=excluded.evidence,solution=excluded.solution,cves=excluded.cves''',
                      (rid,snapshot_id,host,port,name,severity,evidence,solution,cve_json))


def report_view(report_id, severity='All', query=''):
    reports = rows('SELECT * FROM reports WHERE id=?',(report_id,))
    if not reports:raise ValueError('Report not found')
    if severity != 'All' and severity not in SEVERITY_BANDS:raise ValueError('Unknown severity filter')
    findings = [decorate_finding(r) for r in rows('SELECT * FROM report_findings WHERE report_id=? ORDER BY severity DESC,name',(report_id,))]
    counts = {band:sum(f['severity_category']==band for f in findings) for band in SEVERITY_BANDS}
    query = query.strip().casefold()
    filtered = [f for f in findings if (severity=='All' or f['severity_category']==severity) and (not query or query in ' '.join([f['name'],f['host'],f['port'],*f['cves']]).casefold())]
    reports[0]['segments']=scope_segments(reports[0]['scope'])
    return {'report':reports[0],'findings':filtered,'severity_counts':counts,'total':len(findings),'filtered_count':len(filtered)}


def report_export_rows(view):
    return [{'scope':view['report']['scope'],'segment':f['segment'],'severity_category':f['severity_category'],'severity_score':f['severity'],'host':f['host'],'port':f['port'],'finding':f['name'],'cves':'; '.join(f['cves']),'evidence':f['evidence'],'remediation':f['solution']} for f in view['findings']]


def report_list():
    reports=rows('SELECT r.*,COUNT(f.finding_id) AS finding_count FROM reports r LEFT JOIN report_findings f ON f.report_id=r.id GROUP BY r.id ORDER BY r.scan_end DESC')
    for report in reports:report['segments']=scope_segments(report['scope'])
    return reports


def background():
    while not STOP.wait(60):
        try:
            settings = {r["key"]: r["value"] for r in rows("SELECT * FROM settings")}
            due = float(settings.get("next_discovery", "0"))
            if settings.get("discovery_enabled") == "true" and time.time() >= due:
                if discover(",".join(SEGMENTS.values())):
                    with connect(DB) as db:
                        db.execute("INSERT OR REPLACE INTO settings VALUES('next_discovery',?)", (str(time.time() + configuration()['discovery_interval_hours']*3600),))
            import_reports()
        except Exception:
            LOG.exception("Engine synchronization or scheduled discovery failed")


class Handler(BaseHTTPRequestHandler):
    server_version = "Watchtower"

    def send(self, status, body, content_type="application/json"):
        data = json.dumps(body).encode() if content_type == "application/json" else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        header = self.headers.get('Authorization', '')
        if self.command == 'GET' and self.path.split('?',1)[0] in ('/','/api/state','/api/report','/reports/summary','/reports/findings.csv') and header.startswith('Bearer '):
            token_file = Path(os.environ.get('SENTINEL_SERVICE_TOKEN_FILE','/etc/sentinel/service-token'))
            local = self.client_address[0] in ('127.0.0.1','::1',os.environ.get('SENTINEL_BIND','127.0.0.1'))
            if local and token_file.is_file() and hmac.compare_digest(header[7:].encode(),token_file.read_text().strip().encode()):
                return True
        try:
            scheme, token = self.headers.get("Authorization", "").split(" ", 1)
            username, password = base64.b64decode(token, validate=True).decode().split(":", 1)
            if scheme == "Basic" and auth.verify(DB.parent / 'auth.json', os.environ['SENTINEL_PASSWORD_FILE'], username, password):
                return True
        except (ValueError, UnicodeError, KeyError, TypeError):
            pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Watchtower"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def do_GET(self):
        if not self.authorized():
            return
        path = self.path.split("?", 1)[0]
        if path in ("/", "/app.js", "/style.css", "/report.css"):
            name, mime = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css"),'/report.css':('report.css','text/css')}[path]
            return self.send(200, (ROOT / "static" / name).read_text(), mime)
        if path == "/api/state":
            return self.send(200, {"segments": SEGMENTS, "setup": setup_state(), "assets": rows("SELECT * FROM assets ORDER BY segment,address"), "discoveries": rows("SELECT * FROM discoveries ORDER BY id DESC LIMIT 20"), "findings": [], "counts": rows("SELECT COUNT(*) AS findings, COALESCE(SUM(severity >= 7),0) AS high FROM findings")[0], "reports": report_list(), "settings": rows("SELECT * FROM settings")})
        if path == "/api/engine":
            try:
                return self.send(200, {"ready": True, **engine_state()})
            except Exception:
                LOG.exception("Engine health check failed")
                return self.send(503, {"ready": False, "message": "Engine is initializing or unavailable. Inspect the engine service logs."})
        if path == '/api/settings':
            return self.send(200, configuration())
        if path in ('/api/report','/reports/findings.csv','/reports/summary'):
            params=parse_qs(urlsplit(self.path).query)
            report_id=params.get('report_id',[''])[0]
            if not report_id:
                latest=rows('SELECT id FROM reports ORDER BY scan_end DESC LIMIT 1')
                if not latest:return self.send(404,{'error':'No completed assessment reports yet'})
                report_id=latest[0]['id']
            try:view=report_view(report_id,params.get('severity',['All'])[0],params.get('q',[''])[0][:200])
            except ValueError as error:return self.send(400,{'error':str(error)})
            if path=='/api/report':return self.send(200,view)
            if path=='/reports/findings.csv':
                export=report_export_rows(view)
                return self.send(200,csv_export(export) if export else 'scope,segment,severity_category,severity_score,host,port,finding,cves,evidence,remediation\r\n','text/csv')
            return self.send(200,reporting.render(view),'text/html')
        self.send(404, {"error": "Not found"})

    def do_POST(self):
        if not self.authorized():
            return
        if self.headers.get("X-Sentinel-Request") != "1" or self.headers.get("Content-Type") != "application/json":
            return self.send(403, {"error": "Use the dashboard to submit requests"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size < 8192:
                raise ValueError("Invalid request size")
            payload = json.loads(self.rfile.read(size))
            if self.path == '/api/password':
                auth.change_password(DB.parent / 'auth.json', os.environ['SENTINEL_PASSWORD_FILE'], payload['current_password'], payload['new_password'])
                return self.send(200, {'changed': True, 'message': 'Password changed. Sign in again using your new password.'})
            if self.path == '/api/settings':
                return self.send(200, update_configuration(payload))
            if self.path == '/api/scan-schedules':
                return self.send(200,save_scan_schedule(payload))
            if self.path == '/api/scan-schedules/enabled':
                return self.send(200,set_scan_schedule_enabled(payload['task_id'],payload['enabled']))
            if self.path == '/api/discovery/control':
                DISCOVERY.control(int(payload['id']), payload['action'])
                return self.send(200, {'accepted': True})
            if self.path == "/api/discovery":
                started = discover(payload["scope"])
                return self.send(202 if started else 409, {"started": started})
            if self.path == "/api/schedule":
                enabled = payload["enabled"]
                if not isinstance(enabled, bool):
                    raise ValueError("enabled must be boolean")
                update_configuration({'discovery_enabled': enabled})
                return self.send(200, {"enabled": enabled})
            if self.path == "/api/sync":
                import_reports()
                return self.send(200, {"synced": True})
            if self.path == "/api/assessment":
                weekly = payload.get("weekly", False)
                if not isinstance(weekly, bool):
                    raise ValueError("weekly must be boolean")
                config = configuration()
                return self.send(202, engine.create_assessment(payload["scope"], payload.get("profile", "Discovery"), weekly, max_hosts=config['max_hosts'], max_checks=config['max_checks']))
            if self.path == '/api/assessment/control':
                engine.control_assessment(payload['task_id'], payload['action'])
                with connect(DB) as db:
                    db.execute('INSERT OR REPLACE INTO task_controls VALUES(?,?)', (payload['task_id'], payload['action']))
                return self.send(202, {'accepted': True})
            if self.path == "/api/assessment/stop":
                engine.stop_assessment(payload["task_id"])
                return self.send(200, {"stopping": True})
            if self.path == "/api/assessment/unschedule":
                set_scan_schedule_enabled(payload['task_id'],False)
                return self.send(200, {"scheduled": False})
            self.send(404, {"error": "Not found"})
        except (ValueError, KeyError, TypeError) as exc:
            self.send(400, {"error": str(exc)})
        except Exception:
            LOG.exception("Request failed")
            self.send(503, {"error": "Scanner operation failed. Inspect service logs."})


class TLSHTTPServer(ThreadingHTTPServer):
    """Keep slow TLS probes out of the listener thread."""
    def __init__(self, address, handler, context):
        self.tls_context = context
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(15)
        try:
            wrapped = self.tls_context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
            return wrapped, address
        except Exception:
            connection.close()
            raise


def main():
    logging.basicConfig(level=logging.INFO)
    DB.parent.mkdir(parents=True, exist_ok=True)
    initialize(DB)
    with connect(DB) as db:
        db.execute("UPDATE discoveries SET status='interrupted',finished=? WHERE status IN ('running','paused','stopping')", (now(),))
    threading.Thread(target=background, daemon=True).start()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.environ["SENTINEL_TLS_CERT"], os.environ["SENTINEL_TLS_KEY"])
    server = TLSHTTPServer((os.environ.get("SENTINEL_BIND", "127.0.0.1"), int(os.environ.get("SENTINEL_PORT", "8443"))), Handler, context)
    try:
        server.serve_forever()
    finally:
        STOP.set()
        server.server_close()


if __name__ == "__main__":
    main()
