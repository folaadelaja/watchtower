"""Bounded Greenbone Management Protocol adapter over the local Unix socket."""
import glob
import os
import socket
import xml.etree.ElementTree as ET
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from contextlib import contextmanager
from . import scheduling
from .core import scope_segments


def command(tag, **attributes):
    return ET.Element(tag, {k: str(v) for k, v in attributes.items()})


class EngineError(RuntimeError):
    pass


class Engine:
    def __init__(self, sock):
        self.sock = sock

    def request(self, element):
        self.sock.sendall(ET.tostring(element, encoding="utf-8"))
        parser = ET.XMLPullParser(events=("start", "end"))
        depth = 0
        total = 0
        while True:
            data = self.sock.recv(65536)
            if not data:
                raise EngineError("Scanner closed the connection")
            total += len(data)
            if total > 64 * 1024 * 1024:
                raise EngineError("Scanner response exceeded the size limit")
            parser.feed(data)
            for event, node in parser.read_events():
                depth += 1 if event == "start" else -1
                if event == "end" and depth == 0:
                    if not node.get("status", "").startswith("2"):
                        raise EngineError(node.get("status_text", "Scanner request failed"))
                    return node


@contextmanager
def session():
    path = os.environ.get("GMP_SOCKET")
    if not path:
        candidates = glob.glob("/var/lib/docker/volumes/*gvmd_socket_vol/_data/gvmd.sock")
        if len(candidates) != 1:
            raise EngineError("Scanner is still initializing; management socket is not ready")
        path = candidates[0]
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(120)
        sock.connect(path)
        engine = Engine(sock)
        auth = command("authenticate")
        credentials = ET.SubElement(auth, "credentials")
        ET.SubElement(credentials, "username").text = os.environ.get("GMP_USERNAME", "admin")
        ET.SubElement(credentials, "password").text = open(os.environ["GMP_PASSWORD_FILE"]).read().strip()
        engine.request(auth)
        yield engine


def status():
    with session() as engine:
        version = engine.request(command("get_version")).findtext("version")
        tasks = engine.request(command("get_tasks", filter="rows=-1"))
        feeds = engine.request(command("get_feeds"))
        configs = engine.request(command("get_configs", filter="rows=-1"))
        targets=engine.request(command('get_targets',filter='rows=-1'))
        target_scopes={t.get('id'):t.findtext('hosts','') for t in targets.findall('target')}
        task_data=[]
        for task in tasks.findall('task'):
            target=task.find('target');schedule=task.find('schedule')
            scope=target_scopes.get(target.get('id'),'') if target is not None else ''
            data={'id':task.get('id'),'name':task.findtext('name'),'status':task.findtext('status'),'progress':task.findtext('progress'),'scope':scope,'segments':scope_segments(scope),'profile':task.findtext('config/name') or 'Full and fast','schedule_id':schedule.get('id','') if schedule is not None else ''}
            if data['schedule_id']:
                data['schedule']={'name':schedule.findtext('name',''),**scheduling.describe(schedule.findtext('icalendar',''),schedule.findtext('timezone') or scheduling.ZONE)}
            task_data.append(data)
        return {"version": version, "profiles_ready": any(c.findtext("name") == "Full and fast" for c in configs.findall("config")),
                "tasks": task_data,
                "feeds": [{"name": f.findtext("name"), "version": f.findtext("version"), "type": f.findtext("type")} for f in feeds.findall("feed")]}


def target_hosts(scope):
    from .core import validate_scope
    scope = validate_scope(scope)
    return ','.join(item[:-3] if item.endswith('/32') else item for item in scope.split(','))


def create_assessment(scope, profile="Discovery", weekly=False, start_now=True, start_at=None, max_hosts=2, max_checks=4, recurrence=None, display_name=None):
    from .core import validate_scope
    scope = validate_scope(scope)
    # GMP accepts a bare IPv4 host; its host parser rejects a /32 suffix.
    hosts = target_hosts(scope)
    if profile not in ("Discovery", "Full and fast"):
        raise ValueError("Unsupported assessment profile")
    if type(max_hosts) is not int or type(max_checks) is not int or not 1 <= max_hosts <= 8 or not 1 <= max_checks <= 8:
        raise ValueError('Scan concurrency must be between 1 and 8')
    name = display_name or f"Watchtower · {profile} · {scope} · {datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
    schedule_id=''
    with session() as client:
        configs = client.request(command("get_configs", filter="rows=-1"))
        config_id = next((c.get("id") for c in configs.findall("config") if c.findtext("name") == profile), None)
        if not config_id:
            raise EngineError("Assessment profiles are not ready; feed import may still be running")
        scanners = client.request(command("get_scanners", filter="rows=-1"))
        scanner_id = next((s.get("id") for s in scanners.findall("scanner") if s.findtext("type") == "2"), None)
        ports = client.request(command("get_port_lists", filter="rows=-1"))
        port_id = next((p.get("id") for p in ports.findall("port_list") if p.findtext("name") == "All IANA assigned TCP"), None)
        if not scanner_id or not port_id:
            raise EngineError("Scanner or port-list data is not ready")
        target = command("create_target")
        ET.SubElement(target, "name").text = name
        ET.SubElement(target, "hosts").text = hosts
        ET.SubElement(target, "port_list", id=port_id)
        target_id = client.request(target).get("id")
        task = command("create_task")
        ET.SubElement(task, "name").text = name
        ET.SubElement(task, "config", id=config_id)
        ET.SubElement(task, "target", id=target_id)
        ET.SubElement(task, "scanner", id=scanner_id)
        preferences = ET.SubElement(task, "preferences")
        for key, value in (("max_hosts", str(max_hosts)), ("max_checks", str(max_checks))):
            pref = ET.SubElement(preferences, "preference")
            ET.SubElement(pref, "scanner_name").text = key
            ET.SubElement(pref, "value").text = value
        if weekly or start_at is not None:
            zone = ZoneInfo("America/New_York")
            start = start_at or (datetime.now(zone) + timedelta(days=7))
            schedule = command("create_schedule")
            frequency=recurrence or ('weekly' if weekly else 'once')
            ET.SubElement(schedule, "name").text = name
            ET.SubElement(schedule, "timezone").text = "America/New_York"
            ET.SubElement(schedule, "icalendar").text = scheduling.calendar(start,frequency)
            schedule_id = client.request(schedule).get("id")
            ET.SubElement(task, "schedule", id=schedule_id)
            ET.SubElement(task, "schedule_periods").text = '1' if frequency=='once' else '0'
        task_id = client.request(task).get("id")
        if start_now:
            client.request(command("start_task", task_id=task_id))
        return {"task_id": task_id, "weekly": weekly,'schedule_id':schedule_id,'target_id':target_id}


def stop_assessment(task_id):
    task_id = str(uuid.UUID(task_id))
    with session() as client:
        client.request(command("stop_task", task_id=task_id))


def control_assessment(task_id, action):
    task_id = str(uuid.UUID(task_id))
    if action not in ('pause','resume','stop','start'):
        raise ValueError('Unknown assessment action')
    with session() as client:
        result = client.request(command('get_tasks', task_id=task_id))
        status = result.findtext('task/status')
        if action in ('pause','stop'):
            if status in ('Stopped','Interrupted') and action == 'stop':
                return
            if status not in ('Running','Requested','Queued','Resume Requested'):
                raise ValueError('This assessment is not running')
            client.request(command('stop_task', task_id=task_id))
        elif action == 'resume':
            if status not in ('Stopped','Interrupted'):
                raise ValueError('This assessment is not paused or resumable')
            client.request(command('resume_task', task_id=task_id))
        else:
            if status not in ('New','Done','Stopped','Interrupted'):
                raise ValueError('This assessment cannot be started in its current state')
            client.request(command('start_task', task_id=task_id))


def disable_schedule(task_id):
    task_id = str(uuid.UUID(task_id))
    with session() as client:
        task = command("modify_task", task_id=task_id)
        ET.SubElement(task, "schedule", id="0")
        client.request(task)


def attach_schedule(task_id, schedule_id, recurrence='weekly'):
    with session() as client:
        task=command('modify_task',task_id=str(uuid.UUID(task_id)))
        ET.SubElement(task,'schedule',id=str(uuid.UUID(schedule_id)))
        ET.SubElement(task,'schedule_periods').text='1' if recurrence=='once' else '0'
        client.request(task)


def edit_schedule(task_id,schedule_id,name,start,recurrence):
    with session() as client:
        schedule=command('modify_schedule',schedule_id=str(uuid.UUID(schedule_id)))
        ET.SubElement(schedule,'name').text=name
        ET.SubElement(schedule,'icalendar').text=scheduling.calendar(start,recurrence)
        ET.SubElement(schedule,'timezone').text=scheduling.ZONE
        client.request(schedule)
        task=command('modify_task',task_id=str(uuid.UUID(task_id)))
        ET.SubElement(task,'name').text=name
        ET.SubElement(task,'schedule_periods').text='1' if recurrence=='once' else '0'
        client.request(task)


def rename_task(task_id,name):
    with session() as client:
        task=command('modify_task',task_id=str(uuid.UUID(task_id)))
        ET.SubElement(task,'name').text=name
        client.request(task)
