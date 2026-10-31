"""Scope validation and persistent inventory. No engine or web dependencies."""
import csv
import io
import ipaddress
import sqlite3
import json
from datetime import datetime, timezone
from contextlib import contextmanager

SEGMENTS = {"LAN": "192.168.10.0/24", "IoT": "192.168.20.0/24", "HomeLab": "192.168.30.0/24"}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_scope(value):
    networks = []
    for item in value.split(","):
        network = ipaddress.ip_network(item.strip(), strict=False)
        if network.version != 4 or not any(network.subnet_of(ipaddress.ip_network(s)) for s in SEGMENTS.values()):
            raise ValueError("Targets must be inside the configured LAN, IoT, or HomeLab subnet")
        networks.append(str(network))
    if not networks or len(networks) > 16:
        raise ValueError("Provide between one and sixteen targets")
    return ",".join(dict.fromkeys(networks))


def segment_for(address):
    ip = ipaddress.ip_address(address)
    return next((name for name, cidr in SEGMENTS.items() if ip in ipaddress.ip_network(cidr)), "Other")


@contextmanager
def connect(path):
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    try:
        with db:
            yield db
    finally:
        db.close()


def initialize(path):
    with connect(path) as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS assets(address TEXT PRIMARY KEY, segment TEXT NOT NULL,
          hostname TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS discoveries(id INTEGER PRIMARY KEY, started TEXT NOT NULL,
          finished TEXT, scope TEXT NOT NULL, status TEXT NOT NULL, error TEXT);
        CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, host TEXT, port TEXT,
          name TEXT, severity REAL, evidence TEXT, solution TEXT, report_id TEXT,
          first_seen TEXT, last_seen TEXT);
        CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, task TEXT, status TEXT,
          scan_start TEXT, scan_end TEXT, imported TEXT);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS task_controls(task_id TEXT PRIMARY KEY, intent TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS report_findings(report_id TEXT NOT NULL,finding_id TEXT NOT NULL,
          host TEXT,port TEXT,name TEXT,severity REAL,evidence TEXT,solution TEXT,cves TEXT NOT NULL DEFAULT '[]',
          PRIMARY KEY(report_id,finding_id));
        CREATE TABLE IF NOT EXISTS managed_schedules(task_id TEXT PRIMARY KEY,schedule_id TEXT NOT NULL,data TEXT NOT NULL);
        ''')
        for table,column,definition in [('findings','cves',"TEXT NOT NULL DEFAULT '[]'"),('reports','scope',"TEXT NOT NULL DEFAULT ''"),('reports','task_id',"TEXT NOT NULL DEFAULT ''")]:
            if column not in {row['name'] for row in db.execute(f'PRAGMA table_info({table})')}:
                db.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')


SEVERITY_BANDS = ('Critical','High','Medium','Low','Informational','Unrated')


def severity_band(score):
    if score >= 9:return 'Critical'
    if score >= 7:return 'High'
    if score >= 4:return 'Medium'
    if score > 0:return 'Low'
    if score == 0:return 'Informational'
    return 'Unrated'


def scope_segments(scope):
    names=set()
    for value in scope.split(','):
        try:
            network=ipaddress.ip_network(value.strip(),strict=False)
            for name,cidr in SEGMENTS.items():
                if network.version==4 and network.subnet_of(ipaddress.ip_network(cidr)):names.add(name)
        except ValueError:pass
    return sorted(names)


def decorate_finding(row):
    finding = dict(row)
    finding['severity_category'] = severity_band(finding['severity'])
    finding['segment'] = segment_for(finding['host'])
    finding['cves'] = json.loads(finding.get('cves') or '[]')
    return finding


def record_assets(path, assets):
    timestamp = now()
    with connect(path) as db:
        for address, hostname in assets:
            validate_scope(address)
            db.execute('''INSERT INTO assets VALUES(?,?,?,?,?) ON CONFLICT(address)
              DO UPDATE SET hostname=excluded.hostname,last_seen=excluded.last_seen''',
              (address, segment_for(address), hostname, timestamp, timestamp))


def csv_export(rows):
    out = io.StringIO()
    rows = list(rows)
    if not rows:
        return "No findings recorded\r\n"
    writer = csv.writer(out)
    writer.writerow(rows[0].keys())
    for row in rows:
        # Prevent formula execution when scanner-derived strings are opened in a spreadsheet.
        writer.writerow("'" + str(v) if isinstance(v, str) and v.lstrip().startswith(("=", "+", "-", "@")) else v for v in row.values())
    return out.getvalue()
