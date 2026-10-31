"""Schedule validation and summaries for the recurrence types exposed by Watchtower."""
import re
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

ZONE='America/New_York'
RECURRENCES=('once','daily','weekly')


def parse_start(value, current=None):
    try:start=datetime.fromisoformat(value)
    except (TypeError,ValueError):raise ValueError('Choose a valid start date and time')
    if start.tzinfo is not None:raise ValueError('Enter local time in America/New_York')
    zone=ZoneInfo(ZONE)
    aware=start.replace(tzinfo=zone,fold=0)
    if aware.astimezone(timezone.utc).astimezone(zone).replace(tzinfo=None)!=start:
        raise ValueError('That local time does not exist because clocks move forward; choose another time')
    if aware.utcoffset()!=start.replace(tzinfo=zone,fold=1).utcoffset():
        raise ValueError('That local time occurs twice when clocks change; choose an unambiguous time')
    if aware<= (current or datetime.now(timezone.utc)):
        raise ValueError('The schedule must start in the future')
    return aware


def calendar(start, recurrence):
    if recurrence not in RECURRENCES:raise ValueError('Choose once, daily, or weekly')
    lines=['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//Watchtower//Assessments//EN','BEGIN:VEVENT',f'UID:{uuid.uuid4()}',f'DTSTAMP:{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}',f'DTSTART;TZID={ZONE}:{start.astimezone(ZoneInfo(ZONE)):%Y%m%dT%H%M%S}','DURATION:PT0S']
    if recurrence!='once':lines.append('RRULE:FREQ='+recurrence.upper())
    return '\r\n'.join(lines+['END:VEVENT','END:VCALENDAR',''])


def describe(icalendar, zone=ZONE, current=None):
    # Greenbone embeds historical timezone RRULEs. Only the VEVENT is the scan schedule.
    unfolded=re.sub(r'\r?\n[ \t]','',icalendar or '')
    if 'BEGIN:VEVENT' not in unfolded:return {'recurrence':'unknown','start_local':'','next_run':None,'timezone':zone}
    event=unfolded.split('BEGIN:VEVENT',1)[1].split('END:VEVENT',1)[0]
    properties={line.split(':',1)[0].split(';',1)[0]:line.split(':',1)[1] for line in event.splitlines() if ':' in line}
    raw=properties.get('DTSTART','')
    try:
        tz=ZoneInfo(zone)
        start=datetime.strptime(raw.rstrip('Z'),'%Y%m%dT%H%M%S').replace(tzinfo=timezone.utc if raw.endswith('Z') else tz).astimezone(tz)
    except (ValueError,KeyError):return {'recurrence':'unknown','start_local':'','next_run':None,'timezone':zone}
    rule=properties.get('RRULE','')
    values=dict(item.split('=',1) for item in rule.split(';') if '=' in item)
    frequency=values.get('FREQ','ONCE').lower()
    supported=frequency in RECURRENCES and set(values)<= {'FREQ','INTERVAL'} and values.get('INTERVAL','1')=='1'
    result={'recurrence':frequency if supported else 'advanced','start_local':start.strftime('%Y-%m-%dT%H:%M'),'timezone':zone,'next_run':None}
    if not supported:return result
    current=(current or datetime.now(timezone.utc)).astimezone(tz)
    candidate=start
    if frequency!='once':
        days=7 if frequency=='weekly' else 1
        jumps=max(0,(current.date()-start.date()).days//days)
        candidate=start+timedelta(days=jumps*days)
        while candidate<=current or candidate.astimezone(timezone.utc).astimezone(tz).replace(tzinfo=None)!=candidate.replace(tzinfo=None):
            candidate+=timedelta(days=days)
    if candidate>current:result['next_run']=candidate.isoformat()
    return result
