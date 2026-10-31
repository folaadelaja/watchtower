"""Read-only deployment smoke checks; run as an administrator inside the guest."""
import base64
import json
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

base = 'https://192.168.10.30:8443'
context = ssl._create_unverified_context()
for attempt in range(40):
    try:
        urllib.request.urlopen(base, context=context, timeout=2)
        raise RuntimeError('Dashboard allowed unauthenticated access')
    except urllib.error.HTTPError as error:
        assert error.code == 401
        break
    except urllib.error.URLError:
        time.sleep(0.5)
else:
    raise RuntimeError('Dashboard did not become available after startup')
token = Path('/etc/sentinel/service-token').read_text().strip()
headers = {'Authorization': 'Bearer ' + token}


def get(route):
    request = urllib.request.Request(base + route, headers=headers)
    with urllib.request.urlopen(request, context=context, timeout=30) as response:
        assert response.status == 200
        return response.read()


assert b'Watchtower' in get('/')
state = json.loads(get('/api/state'))
assert state['segments'] and isinstance(state['assets'], list)
assert get('/reports/summary') and get('/reports/findings.csv')
print('HTTPS authentication, Watchtower branding, inventory API, and export endpoints passed')
print('Observed assets:', len(state['assets']))
print('Initial assessment setup phase:', state.get('setup', {}).get('phase', 'unknown'))
print('Export endpoint checks do not establish completion of a vulnerability assessment')
