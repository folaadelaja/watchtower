"""Set the engine admin password without logging or persisting it in source."""
import pathlib
import subprocess
import time

marker = pathlib.Path('/etc/sentinel/engine-credentials-configured')
if not marker.exists():
    password = pathlib.Path('/etc/sentinel/engine-password').read_text().strip()
    for attempt in range(240):
        result = subprocess.run(
            ['docker', 'compose', '-f', '/opt/sentinel/engine/compose.yaml', 'exec', '-T',
             '-u', 'gvmd', 'gvmd', 'gvmd', '--user=admin', '--new-password=' + password],
            capture_output=True, timeout=120)
        if result.returncode == 0:
            marker.touch(mode=0o600)
            print('Engine admin credential configured successfully')
            break
        time.sleep(15)
    else:
        raise SystemExit('Engine credential initialization did not complete; inspect engine readiness')
