#!/bin/bash
set -euo pipefail
cd /opt/sentinel/app
install -d -m 700 /etc/sentinel
install -d -m 750 /var/lib/sentinel
python3 - <<'PY'
import os
import secrets
from pathlib import Path
for name in ('dashboard-password', 'engine-password', 'service-token'):
    path = Path('/etc/sentinel') / name
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(secrets.token_urlsafe(24) + '\n')
PY
if [ ! -f /etc/sentinel/tls.key ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -keyout /etc/sentinel/tls.key \
    -out /etc/sentinel/tls.crt -days 365 -subj '/CN=sentinel-scanner' \
    -addext 'subjectAltName=DNS:sentinel-scanner,IP:192.168.10.30' 2>/dev/null
  chmod 600 /etc/sentinel/tls.key
fi
cat > /etc/systemd/system/sentinel.service <<'UNIT'
[Unit]
Description=Watchtower vulnerability management dashboard
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=/opt/sentinel/app
ExecStart=/usr/bin/python3 -m sentinel.server
Environment=SENTINEL_BIND=192.168.10.30
Environment=SENTINEL_PORT=8443
Environment=SENTINEL_DB=/var/lib/sentinel/state.db
Environment=SENTINEL_PASSWORD_FILE=/etc/sentinel/dashboard-password
Environment=GMP_PASSWORD_FILE=/etc/sentinel/engine-password
Environment=SENTINEL_TLS_CERT=/etc/sentinel/tls.crt
Environment=SENTINEL_TLS_KEY=/etc/sentinel/tls.key
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/sentinel
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now sentinel
cat > /etc/systemd/system/sentinel-engine-credentials.service <<'UNIT'
[Unit]
Description=Configure the scanner engine admin credential
After=scanner-engine-bootstrap.service
Requires=scanner-engine-bootstrap.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/sentinel/app/infra/initialize-engine.py
TimeoutStartSec=5400
RemainAfterExit=yes
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now --no-block sentinel-engine-credentials
cat > /etc/systemd/system/sentinel-feed-refresh.service <<'UNIT'
[Unit]
Description=Refresh Greenbone vulnerability feed data
After=network-online.target scanner-engine-bootstrap.service
Requires=scanner-engine-bootstrap.service
[Service]
Type=oneshot
WorkingDirectory=/opt/sentinel/engine
ExecStart=/usr/bin/docker compose pull notus-data vulnerability-tests scap-data dfn-cert-data cert-bund-data report-formats data-objects
ExecStart=/usr/bin/docker compose up -d notus-data vulnerability-tests scap-data dfn-cert-data cert-bund-data report-formats data-objects
TimeoutStartSec=7200
UNIT
cat > /etc/systemd/system/sentinel-feed-refresh.timer <<'UNIT'
[Unit]
Description=Daily vulnerability feed refresh
[Timer]
OnCalendar=*-*-* 04:00:00 America/New_York
RandomizedDelaySec=1800
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now sentinel-feed-refresh.timer
cat > /etc/systemd/system/sentinel-complete-setup.service <<'UNIT'
[Unit]
Description=Validate scanner and configure weekly assessments
After=sentinel-engine-credentials.service
Requires=sentinel-engine-credentials.service
[Service]
Type=oneshot
WorkingDirectory=/opt/sentinel/app
Environment=GMP_PASSWORD_FILE=/etc/sentinel/engine-password
Environment=PYTHONPATH=/opt/sentinel/app
ExecStart=/usr/bin/python3 /opt/sentinel/app/infra/complete-setup.py
TimeoutStartSec=infinity
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now --no-block sentinel-complete-setup
