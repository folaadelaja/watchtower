# Watchtower

This public source snapshot uses example private networks, host addresses, and MAC addresses.
Configure these values and replace the SSH public-key placeholder before deploying.
No private repository history, credentials, scan results, or personal deployment keys are included.

A self-hosted homelab vulnerability management controller backed by Greenbone Community
Edition/OpenVAS. Built for LAN, IoT, and HomeLab coverage on a dedicated Proxmox VM.

## Included

- Authenticated HTTPS dashboard with real inventory and visible discovery job failures.
- Rate-limited Nmap host discovery and an optional persistent daily discovery schedule.
- Greenbone assessment creation with Discovery or Full and fast profiles, optional weekly
  scheduling, task progress, and a stop control.
- Automatic completed-report import, per-assessment result snapshots with scope, severity
  categories and CVE references, deduplicated issue history, scoped CSV export, and a
  browser-printable assessment summary (use the browser's Print to PDF for a PDF file).
- Explicit subnet scope validation and segment-isolation rules.
- Settings for password changes, discovery interval/rate, and assessment concurrency.
- Live scan activity with animation, true engine progress, and pause/resume/stop controls.
- Cloud-init bootstrap and controller installation scripts. No application dependencies
  beyond Python 3.12+, Docker Compose, Nmap, and the Greenbone containers.

## Deployment

The example deployment uses a separate Ubuntu 24.04 VM: 8 vCPUs, 24 GiB RAM,
and a 200 GiB disk. See [infrastructure notes](infra/README.md) and [design](DESIGN.md).

After copying this directory to `/opt/sentinel/app` in the guest, run
`sudo bash /opt/sentinel/app/infra/install-controller.sh`.
The cloud-init file handles the initial engine install. The network configuration script
expects the two documented MAC addresses; adapt it before reusing on another VM.

Dashboard: `https://192.168.10.30:8443`. Username: `admin`.
The generated password is stored only in `/etc/sentinel/dashboard-password` inside the VM.
The separate engine credential is stored in `/etc/sentinel/engine-password`.
Read credentials locally as an administrator; do not commit them.
Use Settings to change the dashboard password. Your new password is stored as a salted
PBKDF2 hash in `/var/lib/sentinel/auth.json`; the original login file becomes invalid.
Refresh and sign in again after changing it. The separate engine credential is unaffected.
HTTPS currently uses a self-signed certificate. Replace it with a trusted internal certificate
for regular use. Configure DHCP reservations for stable addresses.

## Operations

- Controller: `systemctl status sentinel`
- Initial engine installation: `journalctl -u scanner-engine-bootstrap`
- Engine credential initialization: `systemctl status sentinel-engine-credentials`
- Initial validation and weekly schedule setup: `systemctl status sentinel-complete-setup`
- Setup progress: `/var/lib/sentinel/setup-progress.json`
- Engine services: `docker compose -f /opt/sentinel/engine/compose.yaml ps`
- Application database: `/var/lib/sentinel/state.db` (SQLite WAL mode).
- Engine data: persistent Docker volumes. Back up the database using SQLite's backup API,
  credentials securely, and engine volumes with a consistent backup/snapshot strategy.

Feed data refresh is scheduled daily at 4 a.m. America/New_York with up to 30 minutes of
jitter using `sentinel-feed-refresh.timer`. It refreshes data images rather than automatically
upgrading engine binaries. Check timer/service status and actual feed versions; a scheduled
refresh does not guarantee a successful import. Engine connectivity alone does not establish that
feed loading is complete or that every network segment has been assessed.

Once profiles are loaded, setup validates a Full and fast assessment against the scanner
itself, then creates weekly Full and fast tasks for Sunday: LAN at 2 a.m., HomeLab at
4 a.m., and IoT at 6 a.m., all in America/New_York. The two-hour spacing is a start-time
offset, not a maximum scan duration. Tasks cap concurrent hosts/checks at 2/4.
These tasks are not configured until validation succeeds; check setup progress for the
actual state. The first full environment assessments occur at their scheduled times.

Scheduled scans lists all segment schedules with their names, targets, recurrence, and next
planned run in America/New_York. Create schedule supports one-time, daily, and weekly runs at
a chosen local date/time, including a custom IP or subnet. Edit time updates an existing
schedule; Disable/Enable preserves its association for later reuse. Creating a schedule does
not immediately start a scan. Ambiguous or nonexistent daylight-saving times are rejected
instead of silently choosing an offset. Next runs are calculated from the scanner's VEVENT,
excluding the historical timezone recurrence rules embedded in its calendar data.

## Validation and current limits

Run `python3 -m unittest discover -s tests -v`.

This is an initial single-administrator homelab release, not a Qualys/Tenable equivalent.
The controller uses Python's HTTP server behind TLS; use a hardened reverse proxy and
application server before broader deployment. It currently runs as root to access Nmap and
the engine Unix socket; privilege separation is future hardening work.
TLS handshakes run in individual request workers with a connection timeout, so an unfinished
scanner probe cannot block the dashboard listener.

Discovery pause uses operating-system process suspension; resume continues that process.
Assessment pause asks Greenbone to stop safely, then Resume uses its supported resume
operation. This is not an instantaneous freeze. Stop ends the current run; scheduled
future runs require the separate Disable schedule control. New concurrency settings apply
to newly created assessments, not existing weekly tasks. No percentage is fabricated when
the engine does not provide one. Reduced-motion preferences disable the radar animation.

Open Scan reports, select View report, then filter by severity or search finding/asset/CVE.
CSV and printable exports use the selected assessment and filters. Findings are collapsed
until opened; the detail view shows evidence and remediation. Individual result entries are
preserved per scan even when several entries refer to the same underlying check. The global
finding count deduplicates issues across reports. Missing CVE references are shown explicitly.

Finding history is retained rather than automatically marked resolved. Credentialed host
checks, user roles, risk acceptance, notifications, and automatic remediation are not yet
implemented. Network scans cannot detect every local package vulnerability. IoT devices
should start with discovery and conservative assessments. The report view displays 50 results
per page; CSV exports include all results matching its filters. The report synchronizer examines
the latest 100 reports.

Greenbone's [community container guide](https://greenbone.github.io/docs/latest/22.4/container/)
describes a community/testing setup rather than a production deployment. Review third-party
component licenses before redistributing them.
