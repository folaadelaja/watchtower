# Self-hosted vulnerability management platform

Proposed design for an example IoT, LAN, and HomeLab environment.
This is a design, not a deployed system.

## Product

Build a central dashboard around established scanning engines. Use Greenbone Community
Edition / OpenVAS as the first network vulnerability engine, integrated through its
management API. Build our own inventory, scheduling controls, normalized findings,
remediation workflow, and reporting. Evaluate additional web and container engines after
the initial workflow is reliable. Commercial product parity is not an initial milestone.

The first usable release should let the user:
- See assets grouped by network segment and identify stale or failed scans.
- Schedule lightweight discovery and deeper vulnerability assessments independently.
- View finding evidence, severity, affected asset, first/last seen, and remediation guidance.
- Track open, accepted-risk, and verified-resolved findings across scans.
- Download executive summaries, technical reports, and CSV exports.
- Inspect scanner feed freshness and job status so failures are visible.

Network scans do not reveal every local package vulnerability. Add authenticated host
assessment where supported and authorized. Keep unsupported checks and unassessed assets visible.

## Initial infrastructure proposal

Create a separate Linux VM. Start with a planning budget of 8 vCPUs, 24 GiB RAM,
and 200 GiB disk; finalize after engine requirements and actual scope are checked.

Example Proxmox bridge layout:
- vmbr0: LAN/default, 192.168.10.0/24.
- vmbr1: IoT, IPv4 subnet not yet verified.
- vmbr2: HomeLab, 192.168.30.0/24.

Preferred topology: management VM on a management-approved segment, with narrowly scoped
firewall access to scan targets. If routing cannot provide discovery and assessment coverage,
use per-segment scanner workers. A VM with three interfaces is also possible, but requires
IP forwarding and bridging between segments to remain disabled and management access restricted.
Choose the topology after confirming gateway rules and IoT addressing.

## Scanning behavior

Use explicit approved subnet allowlists. Separate routine discovery from deeper scans,
with conservative IoT policies, maintenance windows, concurrency limits, and a stop control.
Exclude disruptive test categories from routine policies. Never infer that an unreachable
device is vulnerability-free or mark findings resolved from a failed or incomplete scan.

## Application structure

Proposed stack: Python API and workers, PostgreSQL for inventory/findings/history, a persistent
job queue, and a TypeScript web dashboard. Greenbone owns its engine-specific services and
feed lifecycle. The application communicates with its supported management API rather than
replacing the scanner. Package services reproducibly and keep credentials outside Git.

## Delivery sequence

1. Confirm subnet scope, routing, guest addressing, OS image, and GitHub destination.
2. Create the isolated new VM and deploy Greenbone; verify feed readiness and engine health.
3. Validate discovery and an assessment against a small approved target set.
4. Build inventory, job status, finding history, schedules, and report exports around real results.
5. Validate coverage separately for LAN, IoT, and HomeLab, then enable recurring schedules.

## References

- Greenbone architecture: https://greenbone.github.io/docs/latest/architecture.html
- Official container deployment: https://greenbone.github.io/docs/latest/22.4/container/
