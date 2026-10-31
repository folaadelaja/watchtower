# New scanner VM

Ubuntu 24.04 cloud image, 8 vCPUs, 24 GiB RAM, 200 GiB disk.
Initial management NIC uses DHCP on vmbr0. SSH requires your own public SSH
key in the cloud-init template; passwords are disabled. The engine web ports initially bind only to
guest loopback using the upstream compose defaults. Public/LAN UI access is not
enabled until authentication has been configured.

The cloud-init bootstrap installs Docker and starts the Greenbone Community engine.
Check `cloud-init status --long` and `journalctl -u scanner-engine-bootstrap` in
the guest. Feed loading can continue after container startup.

This community-container deployment is a homelab foundation. The upstream guide
does not present it as a production deployment. Validate updates, backups, engine
health, and assessment coverage before relying on its reports.

The example IoT network is 192.168.20.0/24.
LAN is 192.168.10.0/24 and HomeLab is 192.168.30.0/24. Additional segment access must
preserve isolation; no scans are automatically launched by this bootstrap.
