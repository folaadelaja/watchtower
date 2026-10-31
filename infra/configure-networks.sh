#!/bin/bash
set -euo pipefail
# Run inside the new scanner guest before attaching its IoT and HomeLab NICs.
cat > /etc/sentinel-firewall.nft <<'NFT'
add table inet sentinel
flush table inet sentinel
table inet sentinel {
  chain forward_guard {
    type filter hook forward priority -10; policy accept;
    iifname { "eth0", "scan-iot", "scan-lab" } oifname { "eth0", "scan-iot", "scan-lab" } counter drop
  }
  chain input_guard {
    type filter hook input priority -10; policy accept;
    ct state established,related accept
    iifname { "scan-iot", "scan-lab" } udp sport 67 udp dport 68 accept
    iifname { "scan-iot", "scan-lab" } counter drop
  }
}
NFT
nft --check --file /etc/sentinel-firewall.nft
cat > /etc/systemd/system/sentinel-firewall.service <<'UNIT'
[Unit]
Description=Preserve scanner network segment isolation
Before=docker.service network-pre.target
Wants=network-pre.target
DefaultDependencies=no
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/nft --file /etc/sentinel-firewall.nft
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now sentinel-firewall
# Explicit locally administered MACs belong only to this newly created VM.
cat > /etc/netplan/60-scanner-segments.yaml <<'NETPLAN'
network:
  version: 2
  ethernets:
    scan-iot:
      match:
        macaddress: '02:00:00:00:20:01'
      set-name: scan-iot
      dhcp4: true
      dhcp6: false
      accept-ra: false
      optional: true
      dhcp4-overrides:
        use-routes: false
        use-dns: false
    scan-lab:
      match:
        macaddress: '02:00:00:00:30:01'
      set-name: scan-lab
      dhcp4: true
      dhcp6: false
      accept-ra: false
      optional: true
      dhcp4-overrides:
        use-routes: false
        use-dns: false
NETPLAN
chmod 600 /etc/netplan/60-scanner-segments.yaml
netplan generate
netplan apply
