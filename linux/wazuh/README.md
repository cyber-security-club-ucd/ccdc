# Wazuh Cross-Platform Security Lite Pack

This folder contains ready-to-push Wazuh artifacts for low-overhead detection on:
- Debian Linux agents
- RHEL Linux agents
- Windows agents
- Wazuh manager rules

## Files in this pack

- `agents/debian/agent.conf`
- `agents/rhel/agent.conf`
- `agents/alpine/agent.conf`
- `agents/void/agent.conf`
- `agents/windows/agent.conf`
- `manager/ossec.conf`
- `manager/decoders/local_decoder_security_lite.xml`
- `manager/rules/local_rules_security_lite.xml`
- `scripts/apply_security_lite.sh`
- `scripts/revert_security_lite.sh`
- `scripts/harden_manager_457.sh`
- `scripts/reverse_harden_manager_457.sh`

## Manager-side install

1. Decoder file is optional in this profile. If you keep it, merge `manager/decoders/local_decoder_security_lite.xml` into:
   - `/var/ossec/etc/decoders/local_decoder.xml`
2. Append rule entries from `manager/rules/local_rules_security_lite.xml` into:
   - `/var/ossec/etc/rules/local_rules.xml`
3. Restart manager:

```bash
sudo systemctl restart wazuh-manager
```

## Debian manager scripts

On a Debian Wazuh manager, you can apply or fully revert this pack with:

```bash
sudo bash linux/wazuh/scripts/apply_security_lite.sh
sudo bash linux/wazuh/scripts/revert_security_lite.sh
```

The apply script:

- copies `manager/ossec.conf` directly to `/var/ossec/etc/ossec.conf` on the manager
- copies the security-lite decoder and rules into `/var/ossec/etc/decoders` and `/var/ossec/etc/rules`
- copies each agent profile into `/var/ossec/etc/shared/<group>/agent.conf`
- backs up any existing target files before changing them
- restarts `wazuh-manager`

The revert script restores the exact backed-up files and removes files that did not exist before the apply step.

## Centralized group config install

Create groups (example):

```bash
sudo /var/ossec/bin/agent_groups -a -g debian
sudo /var/ossec/bin/agent_groups -a -g rhel
sudo /var/ossec/bin/agent_groups -a -g windows
```

Copy configs on manager:

- Debian agents:
  - copy `agents/debian/agent.conf` to `/var/ossec/etc/shared/debian/agent.conf`
- RHEL agents:
  - copy `agents/rhel/agent.conf` to `/var/ossec/etc/shared/rhel/agent.conf`
- Windows agents:
  - copy `agents/windows/agent.conf` to `/var/ossec/etc/shared/windows/agent.conf`

Manager host note:

- The manager host does not use a shared `manager/agent.conf` in this pack.
- `apply_security_lite.sh` copies `manager/ossec.conf` directly to `/var/ossec/etc/ossec.conf`.

Assign agents to groups:

```bash
# Examples (replace IDs)
sudo /var/ossec/bin/agent_groups -a -i 001 -g debian
sudo /var/ossec/bin/agent_groups -a -i 002 -g rhel
sudo /var/ossec/bin/agent_groups -a -i 003 -g windows
```

## Manager hardening script (items 4/5/7)

Run on Debian manager:

```bash
sudo bash linux/wazuh/scripts/harden_manager_457.sh
sudo bash linux/wazuh/scripts/reverse_harden_manager_457.sh
```

This script applies:

- item 4: lock down write/read permissions for Wazuh config and binary paths
- item 5: tighten secret/key file permissions under Wazuh and Filebeat paths
- item 7: lock down Filebeat config ownership/permissions

`reverse_harden_manager_457.sh` restores owner/mode values from the snapshot created by `harden_manager_457.sh`.

## Agent restart

After placing agent configs, restart agents:

Linux:

```bash
sudo systemctl restart wazuh-agent
```

Windows (Administrator PowerShell):

```powershell
Restart-Service -Name WazuhSvc
```

## Rule IDs used

- Security detections: `100300-100310`

## Covered detections

- Multiple failed logins
- su/session to root
- New account creation
- User added to sudo/wheel/admin groups
- SSH key changes
- Cron/scheduled task changes
- Netcat usage (audit/4688-based)
- Nginx/Apache/IIS config changes
- MySQL config changes
- DNS config changes
- Firewall rule/policy changes

## Notes

- This profile intentionally avoids remote command monitoring.
- FIM scope is restricted to critical directories only to protect SIEM RAM/storage.
- Optional log locations that do not exist on a host can be removed from that host profile.
