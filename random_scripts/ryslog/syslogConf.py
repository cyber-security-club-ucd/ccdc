import os

RSYSLOG_CONF = "/etc/rsyslog.conf"

RULES = """
# Filter logs for severity 0-3 (Emergency, Alert, Critical, Error)
if $syslogseverity <= 3 then /var/log/high_severity.log
& stop

# Log all user connections (from SSH, login, etc.)
if $programname == 'sshd' or $programname == 'login' then /var/log/user_connections.log
& stop

# Log all failed authentication attempts (e.g., SSH invalid logins)
if $programname == 'sshd' and ($msg contains 'Failed password' or $msg contains 'Invalid user') then /var/log/auth_failures.log
& stop

# Log all successful root logins via SSH
if $programname == 'sshd' and $msg contains 'Accepted' and $msg contains 'root' then /var/log/root_logins.log
& stop

# Log all commands executed using sudo
if $programname == 'sudo' then /var/log/sudo_commands.log
& stop

# Log unauthorized file access attempts detected by SELinux/auditd
if $programname == 'audit' and $msg contains 'AVC' then /var/log/unauthorized_access.log
& stop
"""

def append_rules():
    """Appends predefined rsyslog rules to the configuration file."""
    with open(RSYSLOG_CONF, "a") as file:
        file.write("\n" + RULES + "\n")
    
    print("Rules added to rsyslog.conf.")
    restart_rsyslog()

def restart_rsyslog():
    """Restarts rsyslog to apply changes."""
    os.system("systemctl restart rsyslog")
    print("rsyslog restarted successfully.")

if __name__ == "__main__":
    append_rules()
