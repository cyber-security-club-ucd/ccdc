#!/bin/bash

mkdir -p ~/sop

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
        echo not root
		return 1
    else
        echo root
	fi
}

getMachineInfo() {
    OS=$(uname -a)
    IP=$(ip addr show)

    # If machine doesn't have ip addr tool installed
    if [[ -z "$IP" ]]; then 
        IP=$(ifconfig)
    fi

    HOSTNAME=$(hostname)
    DISTRO=$(cat /etc/lsb-release)

    echo -e "operating system = $OS \n"
    echo -e "Hostname = $HOSTNAME \n"
    echo -e "Distro = $DISTRO \n"
    echo -e "IP address = $IP \n"

    echo -e "operating system = $OS \n" >> ~/sop/machineInfo.txt
    echo -e "Hostname = $HOSTNAME \n" >> ~/sop/machineInfo.txt
    echo -e "Distro = $DISTRO \n" >> ~/sop/machineInfo.txt
    echo -e "IP address = $IP \n" >> ~/sop/machineInfo.txt

}



getRunningServices() {
    mkdir -p ~/sop/running

    sudo systemctl --type=service --state=running >> ~/sop/running/runningServices.txt
    sudo systemctl list-unit-files --state=enabled >> ~/sop/running/enabledServices.txt

    sudo ss -plnt >> ~/sop/running/openPorts.txt
    sudo ss -plnu >> ~/sop/running/openPorts.txt

    sudo nmap -p- localhost >> ~/sop/running/localNmapScan.txt
}

sshConfigSetUp() {
    if [[ ! -d /etc/ssh ]]; then
        echo "no ssh directory found at /etc/ssh"
        return 1
    fi

    # Make ssh_config.d if it doesn't exist already
    if [[ ! -d /etc/ssh/ssh_config.d ]]; then
        mkdir -p /etc/ssh/ssh_config.d
    fi

    echo "PermitRootLogin prohibit-password" >> /etc/ssh/sshd_config.d/00-custom.conf
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config.d/00-custom.conf

    sudo systemctl reload ssh
}

# Got through part of logging but I think this is gonna be complex
auditdSetUp() {
    source /etc/os-release

    if [[ $ID == "debian" || $ID == "ubuntu" ]]; then
        sudo apt install -y auditd && sudo systemctl enable --now auditd
    elif [[ $ID == "fedora" || $ID_LIKE == "fedora" $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
        # I think all of these use dnf for installs but not sure
         sudo dnf install audit
         sudo service auditd start
         sudo systemctl enable auditd
    elif [[ $ID == "alpine" ]]; then
        sudo apk add audit && rc-update add auditd && rc-service auditd start
    fi

    # Check this reg ex, it should find max_log_file line irregardless of spaces around equal sight (\s*) and current value ([0-9]\+)
    sudo sed -i "s/^max_log_file\s*=\s*[0-9]\+/max_log_file=100/"

    mkdir -p ~/sop/auditdRules

    wget https://raw.githubusercontent.com/Neo23x0/auditd/refs/heads/master/audit.rules >> ~/sop/auditdRules/audit.rules
}