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
    os=$(uname -a)
    curr_ip=$(ip addr show)

    # If machine doesn't have ip addr tool installed
    if [[ -z "$IP" ]]; then 
        IP=$(ifconfig)
    fi

    host=$(hostname)
    distro=$(cat /etc/os-release)

    if [[ -z "$distro" ]]; then
        distro=$(cat /etc/lsb-release)
    fi

    ram=$(free -h)
    disk=$(df -h)

    echo -e "operating system = $os \n"
    echo -e "Hostname = $host \n"
    echo -e "Distro = $distro \n"
    echo -e "IP address = $curr_ip \n"

    echo -e "Ram on computer = $ram \n"
    echo -e "Disk on computer = $disk \n"

    echo -e "operating system = $os \n" >> ~/sop/machineInfo.txt
    echo -e "Hostname = $host \n" >> ~/sop/machineInfo.txt
    echo -e "Distro = $distro \n" >> ~/sop/machineInfo.txt
    echo -e "Ram on computer = $ram \n" >> ~/sop/machineInfo.txt
    echo -e "Disk on computer = $disk \n" >> ~/sop/machineInfo.txt

    echo -e "IP address = $curr_ip \n" >> ~/sop/ipAddress.txt
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
    mkdir -p ~/sop/auditdRules
    cd ~/sop/auditdRules

    installAuditd
    configureAuditdRules

    # start auditd after installing and configuring
    if [[ $ID == "alpine" ]]; then
        sudo rc-service auditd start
    else
        sudo systemctl start auditd
    fi

    laurelSetUp
}   

installAuditd() {
    # Install tools and audits using distro specific package manager
    if [[ $ID == "debian" || $ID == "ubuntu" ]]; then
        sudo apt install git clang libacl1-dev
        sudo apt install -y auditd 
        sudo systemctl enable auditd
    elif [[ $ID == "fedora" || $ID_LIKE == "fedora" || $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
        sudo dnf install git clang libacl-devel
        sudo dnf install audit
        sudo systemctl enable auditd
    elif [[ $ID == "alpine" ]]; then
        sudo apk add git clang acl-dev
        sudo apk add audit && rc-update add auditd
    fi
}

configureAuditdRules() {
    wget https://raw.githubusercontent.com/Neo23x0/auditd/refs/heads/master/audit.rules -O audit.rules

    # Check this reg ex, it should find max_log_file line irregardless of spaces around equal sight (\s*) and current value ([0-9]\+)
    sudo sed -i "s/^max_log_file\s*=\s*[0-9]\+/max_log_file=100/" audit.rules
    # Comment of this line by putting # in front
    sudo sed -i "s/^-a always,exclude -F msgtype=CWD/# -a always,exclude -F msgtype=CWD" audit.rules
    echo "-a exit,always -S execve -k task" >> audit.rules

    # Copy configured Neo rules to master audit.rules file
    sudo cp ./audit.rules /etc/audit/rules.d/audit.rules

    sudo augenrules
}

laurelSetUp() {
    # Setting up Laurel for auditd
    git clone https://github.com/threathunters-io/laurel.git
    cd laurel
    
    sudo curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source ~/.bashrc
    cargo build --release
    sudo install -m755 target/release/laurel /usr/local/sbin/laurel

    sudo useradd --system --home-dir /var/log/laurel --create-home _laurel

    wget https://raw.githubusercontent.com/threathunters-io/laurel/refs/heads/master/etc/laurel/config.toml -O laurelConfig
    wget https://raw.githubusercontent.com/threathunters-io/laurel/refs/heads/master/etc/audit/plugins.d/laurel.conf -O laurelPlugin

    sudo cp ./laurelConfig /etc/laurel/config.toml

    if [[ -d /etc/audit/plugins.d/laurel.conf ]]; then
        sudo cp ./laurelPlugin /etc/audit/plugins.d/laurel.conf
    else
        sudo cp ./laurelPlugin /etc/audisp/plugins.d/laurel.conf
    fi
}

main() {
    if [[ isRoot -ne 0 ]]; then
        echo "must be root to run this scripts"
        return 1
    fi

    getMachineInfo
    getRunningServices
    sshConfigSetUp
    auditdSetUp
}

main