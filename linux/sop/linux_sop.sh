#!/bin/bash
isRoot() {
	if [ "$EUID" -ne 0 ]; then
        echo "not root"
		return 1
    else
        echo "root"
	fi
}

installTools() {
    source /etc/os-release

    # Install tools and audits using distro specific package manager
    if [[ $ID == "debian" || $ID == "ubuntu" ]]; then
        sudo apt-get update
        sudo apt-get install -y git clang libacl1-dev vim nmap iproute2 curl
    elif [[ $ID == "fedora" || $ID_LIKE == "fedora" || $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
        if command -v dnf &>/dev/null; then
            sudo dnf update -y
            sudo dnf install -y git clang libacl-devel vim nmap iproute2 curl
        elif command -v yum &>/dev/null; then
            sudo yum update -y
            sudo yum install -y git clang libacl-devel vim nmap iproute2 curl
        fi
    elif [[ $ID == "alpine" ]]; then
        sudo apk update
        sudo apk add git clang acl-dev vim nmap iproute2 curl
    fi

    return 0
}

getMachineInfo() {
    os=$(uname -a)
    curr_ip=$(ip addr show)

    # If machine doesn't have ip addr tool installed
    if [[ -z "$curr_ip" ]]; then 
        curr_ip=$(ifconfig)
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

    echo -e "operating system = $os \n" >> $HOME/sop/machineInfo.txt
    echo -e "Hostname = $host \n" >> $HOME/sop/machineInfo.txt
    echo -e "Distro = $distro \n" >> $HOME/sop/machineInfo.txt
    echo -e "Ram on computer = $ram \n" >> $HOME/sop/machineInfo.txt
    echo -e "Disk on computer = $disk \n" >> $HOME/sop/machineInfo.txt

    echo -e "IP address = $curr_ip \n" >> $HOME/sop/ipAddress.txt
}

getRunningServices() {
    mkdir -p $HOME/sop/running

    sudo systemctl --type=service --state=running >> $HOME/sop/running/runningServices.txt
    sudo systemctl list-unit-files --state=enabled >> $HOME/sop/running/enabledServices.txt

    sudo ss -plnt >> $HOME/sop/running/openPorts.txt
    sudo ss -plnu >> $HOME/sop/running/openPorts.txt

    sudo nmap -p- localhost -oN $HOME/sop/running/localNmapScan.txt
}

sshConfigSetUp() {
    if [[ ! -d /etc/ssh ]]; then
        echo "no ssh directory found at /etc/ssh"
        return 1
    fi

    # Make ssh_config.d if it doesn't exist already
    if [[ ! -d /etc/ssh/ssh_config.d ]]; then
        sudo mkdir -p /etc/ssh/ssh_config.d
    fi

    sudo echo "PermitRootLogin prohibit-password" >> /etc/ssh/sshd_config.d/00-custom.conf
    sudo echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config.d/00-custom.conf

    sudo systemctl reload ssh
}

# Got through part of logging but I think this is gonna be complex
auditdSetUp() {
    source /etc/os-release

    mkdir -p $HOME/sop/auditdRules
    cd $HOME/sop/auditdRules

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
        sudo apt install -y auditd 
        sudo systemctl enable auditd
    elif [[ $ID == "fedora" || $ID_LIKE == "fedora" || $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
        sudo dnf install audit
        sudo systemctl enable auditd
    elif [[ $ID == "alpine" ]]; then
        sudo apk add audit && sudo rc-update add auditd
    fi
}

configureAuditdRules() {
    wget https://raw.githubusercontent.com/Neo23x0/auditd/refs/heads/master/audit.rules -O audit.rules

    # Check this reg ex, it should find max_log_file line irregardless of spaces around equal sight (\s*) and current value ([0-9]\+)
    sudo sed -E -i "s/^max_log_file\s*=\s*[0-9]\+/max_log_file=100/" /etc/audit/auditd.conf
    # Comment of this line by putting # in front
    sudo sed -i "s/^-a always,exclude -F msgtype=CWD/# -a always,exclude -F msgtype=CWD" audit.rules
    echo "-a exit,always -S execve -k task" >> audit.rules

    # Copy configured Neo rules to master audit.rules file
    sudo cp ./audit.rules /etc/audit/rules.d/audit.rules

    sudo augenrules
}

laurelSetUp() {
    # Setting up Laurel for auditd

    # Rust already installed if .rustup exists
    if [[ ! -d /root/.rustup ]]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sudo sh
        source $HOME/.bashrc
    fi

    if git clone https://github.com/threathunters-io/laurel.git $HOME/sop/auditdRules/laurel; then
        echo "Successfully cloned in laurel"
    else
        echo "git clone of laurel failed"
    fi

    cd $HOME/sop/auditdRules/laurel

    echo "curr working dir = $(pwd)"

    . "$HOME/.cargo/env"

    cargo build --release
    sudo install -m755 ./target/release/laurel /usr/local/sbin/laurel

    sudo useradd --system --home-dir /var/log/laurel --create-home _laurel

    wget https://raw.githubusercontent.com/threathunters-io/laurel/refs/heads/master/etc/laurel/config.toml -O laurelConfig
    wget https://raw.githubusercontent.com/threathunters-io/laurel/refs/heads/master/etc/audit/plugins.d/laurel.conf -O laurelPlugin

    sudo cp ./laurelConfig ./etc/laurel/config.toml

    if [[ -d ./etc/audit/plugins.d ]]; then
        sudo cp ./laurelPlugin ./etc/audit/plugins.d/laurel.conf
    else
        sudo cp ./laurelPlugin ./etc/audisp/plugins.d/laurel.conf
    fi

    sudo pkill -HUP auditd
}

main() {
    installTools

    mkdir -p $HOME/sop
    cd $HOME/sop

    sshConfigSetUp
    auditdSetUp

    getMachineInfo
    getRunningServices
}

main
