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
        sudo apt-get install -y git clang libacl1-dev vim nmap curl wget zip
    elif [[ $ID == "fedora" || $ID_LIKE == "fedora" || $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
        if command -v dnf &>/dev/null; then
            sudo dnf update -y
            sudo dnf install -y git clang libacl-devel vim nmap curl wget zip
        elif command -v yum &>/dev/null; then
            sudo yum update -y # This is taking kind of a while
            sudo yum install -y git clang libacl-devel vim nmap curl wget zip
        fi
    elif [[ $ID == "alpine" ]]; then
        sudo apk update
        sudo apk add git clang acl-dev vim nmap curl wget zip
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

    # echo -e "operating system = $os \n"
    # echo -e "Hostname = $host \n"
    # echo -e "Distro = $distro \n"
    # echo -e "IP address = $curr_ip \n"

    # echo -e "Ram on computer = $ram \n"
    # echo -e "Disk on computer = $disk \n"

    echo -e "operating system = $os \n" | tee -a $HOME/sop/machineInfo.txt
    echo -e "Hostname = $host \n" | tee -a $HOME/sop/machineInfo.txt
    echo -e "Distro = $distro \n" | tee -a $HOME/sop/machineInfo.txt
    echo -e "Ram on computer:\n $ram \n" | tee -a $HOME/sop/machineInfo.txt
    echo -e "Disk on computer:\n $disk \n" | tee -a $HOME/sop/machineInfo.txt

    echo -e "IP address = $curr_ip \n" | tee -a $HOME/sop/ipAddress.txt
}

getRunningServices() {
    if [[ -d $HOME/sop/running ]]; then
        rm -rf $HOME/sop/running
    fi

    mkdir -p $HOME/sop/running

    sudo systemctl --type=service --state=running | tee -a $HOME/sop/running/runningServices.txt
    sudo systemctl list-unit-files --state=enabled | tee -a $HOME/sop/running/enabledServices.txt

    sudo ss -plnt | tee -a $HOME/sop/running/openPorts.txt
    sudo ss -plnu | tee -a $HOME/sop/running/openPorts.txt

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

    echo "PermitRootLogin prohibit-password" | sudo tee -a /etc/ssh/sshd_config.d/00-custom.conf
    echo "PermitEmptyPasswords no" | sudo tee -a /etc/ssh/sshd_config.d/00-custom.conf

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

    # Just delete the prev max_log_line and exho in a new one rather than trying to replace it
    sudo sed -i '/^max_log_file\s*=/d' /etc/audit/auditd.conf
    echo 'max_log_file = 100' | sudo tee -a /etc/audit/auditd.conf  

    # # If it has a max_log_file line use sed to change it
    # if grep -q '^max_log_file' /etc/audit/auditd.conf; then
    #     # Check this reg ex, it should find max_log_file line irregardless of spaces around equal sight (\s*) and current value ([0-9]\+)
    #     sudo sed -E -i 's/^max_log_file\s*=\s*[0-9]+/max_log_file = 100/' /etc/audit/auditd.conf
    # else
    #     # If it doesn't have this line just echo it in
    #     echo 'max_log_file = 100' | sudo tee -a /etc/audit/auditd.conf
    # fi


    # Comment out this line by putting # in front
    sed -i 's|^-a always,exclude -F msgtype=CWD|#&|' audit.rules
    echo "-a exit,always -S execve -k task" | tee -a audit.rules

    # Copy configured Neo rules to master audit.rules file
    sudo cp ./audit.rules /etc/audit/rules.d/audit.rules

    sudo augenrules
}

laurelSetUp() {
    # Setting up Laurel for auditd

    # Rust already installed if .rustup exists
    if [[ ! -d /root/.rustup ]]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sudo sh
        source ~/.bashrc
    fi

    if git clone https://github.com/threathunters-io/laurel.git $HOME/sop/auditdRules/laurel; then
        echo "Successfully cloned in laurel"
    else
        echo "git clone of laurel failed"
    fi

    cd $HOME/sop/auditdRules/laurel

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

setUpAnsibleUser() {
    if id "ansible" &>/dev/null; then
        echo "User 'ansible' already exists. Exiting."
        return 1
    fi

    read -s -p "give ansible user password: " password
    echo ""
    read -s -p "confirm ansible user password " confirmed
    echo ""
    count=0
    while [[ $password != $confirmed ]]; do
        echo -e "passwords did not match try again\n"
        ((count++))
        if [[ $count -gt 2 ]]; then
            echo "Too many failed ansible passwords, just do it on your own"
            return -1
        fi
        read -s -p "give ansible user password: " password
        echo ""
        read -s -p "confirm ansible user password " confirmed
        echo ""
    done

    sudo useradd -m ansible
    echo "ansible:$password" | sudo chpasswd
    echo "ansbile user created"

    source /etc/os-release

    # Install tools and audits using distro specific package manager
    if [[ $ID == "debian" || $ID == "ubuntu" ]]; then
        sudo usermod -aG sudo ansible
    else
        sudo usermod -aG wheel ansible
    fi
    echo "ansible user added to sudo/wheel group"
}

essentialFoldersBackup() {
    mkdir -p $HOME/sop/backups

    backup_targets="/etc /var /home"
    zip -r $HOME/sop/backups/backup-initial.zip /etc /var /home
}


dbBackup() {
    mkdir -p $HOME/sop/backups
    # Assumes you are running either postgres or mysql on a machine, but not both
    echo -e "Enter default password to login to mysql / postgres DB if it hasn't been changed yet"
    echo -e "For postgres databases you will be reprompted for a password for each database you are dumping making copy paste the best method for this"
    echo ""
    # Try to make mysql backup
    mysqldump -u root -p -A -R -E --triggers --single-transaction > $HOME/sop/backups/mysql_backup.sql

    #Try to make postgres backup
    
    # note if this is getting too much create the file .pgpass in home (~/) directory with the following line:
    # "localhost:5432:*:postgres:<password>"
    # This will make it so psql doesn't prompt for password each time

    pg_dumpall -U postgres -W -f $HOME/sop/backups/postgres_backup.sql

    # Restore with:
    # mysql -u username -p < mysql_backup.sql
    # OR
    # psql -U postgres -f postgres_backup.sql
}

backup() {
    essentialFoldersBackup
    dbBackup
}

main() {
    mkdir -p $HOME/sop

    installTools
    sshConfigSetUp
    getMachineInfo
    getRunningServices
    setUpAnsibleUser

    cd $HOME/sop

    backup # New function might break things

    # Longest running function (laurel especially takes a while and it doesn't seem to be working quite right for some reason still)
    auditdSetUp
}

main
