#!/bin/bash

echo "Try running this as root i guess"

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