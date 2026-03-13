#!/bin/bash
# Removes dangerous/unnecessary packages. Template credit to CPP.

if [ "$EUID" -ne 0 ]; then echo "Please run as root"; exit 1; fi

RHEL(){
    if command -v dnf >/dev/null ; then
        dnf makecache -q || true
        for pkg in netcat nc gcc cmake make telnet; do
            dnf remove -y "$pkg" >/dev/null 2>&1 || true
        done
    else
        yum makecache -q >/dev/null 2>&1 || true
        for pkg in netcat nc gcc cmake make telnet; do
            yum remove -y -q "$pkg" >/dev/null 2>&1 || true
        done
    fi
    
}

DEBIAN(){
    apt-get update -qq || true
    for pkg in netcat netcat-openbsd nc gcc cmake make telnet; do
        apt-get -y purge "$pkg" >/dev/null 2>&1 || true
    done
}

UBUNTU(){
    DEBIAN
}

ALPINE(){
    apk remove gcc make
}

SLACK(){
    echo "its fucked"
}

if command -v dnf >/dev/null || command -v yum >/dev/null ; then
    RHEL
elif command -v apt-get >/dev/null ; then
    if grep -qi Ubuntu /etc/os-release; then
        UBUNTU
    else
        DEBIAN
    fi
elif command -v apk >/dev/null ; then
    ALPINE
elif command -v slapt-get >/dev/null || (cat /etc/os-release | grep -i slackware) ; then
    SLACK
fi