#!/bin/bash

function configure_cli(){
  if [ "$cli" -eq 0 ]; then
    spin
    log "configuring cli"
    # install zsh
    install lsd
    install lolcat
    install figlet
    install git
    install neovim
    install trash-cli
    install pipx
    install tmux
    log "installing uv via pipx"
    pipx install uv
    log "ensuring pipx path"
    pipx ensurepath

    if [ "$package_manager" == "dnf" ]; then
      install bat
      dnf copr enable atim/starship --assumeyes
      install starship
    fi
    if [ "$package_manager" == "homebrew" ]; then
      install bat
      brew install starship
    fi
    if [ "$package_manager" == "apt" ]; then
	# yes | sh <(curl -sSL https://starship.rs/install.sh)
	curl -sSL https://starship.rs/install.sh > /tmp/install.sh
	chmod +x /tmp/install.sh
	# yes | /tmp/install.sh
	/tmp/install.sh -y
	/usr/bin/rm /tmp/install.sh

    fi
    stop-spin
  fi
}
    usermod -s /bin/zsh "$USER"

function detect_platform(){
  case $(uname) in
    Linux)
      os=linux
      distro_id=$(cat /etc/os-release | grep "^ID=" | cut -d'=' -f2)
      case $distro_id in
        fedora)
          distro=fedora
          package_manager=dnf
          ;;
        debian)
          distro=debian
          package_manager=apt
          ;;
        raspbian)
          distro=raspbian
          package_manager=apt
          ;;
        ubuntu)
          distro=ubuntu
          package_manager=apt
          ;;
        *)
          pprint --failure unrecognized linux distro: "$distro_id"
          exit 1
      ;; esac
      ;;
    Darwin)
      os=macos
      distro=macos
      package_manager=homebrew
      ;;
    *)
      pprint --failure unrecognized OSTYPE: "$OSTYPE"
      exit 1
  ;; esac
}

function set_package_manager_commands(){
  log "detecting package manager"
  case $package_manager in
    dnf)
      function install(){
        pprint --log "installing $@"
        dnf install --assumeyes "$@"
      }
      function upgrade(){
        pprint --log "upgrading system"
        dnf upgrade --assumeyes
      }
      ;;
  apt)
    function install(){
      log "installing $@"
      apt install --yes "$@" || pprint --failure "cannot install $@"
    }
    function upgrade(){
      log "upgrading system"
      apt -qq update && apt -qq upgrade --yes
    }
    ;;
  homebrew)
    function install(){
      log "installing $@"
      sudo -u logan bash -c "brew install '$@'" || pprint --failure "cannot install $@"
    }
    function upgrade(){
      log "upgrading system"
      sudo -u logan bash -c "brew update" && sudo -u logan bash -c "brew upgrade"
      # brew update && brew upgrade && softwareupdate --install --all
    }
    ;;

  *)
    pprint --failure "system package manager not supported"
    exit 1
  ;; esac
}
