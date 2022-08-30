#!/bin/bash

# This is a post install script for an Ubuntu 18.04 or later workstation, vm, or server.
# The goal is to provide a minimal and hardened baseline environment with auditing capability

# Thanks to the following projects for code, ideas, and guidance:
# https://github.com/Disassembler0/Win10-Initial-Setup-Script
# https://github.com/g0tmi1k/OS-Scripts
# https://github.com/angristan/wireguard-install
# https://github.com/drduh/YubiKey-Guide
# https://github.com/drduh/config
# https://static.open-scap.org/ssg-guides/ssg-ubuntu2004-guide-stig.html
# https://github.com/ComplianceAsCode/content

RED="\033[01;31m"      # Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings
BLUE="\033[01;34m"     # Success
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

#PUB_IPV4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
#PUB_IPV6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
GTWY="$(ip route | grep 'default' | cut -d ' ' -f3)"

VM='false'
HW='false'
VPS='false'



function isRoot() {
	if [ "${EUID}" -eq 0 ]; then
		echo "You need to run this script as a normal user"
		exit 1
	fi
}

isRoot

function checkCwd() {
	if  ! [ -e "$(pwd)"/setup-ubuntu.sh ]; then
		echo "To avoid issues, execute this script from it's current working directory."
		echo "If you renamed this script, change this function or rename it 'setup-ubuntu.sh'"
		echo "Quitting."
		exit 1
	fi
}
checkCwd

function checkHostname() {
	if ! (grep -q "$(cat /etc/hostname)" /etc/hosts); then
		echo -e "${RED}"'[!]'"hostname not found in /etc/hosts file.${RESET}"
		exit 1
	fi
}
checkHostname

function checkOS() {

	# Check desktop type
	DESKTOP="$(echo "$XDG_CURRENT_DESKTOP" | cut -d ':' -f2)"
	echo -e "${BLUE}[i]$DESKTOP desktop environment detected${RESET}"

	# Check OS version
	OS="$(grep -E "^ID=" /etc/os-release | cut -d '=' -f 2)"

	if [[ $OS == "ubuntu" ]]; then
		CODENAME="$(grep VERSION_CODENAME /etc/os-release | cut -d '=' -f 2)" # debian or ubuntu
		echo -e "${BLUE}[i]$OS $CODENAME detected.${RESET}"
		MAJOR_UBUNTU_VERSION=$(grep VERSION_ID /etc/os-release | cut -d '"' -f2 | cut -d '.' -f 1)
		if [[ $MAJOR_UBUNTU_VERSION -lt 18 ]]; then
			echo "⚠️ Your version of Ubuntu is not supported."
			echo ""
			echo "However, if you're using Ubuntu >= 16.04 or beta, then you can continue, at your own risk."
			echo ""
			until [[ $CONTINUE =~ ^(y|n)$ ]]; do
				read -rp "Continue? [y/n]: " -e CONTINUE
			done
			if [[ $CONTINUE == "n" ]]; then
				exit 1
			fi
		fi
	elif [[ $OS == "fedora" ]]; then
		MAJOR_FEDORA_VERSION="$(grep VERSION_ID /etc/os-release | cut -d '=' -f2)"
		echo -e "${BLUE}[i]${RESET}$OS $MAJOR_FEDORA_VERSION detected."
		if [[ $MAJOR_FEDORA_VERSION -lt 34 ]]; then
			echo "⚠️ Your version of Fedora may not be supported."
			echo ""
			until [[ $CONTINUE =~ ^(y|n)$ ]]; do
				read -rp "Continue? [y/n]: " -e CONTINUE
			done
			if [[ $CONTINUE == "n" ]]; then
				exit 1
			fi
		fi
	fi
}
checkOS

function MakeTemp() {

    # Make a temporary working directory
#    if [ -d /tmp/setup/ ]; then
#        rm -rf /tmp/setup
#    fi

    if ! [ -d /tmp/setup ]; then
        mkdir /tmp/setup
    fi

    SETUPDIR=/tmp/setup
    export SETUPDIR

    cd "$SETUPDIR" || (echo "Failed changing into setup directory. Quitting." && exit 1)
    echo -e "${BLUE}[i]Changing working directory to $SETUPDIR${RESET}"

}

function checkKernel() {
	
	echo -e "${BLUE}[i]${RESET}Checking kernel parameters..."

	# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-standard.html

	# /etc/sysctl.d/README.sysctl
	# After making any changes, please run "service procps reload" (or, from
	# a Debian package maintainer script "deb-systemd-invoke restart procps.service").

	# xccdf_org.ssgproject.content_rule_sysctl_fs_protected_hardlinks
	if (sudo sysctl -a | grep -qxE "^fs\.protected_hardlinks = 1$"); then
		echo -e "${BLUE}[OK]${RESET}kernel -> fs.protected_hardlinks = 1"
	else
		sudo sysctl -q -n -w fs.protected_hardlinks="1"
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> fs.protected_hardlinks = 1"
		echo 'fs.protected_hardlinks = 1' | sudo tee /etc/sysctl.d/10-local-ssg.conf
	fi

	# xccdf_org.ssgproject.content_rule_sysctl_fs_protected_symlinks
	if (sudo sysctl -a | grep -qxE "^fs\.protected_symlinks = 1$"); then
		echo -e "${BLUE}[OK]${RESET}kernel -> fs.protected_symlinks = 1"
	else
		sudo sysctl -q -n -w fs.protected_symlinks="1"
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> fs.protected_symlinks = 1"
		echo 'fs.protected_symlinks = 1' | sudo tee -a /etc/sysctl.d/10-local-ssg.conf
	fi

	# xccdf_org.ssgproject.content_rule_sysctl_fs_suid_dumpable
	if (sudo sysctl -a | grep -qxE "^fs\.suid_dumpable = 0$"); then 
		echo -e "${BLUE}[OK]${RESET}kernel -> fs.suid_dumpable = 0"
	else
		sudo sysctl -q -n -w fs.suid_dumpable="0"
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> fs.suid_dumpable = 0"
		echo 'fs.suid_dumpable = 0' | sudo tee -a /etc/sysctl.d/10-local-ssg.conf
	fi

	# xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space
	if (sudo sysctl -a | grep -qxE "^kernel\.randomize_va_space = 2$"); then
		echo -e "${BLUE}[OK]${RESET}kernel -> kernel.randomize_va_space = 2"
	else
		sudo sysctl -q -n -w kernel.randomize_va_space="2"
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> kernel.randomize_va_space = 2"
		echo 'kernel.randomize_va_space = 2' | sudo tee -a /etc/sysctl.d/10-local-ssg.conf
	fi

	# xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_tcp_syncookies
	if (sudo sysctl -a | grep -qxE "^net\.ipv4\.tcp_syncookies = 1$"); then
		echo -e "${BLUE}[OK]${RESET}kernel -> net.ipv4.tcp_syncookies = 1"
	else
		sudo sysctl -w net.ipv4.tcp_syncookies="1"
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> net.ipv4.tcp_syncookies = 1"
		echo 'net.ipv4.tcp_syncookies = 1' | sudo tee -a /etc/sysctl.d/10-local-ssg.conf
	fi

	# magic-sysrq-key
	if (sudo sysctl -a | grep -qxE "^kernel\.sysrq = 0$"); then
		echo -e "${BLUE}[OK]${RESET}kernel -> kernel.sysrq (Ctrl+Alt+Del) = 0"
	else
		sudo sysctl -q -n -w kernel.sysrq="0"
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> kernel.sysrq (Ctrl+Alt+Del) = 0"
		if [ -e /etc/sysctl.d/10-magic-sysrq.conf ]; then
			sudo sed -i 's/^kernel.sysrq = .*$/kernel.sysrq = 0/' /etc/sysctl.d/10-magic-sysrq.conf
		else
			echo 'kernel.sysrq = 0' | sudo tee -a /etc/sysctl.d/10-local-ssg.conf
		fi
	fi

	# https://github.com/nongiach/sudo_inject
	# https://github.com/carlospolop/hacktricks/tree/master/linux-unix/privilege-escalation#reusing-sudo-tokens
	# cat /proc/sys/kernel/yama/ptrace_scope
	if (sudo sysctl -a | grep -qxE "^kernel\.yama\.ptrace_scope = [^0]$"); then
		echo -e "${BLUE}[OK]${RESET}kernel -> kernel.ptrace_scope != 0"
	else
		sudo sysctl -q -n -w kernel.yama.ptrace_scope="1"
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> kernel.yama.ptrace_scope = 1"
		echo 'kernel.yama.ptrace_scope = 1' | sudo tee -a /etc/sysctl.d/10-local-ssg.conf
	fi


	# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-cis.html
	# xccdf_org.ssgproject.content_rule_coredump_disable_backtraces
	# xccdf_org.ssgproject.content_rule_coredump_disable_storage
	if ! [ -e /etc/systemd/coredump.conf ]; then
		sudo touch "/etc/systemd/coredump.conf"
	fi

	if (grep -Eqx "^ProcessSizeMax=0$" /etc/systemd/coredump.conf); then
		echo -e "${BLUE}[OK]${RESET}kernel -> backtraces disabled -> ProcessSizeMax=0"
	else
		echo "ProcessSizeMax=0" | sudo tee -a /etc/systemd/coredump.conf
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> backtraces disabled -> ProcessSizeMax=0"
	fi

	if (grep -Eqx "^Storage=none$" /etc/systemd/coredump.conf); then
		echo -e "${BLUE}[OK]${RESET}kernel -> coredumps disabled -> Storage=none"
	else
		echo "Storage=none" | sudo tee -a /etc/systemd/coredump.conf
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> coredumps disabled -> Storage=none"
	fi


	# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-cis.html
	# xccdf_org.ssgproject.content_rule_kernel_module_rds_disabled
	if (grep -Eqx "^install rds /bin/true$" /etc/modprobe.d/rds.conf); then
		echo -e "${BLUE}[OK]${RESET}kernel -> 'install rds /bin/true' -> /etc/modprobe.d/rds.conf"
	else
		echo 'install rds /bin/true' | sudo tee /etc/modprobe.d/rds.conf
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> 'install rds /bin/true' -> /etc/modprobe.d/rds.conf"
	fi

	# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-cis.html
	# xccdf_org.ssgproject.content_rule_kernel_module_tipc_disabled
	if (grep -Eqx "^install tipc /bin/true$" /etc/modprobe.d/tipc.conf); then 
		echo -e "${BLUE}[OK]${RESET}kernel -> 'install tipc /bin/true' -> /etc/modprobe.d/tipc.conf"
	else
		echo 'install tipc /bin/true' | sudo tee /etc/modprobe.d/tipc.conf
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> 'install tipc /bin/true' -> /etc/modprobe.d/tipc.conf"
	fi


	# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-cis.html
	# xccdf_org.ssgproject.content_rule_grub2_enable_iommu_force
	if (grep -Eqx "^.*iommu=force.*$" /etc/default/grub); then
		echo -e "${BLUE}[OK]${RESET}kernel -> iommu=force -> /etc/grub/default"
	elif grep -q '^GRUB_CMDLINE_LINUX=.*iommu=.*"'  '/etc/default/grub' ; then
		# modify the GRUB command-line if an iommu= arg already exists
		sudo sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)iommu=[^[:space:]]*\(.*"\)/\1 iommu=force \2/'  '/etc/default/grub'
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> iommu=force -> /etc/grub/default"
	elif ! (grep -q '^GRUB_CMDLINE_LINUX=.*iommu=.*"'  '/etc/default/grub'); then
		# no iommu=arg is present, append it
		sudo sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)"/\1 iommu=force"/'  '/etc/default/grub'
		echo -e "${YELLOW}[UPDATED]${RESET}kernel -> iommu=force -> /etc/grub/default"
	fi

	# Add other kernel parameter changes here

	sudo update-grub

}

function setPerms() {

	ADDUSER_CONF=/etc/adduser.conf

	echo "======================================================================"
	if ! (grep -qx 'DIR_MODE=0750' "$ADDUSER_CONF"); then
		sudo sed -i 's/DIR_MODE=0755/DIR_MODE=0750/' "$ADDUSER_CONF"
		chmod 750 "$HOME"
		echo -e "${GREEN}[+]${RESET}User DAC policy updated successfully."
	else
		echo -e "${BLUE}[i]${RESET}User DAC policy already updated. Skipping."
	fi
}

function checkSudoers() {
	# Applies to pre-installed Raspberry Pi images
	# and cloud images where /etc/sudoers.d/90-init-cloud-users has 'NOPASSWD:ALL' set
	
	for file in /etc/sudoers.d/* ; do
		if (sudo grep -q "^$USERNAME ALL=(ALL) NOPASSWD:ALL$" "$file"); then
			echo -e "${BLUE}[i]${RESET}Found 'NOPASSWD:ALL' set for '$USERNAME' in $file."
			if (passwd -S "$USERNAME" | grep -P "$USERNAME (L|NP)" > /dev/null); then
				echo -e "User $USERNAME was also found to be locked or had no password set."
				echo "Set a new password now?"
				echo ""
				until [[ $PASSWD_CHOICE =~ ^(y|n)$ ]]; do
					read -rp "[y/n]: " PASSWD_CHOICE
				done
				if [[ $PASSWD_CHOICE == "y" ]]; then
					sudo passwd "$USERNAME"
				fi
			fi
			echo -e "${BLUE}[i]${RESET}Commenting out 'NOPASSWD:ALL' in $file"
			sudo sed -i 's/^'"$USERNAME"' ALL=(ALL) NOPASSWD:ALL$/#'"$USERNAME"' ALL=(ALL) NOPASSWD:ALL/' "$file"
		fi
	done
}

function removeBrowser() {

	# Replace with either Chromium or Firefox snap packages
	echo "======================================================================"
	if ! (snap list | grep firefox > /dev/null); then
		for package in $(dpkg --list | grep firefox | cut -d ' ' -f 3); do 
			sudo apt autoremove --purge -y "$package"
		done
		sudo rm -rf /usr/lib/firefox* > /dev/null
		sudo rm -rf /usr/lib64/firefox* > /dev/null
	else
		echo -e "${BLUE}[i]${RESET}Default browser already removed. Skipping."
	fi
}


function stopServices() {

	echo "======================================================================"
	# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-standard.html
	# xccdf_org.ssgproject.content_rule_service_apport_disabled
	echo -e "${BLUE}[i]${RESET}Checking apport.service..."
	if (systemctl is-active apport); then
		sudo systemctl stop apport
		sudo systemctl disable apport
		sudo systemctl mask --now apport.service
	elif (systemctl is-enabled apport); then
		sudo systemctl disable apport
		sudo systemctl mask --now apport.service
	fi

	# cups
	echo -e "${BLUE}[i]${RESET}Checking service: cups..."
	if (systemctl is-active cups); then
		sudo systemctl stop cups
	fi
	if (systemctl is-enabled cups); then
		sudo systemctl disable cups
		sudo systemctl mask cups
	fi
	# cups-browsed
	echo -e "${BLUE}[i]${RESET}Checking service: cups-browsed..."
	if (systemctl is-active cups-browsed); then
		sudo systemctl stop cups-browsed
	fi
	if (systemctl is-enabled cups-browsed); then
		sudo systemctl disable cups-browsed
		sudo systemctl mask cups-browsed
	fi
	# avahi
	echo -e "${BLUE}[i]${RESET}Checking service: avahi-daemon..."
	if (systemctl is-active avahi-daemon); then
		sudo systemctl stop avahi-daemon
	fi
	if (systemctl is-enabled avahi-daemon); then
		sudo systemctl disable avahi-daemon
		sudo systemctl mask avahi-daemon
	fi
	# bluetooth
	echo -e "${BLUE}[i]${RESET}Checking service: bluetooth..."
	if (systemctl is-active bluetooth); then
		sudo systemctl stop bluetooth
	fi
	if (systemctl is-enabled bluetooth); then
		sudo systemctl disable bluetooth
		sudo systemctl mask bluetooth
	fi

	echo -e "${BLUE}[i]${RESET}All non-essential services stopped and disabled."
}

function updateServices() {

	# For OS's with systemctl, modify the exec command
	if [ -e '/etc/systemd/system/do-agent.service' ]; then
		if ! (grep -q '\-\-no\-collector.process' '/etc/systemd/system/do-agent.service' ); then
			echo "======================================================================"
			echo -e "${BLUE}[i]${RESET}Checking do-agent.service's exec command options have been updated."
			sudo sed -i 's%ExecStart=/opt/digitalocean/bin/do-agent%ExecStart=/opt/digitalocean/bin/do-agent --no-collector.processes%' /etc/systemd/system/do-agent.service
			# Restart the agent
			sudo systemctl daemon-reload
			sudo systemctl restart do-agent
		fi
	fi
}

function addVBox() {

	VBOX_APT_LIST=/etc/apt/sources.list.d/virtualbox.list

	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Add Oracle's VirtualBox apt repository and key to keyring?"
	echo ""
	until [[ $VBOX_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "[y/n]: " VBOX_CHOICE
	done

	if [[ $VBOX_CHOICE == "y" ]]; then
		if ! [ -e ./oracle_vbox_2016.asc ]; then
			echo -e "${GREEN}[+]${RESET}Retrieving VirtualBox apt-key with Wget.${RESET}"
			# Use wget since curl may not be installed yet
			if ! (wget -O oracle_vbox_2016.asc 'https://www.virtualbox.org/download/oracle_vbox_2016.asc'); then
				echo -e "${RED}"'[!]'"${RESET}Unable to retrieve Oracle VirtualBox signing key.${RESET}"
				rm ./oracle_vbox_2016.asc
			fi
		fi
		if [ -e ./oracle_vbox_2016.asc ]; then
			echo -e "${GREEN}[+]${RESET}Adding VirtualBox apt-key from local file.${RESET}"
			echo -e "${GREEN}[+]${RESET}VirtualBox sources.list created at $VBOX_APT_LIST."
			apt-key add ./oracle_vbox_2016.asc
			echo "deb [arch=amd64] https://download.virtualbox.org/virtualbox/debian $CODENAME contrib" | sudo tee "$VBOX_APT_LIST"
		fi
	elif [[ $VBOX_CHOICE == "n" ]] && [ -e "$VBOX_APT_LIST" ]; then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}Looks like the VirtualBox gpg key is present."
		echo "Remove Oracle's VirtualBox apt repository and key from keyring?"
		echo ""
		until [[ $REMOVE_VBOX =~ ^(y|n)$ ]]; do
			read -rp "[y/n]: " REMOVE_VBOX
		done

		if [[ $REMOVE_VBOX == "y" ]]; then
			sudo rm "$VBOX_APT_LIST"
			sudo apt-key del 'B9F8 D658 297A F3EF C18D  5CDF A2F6 83C5 2980 AECF'
			sudo apt update
			sudo apt autoremove -y
			echo ""
			echo -e "${BLUE}[-]${RESET}VirtualBox removed from sources.list and apt keyring."
			echo ""
		fi
	fi
}

function setIpv6() {

	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Disable IPV6?"
	echo ""
	until [[ $IPV6_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "[y/n]: " IPV6_CHOICE
	done
	if [[ $IPV6_CHOICE == "y" ]]; then
		sudo sed -i 's/^IPV6=yes$/IPV6=no/' /etc/default/ufw && echo -e "${BOLD}[+] ipv6 settings changed.${RESET}"
	elif [[ $IPV6_CHOICE == "n" ]] && (grep -qx 'IPV6=no' /etc/default/ufw) ; then
		sudo sed -i 's/^IPV6=no$/IPV6=yes/' /etc/default/ufw && echo -e "${BOLD}[+] ipv6 settings changed.${RESET}"
		# enable ipv6 privacy addressing
		sudo sed -i 's/^#net\/ipv6\/conf\/default\/use_tempaddr=2$/net\/ipv6\/conf\/default\/use_tempaddr=2/' /etc/ufw/sysctl.conf
		sudo sed -i 's/^#net\/ipv6\/conf\/all\/use_tempaddr=2/net\/ipv6\/conf\/all\/use_tempaddr=2/' /etc/ufw/sysctl.conf
	fi
}

function checkNetworking() {

	# https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Checking networking settings..."
	echo ""
	if (grep -Eqx "^LLMNR=no$" /etc/systemd/resolved.conf); then 
		echo -e "${BLUE}[OK]${RESET}/etc/systemd/resolved.conf -> LLMNR=no"
	else
		sudo sed -i 's/^.*LLMNR=.*$/LLMNR=no/' /etc/systemd/resolved.conf
		echo -e "${YELLOW}[UPDATED]${RESET}/etc/systemd/resolved.conf -> LLMNR=no"
	fi

	if (grep -Eqx "^MulticastDNS=no$" /etc/systemd/resolved.conf); then
		echo -e "${BLUE}[OK]${RESET}/etc/systemd/resolved.conf -> MulticastDNS=no"
	else
		sudo sed -i 's/^.*MulticastDNS=.*$/MulticastDNS=no/' /etc/systemd/resolved.conf
		echo -e "${YELLOW}[UPDATED]${RESET}/etc/systemd/resolved.conf -> MulticastDNS=no"
	fi
}

function setFirewall() {
	
	if [ -e "/etc/ssh/sshd_config" ];then
		SERVER_SSH_PORT="$(grep -E "^Port ([0-9]{1,5})" /etc/ssh/sshd_config | cut -d ' ' -f 2)"
	fi
	
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Modify the firewall rules?"
	echo ""
	echo "This will set a basic deny all inbound, allow all outbound, deny routed policy"
	echo "This function reads ssh connection settings in /etc/ssh/sshd_config"
	echo ""
	until [[ $FW_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "[y/n]: " FW_CHOICE
	done
	if [[ $FW_CHOICE == "y" ]]; then

		if (command -v ufw > /dev/null); then
			echo -e "${BLUE}[i]${RESET}Using ufw..."
			sudo ufw reset
			sudo ufw enable
			sudo ufw default deny incoming
			sudo ufw default allow outgoing
			sudo ufw default deny routed

			if [ -e /etc/ssh/sshd_config ]; then
				if ! [[ "$SERVER_SSH_PORT" == "" ]];then
					sudo ufw allow in port "$SERVER_SSH_PORT" proto tcp comment 'ssh'
				else
					sudo ufw allow ssh
				fi
			fi
		else
			echo -e "${BLUE}[i]${RESET}Using iptables..."
			sudo iptables -F    # Flush all chains
			sudo iptables -X    # Delete all user-defined chains

			sudo ip6tables -F    # Flush all chains
			sudo ip6tables -X    # Delete all user-defined chains

			sudo iptables -P INPUT DROP
			sudo iptables -P FORWARD DROP
			sudo iptables -P OUTPUT ACCEPT

			sudo ip6tables -P INPUT DROP
			sudo ip6tables -P FORWARD DROP
			sudo ip6tables -P OUTPUT ACCEPT

			sudo iptables -A INPUT -i lo -j ACCEPT
			sudo iptables -A INPUT -o lo -j ACCEPT
			sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
			sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
			sudo iptables -A INPUT -p icmp -m icmp --icmp-type 3 -j ACCEPT
			sudo iptables -A INPUT -p icmp -m icmp --icmp-type 11 -j ACCEPT
			sudo iptables -A INPUT -p icmp -m icmp --icmp-type 12 -j ACCEPT
			sudo iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
			sudo iptables -A INPUT -p udp -m udp --sport 67 --dport 68 -j ACCEPT

			sudo ip6tables -A INPUT -i lo -j ACCEPT
			sudo ip6tables -A INPUT -o lo -j ACCEPT

			sudo ip6tables -A INPUT -m rt --rt-type 0 -j DROP
			sudo ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
			sudo ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 129 -j ACCEPT                                  # ALLOW echo reply
			sudo ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP
			sudo ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 1/4 -j ACCEPT                                  # changed to be code 4 only
			sudo ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 2 -j ACCEPT
			sudo ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 3/0 -j ACCEPT                                  # changed to be code 0 only
			sudo ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 4/0 -j ACCEPT                                  # changed to be code 0 & 1 only
			sudo ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 4/1 -j ACCEPT                                  # changed to be code 0 & 1 only
			sudo ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 128 -j ACCEPT   

			sudo ip6tables -A INPUT -s fe80::/10 -d fe80::/10 -p udp -m udp --sport 547 --dport 546 -j ACCEPT

			if [ -e /etc/ssh/sshd_config ]; then
				if ! [[ "$SERVER_SSH_PORT" == "" ]];then
					sudo iptables -A INPUT -p tcp -m tcp --dport "$SERVER_SSH_PORT" -j ACCEPT
					sudo ip6tables -A INPUT -p tcp -m tcp --dport "$SERVER_SSH_PORT" -j ACCEPT
				else
					sudo iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
					sudo ip6tables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
				fi
			fi
		fi
		echo -e "${BLUE}[+]${RESET}Basic firewall rules are live."
	fi
}

function checkPackages() {

	echo "======================================================================"
	# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-standard.html
	# xccdf_org.ssgproject.content_rule_package_inetutils-telnetd_removed
	# xccdf_org.ssgproject.content_rule_package_telnetd-ssl_removed
	# xccdf_org.ssgproject.content_rule_package_telnetd_removed
	# xccdf_org.ssgproject.content_rule_package_nis_removed
	# xccdf_org.ssgproject.content_rule_package_ntpdate_removed
	# https://static.open-scap.org/ssg-guides/ssg-ubuntu2004-guide-stig.html
	# xccdf_org.ssgproject.content_rule_package_rsh-server_removed

	echo -e "${BLUE}[-]${RESET}Removing any deprecated packages and protocols..."
	sudo apt-get autoremove --purge -y inetutils-telnetd telnetd-ssl telnetd nis ntpdate rsh-server

	sleep 2

	echo -e "${BLUE}[i]${RESET}Upgrading apt packages..."
	sleep 3
	sudo apt-get update && \
	sudo apt-get upgrade -y
	sleep 2
	echo -e "${BLUE}[i]${RESET}Autoremoving old packages."
	sudo apt-get clean
	sudo apt-get autoremove --purge -y
	sleep 2


	if (command -v snap > /dev/null); then
		echo -e "${BLUE}[i]${RESET}Checking for snap packages..."
		sudo snap refresh
	fi

	sleep 1

}

function setResolver() {

	if ! (command -v unbound > /dev/null); then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}Install Unbound?"
		echo ""
		until [[ $UNBOUND_CHOICE =~ ^(y|n)$ ]]; do
			read -rp "[y/n]: " UNBOUND_CHOICE
		done
		if [[ $UNBOUND_CHOICE == "y" ]]; then
			sudo apt install -y unbound

			if ! (sudo unbound-checkconf | grep 'no errors'); then
				echo -e "${RED}[i]${RESET}Error with unbound configuration. Quitting."
				echo -e "${RED}[i]${RESET}Address any configuration errors above then re-run this script."
				exit 1
			else
				echo -e "${BLUE}[i]${RESET}Stopping and disabling systemd-resolved service..."
				if (systemctl is-active systemd-resolved); then
					sudo systemctl stop systemd-resolved
				fi
				if (systemctl is-enabled systemd-resolved); then
					sudo systemctl disable systemd-resolved
				fi

				# Apply latest conf and restart
				sudo systemctl restart unbound

				sleep 2

				if ! (grep -Eq "^nameserver[[:space:]]127.0.0.1$" /etc/resolv.conf); then
					echo -e "${YELLOW}[i]${RESET}Pointing /etc/resolv.conf to unbound on 127.0.0.1..."
					sudo sed -i 's/^nameserver[[:space:]]127.0.0.53/nameserver 127.0.0.1/' /etc/resolv.conf || exit 1
				fi
			fi
			echo -e "${BLUE}[i]${RESET}Done."
		fi
	fi
}

function installPdfTools() {

	# pdftools
	# Update these values when newer versions are available
	PDF_TOOLS_DIR="/opt/pdftools"
	PDFID_HASH="bb3898900e31a427bcd67629e7fc7acfe1a2e3fd0400bd1923e8b86eda5cb118"
	PDFID_GIT="cc64a213aa40162f8072b95ab80bdbf67c1afaf5"
	PDFID_DIR="/opt/pdftools/pdfid"
	PDFPARSER_HASH="ca0145cd48e4b9b3e8d10aefe2805ac66b500eac51597044bb432507fc68a0b7"
	PDFPARSER_GIT="1d7ee54ffeb50293f3721f3682685328f5cf5a08"
	PDFPARSER_DIR="/opt/pdftools/pdf-parser"

	if ! [ -e "$PDFID_DIR" -o -e "$PDFPARSER_DIR" ]; then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}Install pdftools?"
		echo ""
		until [[ $PDFTOOLS_CHOICE =~ ^(y|n)$ ]]; do
			read -rp "[y/n]: " PDFTOOLS_CHOICE
		done

		if [[ "$PDFTOOLS_CHOICE" == "y" ]]; then

			echo -e "${BLUE}[i]Downloading pdftools...${RESET}"

			sudo mkdir "$PDF_TOOLS_DIR"

			#======================================================================

			# pdfid
			# Commit cc64a213aa40162f8072b95ab80bdbf67c1afaf5
			curl -LfO https://gitlab.com/kalilinux/packages/pdfid/-/archive/"$PDFID_GIT"/pdfid-"$PDFID_GIT".zip

			if ! (sha256sum "$SETUPDIR/pdfid-$PDFID_GIT.zip" | grep -x "$PDFID_HASH  $SETUPDIR/pdfid-$PDFID_GIT.zip"); then
				echo -e "${RED}[i]Bad checksum. Quitting.${RESET}"
				exit 1
			else
				echo -e "${GREEN}[i]OK${RESET}"
			fi

			unzip "$SETUPDIR"/pdfid-"$PDFID_GIT".zip \
			pdfid-"$PDFID_GIT"/pdfid.ini \
			pdfid-"$PDFID_GIT"/pdfid.py \
			pdfid-"$PDFID_GIT"/plugin_embeddedfile.py \
			pdfid-"$PDFID_GIT"/plugin_list \
			pdfid-"$PDFID_GIT"/plugin_nameobfuscation.py \
			pdfid-"$PDFID_GIT"/plugin_triage.py \
			pdfid-"$PDFID_GIT"/debian/copyright

			sudo mv "$SETUPDIR"/pdfid-"$PDFID_GIT" "$PDFID_DIR"
			sudo chmod 755 "$PDFID_DIR"/pdfid.py
			sudo ln -s "$PDFID_DIR"/pdfid.py /usr/local/bin/pdfid

			rm "$SETUPDIR"/pdfid-"$PDFID_GIT".zip

			# Change pdfid.py to python3
			sudo sed -i 's/#!\/usr\/bin\/env python/#!\/usr\/bin\/env python3/' "$PDFID_DIR"/pdfid.py

			#======================================================================

			# pdf-parser
			# Commit 1d7ee54ffeb50293f3721f3682685328f5cf5a08
			curl -LfO https://gitlab.com/kalilinux/packages/pdf-parser/-/archive/"$PDFPARSER_GIT"/pdf-parser-"$PDFPARSER_GIT".zip

			if ! (sha256sum "$SETUPDIR/pdf-parser-$PDFPARSER_GIT.zip" | grep -x "$PDFPARSER_HASH  $SETUPDIR/pdf-parser-$PDFPARSER_GIT.zip"); then
				echo -e "${RED}[i]Bad checksum. Quitting.${RESET}"
				exit 1
			else
				echo -e "${GREEN}[i]OK${RESET}"
			fi

			unzip "$SETUPDIR"/pdf-parser-"$PDFPARSER_GIT".zip \
			pdf-parser-"$PDFPARSER_GIT"/pdf-parser.py \
			pdf-parser-"$PDFPARSER_GIT"/debian/copyright \
			pdf-parser-"$PDFPARSER_GIT"/debian/changelog

			sudo mv "$SETUPDIR"/pdf-parser-"$PDFPARSER_GIT" "$PDFPARSER_DIR"
			sudo chmod 755 "$PDFPARSER_DIR"/pdf-parser.py
			sudo ln -s "$PDFPARSER_DIR"/pdf-parser.py /usr/local/bin/pdf-parser

			rm "$SETUPDIR"/pdf-parser-"$PDFPARSER_GIT".zip

			# Change pdf-parser.py to python3
			sudo sed -i 's/#!\/usr\/bin\/env python/#!\/usr\/bin\/env python3/' "$PDFPARSER_DIR"/pdf-parser.py

			#======================================================================

			echo ""
			echo -e "${BLUE}[i]Listing symlinks...${RESET}"
			ls -l /usr/local/bin
			echo -e "${BLUE}[i]pdftools installed.${RESET}"
			sleep 1
		fi
	fi

}

function System76PPA() {

	# https://eclypsium.com/2022/07/26/firmware-security-realizations-part-1-secure-boot-and-dbx/
	if ! (grep -qx 'System76' /sys/devices/virtual/dmi/id/sys_vendor); then
		return
	fi

	echo -e "${GREEN}[i]Adding System76 drivers...${RESET}"

	# https://support.system76.com/articles/system76-driver

	echo 'Package: *
Pin: release o=LP-PPA-system76-dev-stable
Pin-Priority: 1001

Package: *
Pin: release o=LP-PPA-system76-dev-pre-stable
Pin-Priority: 1001' | sudo tee /etc/apt/preferences.d/system76-apt-preferences

	sudo apt-add-repository -y ppa:system76-dev/stable

	if ! (gpg /etc/apt/trusted.gpg.d/system76-dev_ubuntu_stable.gpg | grep '5D1F 3A80 254F 6AFB A254  FED5 ACD4 42D1 C8B7 748B'); then
		echo -e "${RED}[i]System76 signing key has an unexpected fingerprint.${RESET}"
		return 1
	else
		echo -e "[${GREEN}OK${RESET}]"

	fi 2>/dev/null

	sudo apt-get update
	sudo apt install system76-driver

	if (lsmod | grep -q 'nvidia'); then
		sudo apt install system76-driver-nvidia
	fi

}

function installFlatpak() {

	echo -e "${GREEN}[i]Adding Flatpak...${RESET}"

	sudo apt install -y flatpak

	# Note: the Software Center app on Ubuntu 20.04 and later is distributed as a snap package, 'snap-store'

	# This means following the next step and Installing gnome-software-plugin-flatpak will also install the deb
	# version of the Software Center 'gnome-software' effectively a duplicate not confined by snap.
	# The 'snap-store' does not currently support installing flatpaks via the GUI, so the CLI is used instead.

	# optional step:
#	sudo apt install gnome-software-plugin-flatpak

	sudo flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo

	# Also not a bad idea to add the collection ID to this remote for creating offline versions of installed apps for backup:
	sudo flatpak remote-modify --collection-id=org.flathub.Stable flathub

	if ! (gpg /var/lib/flatpak/repo/flathub.trustedkeys.gpg 2>/dev/null | grep -q '6E5C 05D9 79C7 6DAF 93C0  8135 4184 DD4D 907A 7CAE' > /dev/null); then
		echo -e "${RED}[i]Flatpak signing key has an unexpected fingerprint.${RESET}"
	fi

	echo -e "${BLUE}[i]Applying a strict global override policy for all flatpaks...${RESET}"

	# The overrides/ folder does not exist by default and must be created.
	sudo mkdir -p /var/lib/flatpak/overrides/

	echo '[Context]
filesystems=!host;
shared=!network;!ipc;' | sudo tee /var/lib/flatpak/overrides/global

	# Consider adding sockets=!x11;!fallback-x11 for systems running only wayland
	if ! [ "$XDG_SESSION_TYPE" == "x11" ]; then
		echo 'sockets=!x11;!fallback-x11;
' | sudo tee -a /var/lib/flatpak/overrides/global
	fi

	echo '[Session Bus Policy]
org.gtk.vfs.*=none
org.gtk.vfs=none' | sudo tee -a /var/lib/flatpak/overrides/global

	echo -e "${YELLOW}[i]Reboot before using Flatpak${RESET}"

}

function installPackages() {

	echo -e ""
	echo -e "${BLUE}[i]${RESET}Beginning installation of essential packages."

	if [ "$VPS" = "true" ]; then
		sudo apt install -y aide auditd cryptsetup easy-rsa libpam-google-authenticator openvpn qrencode resolvconf rkhunter tmux wireguard

	elif [ "$HW" = "true" ]; then
		# snap
		if (command -v snap > /dev/null); then
			sudo apt autoremove --purge -y eog gedit
			if (sudo snap install eog); then
				sudo snap connect eog:removable-media
				sudo snap disconnect eog:network
				if ! [ "$XDG_SESSION_TYPE" == "x11" ]; then
					sudo snap disconnect eog:x11
				fi
			fi

			if (sudo snap install gedit); then
				sudo snap connect gedit:removable-media
				sudo snap disconnect gedit:cups-control
				sudo snap disconnect gedit:network
				if ! [ "$XDG_SESSION_TYPE" == "x11" ]; then
					sudo snap disconnect gedit:x11
				fi
			fi
		fi
		# flatpak
		if (command -v evince > /dev/null); then
			sudo apt autoremove --purge -y evince
			echo -e "${YELLOW}[i]${RESET}Evince apt pacakge removed. Replace with: flatpak install org.gnome.Evince${RESET}"
		fi
		sudo apt install -y aide auditd apparmor-utils cryptsetup curl git libpam-google-authenticator pcscd resolvconf rkhunter scdaemon tmux usb-creator-gtk usbguard wireguard
		System76PPA
		installFlatpak

	elif [ "$VM" = "true" ]; then
		if (sudo dmesg | grep -q 'vmware'); then
			sudo apt install -y open-vm-tools-desktop
		fi
		sudo apt install -y aide auditd apparmor-utils cryptsetup curl gimp git hexedit libimage-exiftool-perl libpam-google-authenticator nmap pcscd poppler-utils python3-pip python3-venv resolvconf rkhunter scdaemon screen tmux usbguard wireguard wireshark
		# snap
		if (command -v snap > /dev/null); then
			sudo apt autoremove --purge -y eog gedit

			if (sudo snap install chromium); then
				sudo snap disconnect chromium:bluez
				sudo snap disconnect chromium:cups-control
				sudo snap disconnect chromium:removable-media
				if ! [ "$XDG_SESSION_TYPE" == "x11" ]; then
					sudo snap disconnect chromium:x11
				fi
			fi

			if (sudo snap install eog); then
				sudo snap connect eog:removable-media
				sudo snap disconnect eog:network
				if ! [ "$XDG_SESSION_TYPE" == "x11" ]; then
					sudo snap disconnect eog:x11
				fi
			fi

			if (sudo snap install firefox); then
				sudo snap disconnect firefox:cups-control
				sudo snap disconnect firefox:removable-media
				if ! [ "$XDG_SESSION_TYPE" == "x11" ]; then
					sudo snap disconnect firefox:x11
				fi
			fi

			if (sudo snap install gedit); then
				sudo snap connect gedit:removable-media
				sudo snap disconnect gedit:cups-control
				sudo snap disconnect gedit:network
				if ! [ "$XDG_SESSION_TYPE" == "x11" ]; then
					sudo snap disconnect gedit:x11
				fi
			fi

			if (sudo snap install libreoffice); then
				sudo snap connect libreoffice:removable-media
				sudo snap disconnect libreoffice:bluez
				sudo snap disconnect libreoffice:network
				sudo snap disconnect libreoffice:network-bind
				if ! [ "$XDG_SESSION_TYPE" == "x11" ]; then
					sudo snap disconnect libreoffice:x11
				fi
			fi

			if (sudo snap install vlc); then
				sudo snap connect vlc:removable-media
				sudo snap disconnect vlc:avahi-control
				sudo snap disconnect vlc:network
				sudo snap disconnect vlc:network-bind
				if ! [ "$XDG_SESSION_TYPE" == "x11" ]; then
					sudo snap disconnect vlc:x11
				fi
			fi

		fi
		# flatpak
		if (command -v evince > /dev/null); then
			sudo apt autoremove --purge -y evince
			echo -e "${YELLOW}[i]${RESET}Evince apt pacakge removed. Replace with: flatpak install org.gnome.Evince${RESET}"
		fi

		# Add third party package functions from above below here
		installPdfTools
		installFlatpak
	fi
	echo -e "${BLUE}[+]${RESET}All essential packages installed.${RESET}"
	sleep 1
}

function addGroups() {

	# Monitor && log execution of this or don't enable it.
	if (grep -q 'wireshark' /etc/group); then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}Add $USERNAME to wireshark group?"
		echo ""
		until [[ ${WIRESHARK_CHOICE} =~ ^(y|n)$ ]]; do
			read -rp "[y/n]: " WIRESHARK_CHOICE
		done
	fi
	if [[ $WIRESHARK_CHOICE == "y" ]]; then
		sudo usermod -a -G wireshark "$USERNAME"
		echo "Done."
		sleep 1
	elif [[ $WIRESHARK_CHOICE == "n" ]] && (groups "$USERNAME" | grep -q wireshark); then
		echo -e "${BLUE}[i]${RESET}Remove $USERNAME from wireshark group?"
		until [[ ${WIRESHARK_REMOVE} =~ ^(y|n)$ ]]; do
			read -rp "[y/n]: " WIRESHARK_REMOVE
		done

		if [[ $WIRESHARK_REMOVE == "y" ]]; then
			sudo deluser "$USERNAME" wireshark
		fi
	fi

}

function removeGroups() {

	# Adjusts default user's groups to prevent non-root processes from reading system log files.
	if (groups "$USERNAME" | grep -q ' adm '); then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}Removing user $USERNAME from administrative groups (adm)."
		sudo deluser "$USERNAME" adm
	fi
}

function setPostfix() {

	echo "======================================================================"
	# Prevents the postfix service from flagging the system as degraded if it's not configured.
	if (systemctl is-enabled postfix); then
		echo -e "${BLUE}[-]${RESET}Disabling postfix.service.${RESET}"
		sudo systemctl disable postfix.service
	else
		echo -e "${BLUE}[i]${RESET}postfix.service already disabled. Skipping."
	fi
}

function setAIDE() {

	AIDE_MACROS=/etc/aide/aide.conf.d

	# Stops cron daily execution from altering database
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Checking aide's cron.daily execution (disabled, enable manually)."
	chmod -x '/etc/cron.daily/aide'

	if [ "$HW" = 'true' ] && ! [ -e "$AIDE_MACROS"/31_aide_home-dirs ]; then
		echo "!$HOME" | sudo tee "$AIDE_MACROS"/31_aide_home-dirs
		echo -e "${GREEN}[+]${RESET}Adding AIDE policy file: $AIDE_MACROS/31_aide_home-dirs."
	else
		echo -e "${BLUE}[i]${RESET}AIDE policy file $AIDE_MACROS/31_aide_home-dirs already installed. Skipping."
	fi
}

function setRkhunter() {

	RKHUNTER_CONF=/etc/rkhunter.conf

	# Stops cron daily execution from altering database
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Checking rkhunter's cron.daily execution (disabled, enable manually)."
	sudo chmod -x '/etc/cron.daily/rkhunter'

	if [ -e "$RKHUNTER_CONF" ]; then
		if ! (grep -q -x "DISABLE_TESTS=suspscan hidden_procs deleted_files apps" "$RKHUNTER_CONF"); then
			sudo sed -i 's/^DISABLE_TESTS=.*$/DISABLE_TESTS=suspscan hidden_procs deleted_files apps/' "$RKHUNTER_CONF" 
			echo -e "${BLUE}[*]${RESET}Updating rkhunter test list."
		fi
		if ! (grep -q -x "SCRIPTWHITELIST=/usr/bin/egrep" "$RKHUNTER_CONF"); then
			sudo sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/egrep/SCRIPTWHITELIST=\/usr\/bin\/egrep/' "$RKHUNTER_CONF"
			echo -e "${BLUE}[*]${RESET}Updating script whitelists. (1/5)"
		fi
		if ! (grep -q -x "SCRIPTWHITELIST=/usr/bin/fgrep" "$RKHUNTER_CONF"); then
			sudo sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/fgrep/SCRIPTWHITELIST=\/usr\/bin\/fgrep/' "$RKHUNTER_CONF"
			echo -e "${BLUE}[*]${RESET}Updating script whitelists. (2/5)"
		fi
		if ! (grep -q -x "SCRIPTWHITELIST=/usr/bin/which" "$RKHUNTER_CONF"); then
			sudo sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/which/SCRIPTWHITELIST=\/usr\/bin\/which/' "$RKHUNTER_CONF"
			echo -e "${BLUE}[*]${RESET}Updating script whitelists. (3/5)"
		fi
		if ! (grep -q -x "SCRIPTWHITELIST=/usr/bin/ldd" "$RKHUNTER_CONF"); then
			sudo sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/ldd/SCRIPTWHITELIST=\/usr\/bin\/ldd/' "$RKHUNTER_CONF"
			echo -e "${BLUE}[*]${RESET}Updating script whitelists. (4/5)"
		fi
		if [ "$VPS" = 'false' ]; then
			if ! (grep -q -x "SCRIPTWHITELIST=/usr/bin/lwp-request" "$RKHUNTER_CONF"); then
			sudo sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/lwp-request/SCRIPTWHITELIST=\/usr\/bin\/lwp-request/' "$RKHUNTER_CONF"
			echo -e "${BLUE}[*]${RESET}Updating script whitelists. (5/5)"
			fi
		fi
		if ! (grep -q -x "ALLOW_SSH_PROT_V1=0" "$RKHUNTER_CONF"); then
			sudo sed -i 's/ALLOW_SSH_PROT_V1=2/ALLOW_SSH_PROT_V1=0/' "$RKHUNTER_CONF"
			echo -e "${BLUE}[*]${RESET}Adding warning for detection of SSHv1 protocol."
		fi
		if ! (grep -q -x '#WEB_CMD="/bin/false"' "$RKHUNTER_CONF"); then
			sudo sed -i 's/WEB_CMD="\/bin\/false"/#WEB_CMD="\/bin\/false"/' "$RKHUNTER_CONF"
			echo -e "${BLUE}[*]${RESET}Commenting out WEB_CMD="'"\/bin\/false"'
		fi

		sudo rkhunter -C && echo -e "${GREEN}[+]${RESET}Reloading rkhunter profile."

	elif ! [ -e "$RKHUNTER_CONF" ]; then
		echo -e "${RED}"'[!]'"${RESET}rkhunter.conf file not found. Skipping."
	fi
}

function setSSH() {

	SSHD_CONF='/etc/ssh/sshd_config'

	echo "======================================================================"
	if ! (command -v sshd > /dev/null); then
		echo ""
		echo "Install OpenSSH server?"
		echo ""
		until [[ $SSHD_INSTALL_CHOICE =~ ^(y|n)$ ]]; do
			read -rp "[y/n]: " SSHD_INSTALL_CHOICE
		done
		if [[ $SSHD_INSTALL_CHOICE == "y" ]]; then
			if (command -v apt > /dev/null); then
				sudo apt install -y openssh-server
			elif (command -v dnf > /dev/null); then
				sudo dnf install -y openssh-server
			fi
		fi
	elif ! (systemctl is-active sshd > /dev/null); then
		echo ""
		echo "Start and enable OpenSSH server?"
		echo ""
		until [[ $SSHD_START_CHOICE =~ ^(y|n)$ ]]; do
			read -rp "[y/n]: " SSHD_START_CHOICE
		done
		if [[ $SSHD_START_CHOICE == "y" ]]; then

			sudo systemctl start sshd
			sudo systemctl enable sshd
			echo -e "${BLUE}[+]${RESET}Starting and enabling sshd.service..."
		fi
	fi

	if [ -e "$SSHD_CONF" ]; then
		echo -e "${BLUE}[i]${RESET}Regenerating server host keys..."
		sudo rm /etc/ssh/ssh_host_*
		sudo ssh-keygen -A

		echo -e "${BLUE}[i]${RESET}Updating SSHD config..."
		if ! [ -e /etc/ssh/sshd_config.bkup ]; then
			sudo cp /etc/ssh/sshd_config -n /etc/ssh/sshd_config.bkup
		fi

		# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-cis.html
		# xccdf_org.ssgproject.content_group_ssh_server

		if ! (grep -Eq "^PasswordAuthentication no$" "$SSHD_CONF"); then
			if (grep -Eq "^.*PasswordAuthentication.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*PasswordAuthentication.*$/PasswordAuthentication no/g' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: PasswordAuthentication no"
			else
				echo "PasswordAuthentication no" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: PasswordAuthentication no"
			fi
		fi

		if ! (grep -Eq "^PermitRootLogin no$" "$SSHD_CONF"); then
			if (grep -Eq "^.*PermitRootLogin.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin no/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: PermitRootLogin no"
			else
				echo "PermitRootLogin no" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: PermitRootLogin no"
			fi
		fi

		# This no longer appears as an option, only referenced in /etc/rkhunter.conf
#		if ! (grep -Eq "^Protocol 2$" "$SSHD_CONF"); then
#			if (grep -Eq "^.*Protocol.*$" "$SSHD_CONF"); then
#				sudo sed -i 's/^.*Protocol.*$/&\nProtocol 2/' "$SSHD_CONF"
#				echo -e "${GREEN}[+]${RESET}Prohibiting SSHv1 protocol."
#			else
#				echo "Protocol 2" | sudo tee -a "$SSHD_CONF"
#				echo -e "${GREEN}[+]${RESET}Prohibiting SSHv1 protocol."
#			fi
#		fi

		if ! (grep -Eq "^PermitEmptyPasswords no$" "$SSHD_CONF"); then
			if (grep -Eq "^.*PermitEmptyPasswords.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*PermitEmptyPasswords.*$/PermitEmptyPasswords no/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: PermitEmptyPasswords no"
			else
				echo "PermitEmptyPasswords no" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: PermitEmptyPasswords no"
			fi
		fi

		if ! (grep -Eq "^AllowAgentForwarding no$" "$SSHD_CONF"); then
			if (grep -Eq "^.*AllowAgentForwarding.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*AllowAgentForwarding.*$/AllowAgentForwarding no/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: AllowAgentForwarding no"
			else
				echo "AllowAgentForwarding no" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: AllowAgentForwarding no"
			fi
		fi

		# 600=10 minutes
		if ! (grep -Eq "^ClientAliveInterval 300$" "$SSHD_CONF"); then
			if (grep -Eq "^.*ClientAliveInterval.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*ClientAliveInterval.*$/ClientAliveInterval 300/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: ClientAliveInterval 300"
			else
				echo "ClientAliveInterval 300" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: ClientAliveInterval 300"
			fi
		fi

		# set 0 for ClientAliveInterval to be exact
		if ! (grep -Eq "^ClientAliveCountMax 0$" "$SSHD_CONF"); then
			if ( grep -Eq "^.*ClientAliveCountMax.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*ClientAliveCountMax.*$/ClientAliveCountMax 0/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: ClientAliveCountMax 0"
			else
				echo "ClientAliveCountMax 0" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: ClientAliveCountMax 0"
			fi
		fi

		# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-cis.html
		# xccdf_org.ssgproject.content_rule_disable_host_auth
		if ! (grep -Eq "^HostbasedAuthentication no$" "$SSHD_CONF"); then
			if (grep -Eq "^.*HostbasedAuthentication.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*HostbasedAuthentication.*$/HostbasedAuthentication no/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: HostbasedAuthentication no"
			else
				echo "HostbasedAuthentication no" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: HostbasedAuthentication no"
			fi
		fi

		# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-cis.html
		# xccdf_org.ssgproject.content_rule_sshd_disable_rhosts
		if ! (grep -Eq "^IgnoreRhosts yes$" "$SSHD_CONF"); then
			if (grep -Eq "^.*IgnoreRhosts.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*IgnoreRhosts.*$/IgnoreRhosts yes/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: IgnoreRhosts yes"
			else
				echo "IgnoreRhosts yes" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: IgnoreRhosts yes"
			fi
		fi

		# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-cis.html
		# xccdf_org.ssgproject.content_rule_sshd_do_not_permit_user_env
		if ! (grep -Eq "^PermitUserEnvironment no$" "$SSHD_CONF"); then
			if (grep -Eq "^.*PermitUserEnvironment.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*PermitUserEnvironment.*$/PermitUserEnvironment no/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: PermitUserEnvironment no"
			else
				echo "PermitUserEnvironment no" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: PermitUserEnvironment no"
			fi
		fi

		# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-cis.html
		# xccdf_org.ssgproject.content_rule_sshd_set_loglevel_info
		if ! (grep -Eq "^LogLevel INFO$" "$SSHD_CONF"); then
			if (grep -Eq "^.*LogLevel INFO.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*LogLevel INFO.*$/LogLevel INFO/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: LogLevel INFO"
			else
				echo "LogLevel INFO" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: LogLevel INFO"
			fi
		fi

		# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-cis.html
		# xccdf_org.ssgproject.content_rule_sshd_set_max_auth_tries
		if ! (grep -Eq "^MaxAuthTries 4$" "$SSHD_CONF"); then
			if (grep -Eq "^.*MaxAuthTries.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*MaxAuthTries.*$/MaxAuthTries 4/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: MaxAuthTries 4"
			else
				echo "MaxAuthTries 4" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: MaxAuthTries 4"
			fi
		fi

		# https://static.open-scap.org/ssg-guides/ssg-ubuntu2004-guide-stig.html
		# xccdf_org.ssgproject.content_rule_sshd_disable_x11_forwarding
		if ! (grep -Eq "^X11Forwarding no$" "$SSHD_CONF"); then
			if ( grep -Eq "^.*X11Forwarding.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*X11Forwarding.*$/X11Forwarding no/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: X11Forwarding no"
			else
				echo "X11Forwarding no" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: X11Forwarding no"
			fi
		fi

		# https://static.open-scap.org/ssg-guides/ssg-ubuntu2004-guide-stig.html
		# xccdf_org.ssgproject.content_rule_sshd_use_approved_ciphers_ordered_stig
		if ! (grep -Eq "^Ciphers aes256-ctr,aes192-ctr,aes128-ctr$" "$SSHD_CONF"); then
			if ( grep -Eq "^(#Ciphers|Ciphers).*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*Ciphers.*$/Ciphers aes256-ctr,aes192-ctr,aes128-ctr/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: Ciphers aes256-ctr,aes192-ctr,aes128-ctr"
			else
				echo "Ciphers aes256-ctr,aes192-ctr,aes128-ctr" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: Ciphers aes256-ctr,aes192-ctr,aes128-ctr"
			fi
		fi

		# https://static.open-scap.org/ssg-guides/ssg-ubuntu2004-guide-stig.html
		# xccdf_org.ssgproject.content_rule_sshd_use_approved_macs_ordered_stig
		if ! (grep -Eq "^MACs hmac-sha2-512,hmac-sha2-256$" "$SSHD_CONF"); then
			if ( grep -Eq "^(MACs|#MACs).*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*MACs.*$/MACs hmac-sha2-512,hmac-sha2-256/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: MACs hmac-sha2-512,hmac-sha2-256"
			else
				echo "MACs hmac-sha2-512,hmac-sha2-256" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: MACs hmac-sha2-512,hmac-sha2-256"
			fi
		fi

		# https://static.open-scap.org/ssg-guides/ssg-ubuntu2004-guide-stig.html
		# xccdf_org.ssgproject.content_rule_sshd_x11_use_localhost
		if ! (grep -Eq "^X11UseLocalhost yes$" "$SSHD_CONF"); then
			if (grep -Eq ".*X11UseLocalhost.*$" "$SSHD_CONF"); then
				sudo sed -i 's/^.*X11UseLocalhost.*$/X11UseLocalhost yes/' "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: X11UseLocalhost yes"
			else
				echo "X11UseLocalhost yes" | sudo tee -a "$SSHD_CONF"
				echo -e "${GREEN}[+]${RESET}Setting: X11UseLocalhost yes"
			fi
		fi

		echo -e "${BLUE}[i]${RESET}What port do you want SSH to listen to?"
		echo "   1) Default: 22"
		echo "   2) Custom"
		echo "   3) Random [49152-65535]"
		until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "[i]Port choice [1-3]: " -e -i 1 PORT_CHOICE
		done
		case $PORT_CHOICE in
		1)
			PORT="22"
			;;
		2)
			until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
				read -rp "[i]Custom port [1-65535]: " -e -i 22 PORT
			done
			;;
		3)
			# Generate random number within private ports range
			PORT=$(shuf -i49152-65535 -n1)
			echo -e "${GREEN}[i]${RESET}Random Port: ${BOLD}$PORT${RESET}"
			;;
		esac

		sudo sed -i 's/.*Port .*$/Port '"${PORT}"'/' "$SSHD_CONF"

		echo ""
		if (command -v iptables > /dev/null); then
			echo "iptables are available, use ip/ip6tables?"
			if (command -v ufw > /dev/null); then
				echo "(otherwise, ufw will be used)"
			elif (command -v firewall-cmd > /dev/null); then
				echo "(otherwise, firewall-cmd will be used)"
			fi
			echo ""
			until [[ $IPTABLES_CHOICE =~ ^(y|n)$ ]]; do
				read -rp "[y/n]: " IPTABLES_CHOICE
			done
			if [[ $IPTABLES_CHOICE == "y" ]]; then
				sudo iptables -A INPUT -i "$PUB_NIC" -p tcp -m tcp --dport "$PORT" -j ACCEPT
				sudo ip6tables -A INPUT -i "$PUB_NIC" -p tcp -m tcp --dport "$PORT" -j ACCEPT
			elif [[ $IPTABLES_CHOICE == "n" ]]; then
				if (command -v ufw > /dev/null); then
					sudo ufw allow in on "$PUB_NIC" to any proto tcp port "$PORT" comment 'ssh'
					echo -e "${GREEN}[+]${RESET}Added ufw rules for SSH port ${PORT}."
				elif (command -v firewall-cmd > /dev/null); then
					sudo firewall-cmd --add-port="$SSH_PORT"/tcp
					echo -e "${GREEN}[+]${RESET}Added firewall-cmd rules for SSH port ${PORT}."
				fi
			fi
		fi

		echo ""
		echo "The current connection will remain established until exiting."
		echo "Confirm you can login via ssh from another terminal session"
		echo "after this script completes, and before exiting this current"
		echo "session."
		echo ""
		echo "Restart sshd.service now?"
		echo ""
		until [[ $SSHD_RESTART_CHOICE =~ ^(y|n)$ ]]; do
			read -rp "[y/n]: " SSHD_RESTART_CHOICE
		done
		if [[ $SSHD_RESTART_CHOICE == "y" ]]; then

			sudo systemctl restart sshd.service
			echo -e "${BLUE}[+]${RESET}Restarting sshd.service..."
		fi

		echo -e "${RED}"'[!]'"${RESET}${BOLD}Be sure to review all firewall rules before ending this session.${RESET}"
		sleep 3
	fi
}

function setMFA() {

	# https://www.raspberrypi.org/blog/setting-up-two-factor-authentication-on-your-raspberry-pi/
	# https://github.com/0ptsec/optsecdemo

	SSHD_CONF='/etc/ssh/sshd_config'
	PAM_LOGIN='/etc/pam.d/login'
	PAM_GDM='/etc/pam.d/gdm-password'
	PAM_SSHD='/etc/pam.d/sshd'

	echo -e "${BLUE}[?]Configure libpam-google-authenticator for MFA login?${RESET}"
	if [ -e "$HOME"/.google_authenticator ]; then
		echo -e "${YELLOW}[i]${RESET}A $HOME/.google_authenticator already exists."
	fi
	echo ""
	until [[ $MFA_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "[y/n]: " MFA_CHOICE
	done
	if [[ $MFA_CHOICE == "y" ]]; then

		# Install libpam-google-authenticator if it's missing
		if ! (command -v google-authenticator > /dev/null); then
			sudo apt install -y libpam-google-authenticator
		fi

		# Check if this machine is running an OpenSSH server
		if [ -e "$SSHD_CONF" ]; then
	                if ! (grep -Eq "^ChallengeResponseAuthentication = yes$" "$SSHD_CONF"); then
	                        if (grep -Eq "^.*ChallengeResponseAuthentication.*$" "$SSHD_CONF"); then
	                                sudo sed -i 's/^.*ChallengeResponseAuthentication.*$/ChallengeResponseAuthentication = yes/' "$SSHD_CONF"
	                                echo -e "${GREEN}[+]${RESET}Setting: ChallengeResponseAuthentication = yes"
	                        else
	                                echo "ChallengeResponseAuthentication = yes" | sudo tee -a "$SSHD_CONF"
	                                echo -e "${GREEN}[+]${RESET}Setting: ChallengeResponseAuthentication = yes"
	                        fi
	                fi
	                if ! (grep -Eq "^auth required pam_google_authenticator.so no_increment_hotp nullok$" "$PAM_SSHD"); then
				echo '# libpam-google-authenticator 2fa
auth required pam_google_authenticator.so no_increment_hotp nullok' | sudo tee -a "$PAM_SSHD"
			fi

			sudo systemctl restart sshd
		fi

		# If this isn't a headless server, add MFA to desktop login as well.
		if ! [[ $VPS == 'true' ]]; then
			if ! (grep -Eq "^auth required pam_google_authenticator.so no_increment_hotp nullok$" "$PAM_LOGIN"); then
				echo '# libpam-google-authenticator 2fa
auth required pam_google_authenticator.so no_increment_hotp nullok' | sudo tee -a "$PAM_LOGIN"
		fi
			if ! (grep -Eq "^auth required pam_google_authenticator.so no_increment_hotp nullok$" "$PAM_GDM"); then
				echo '# libpam-google-authenticator 2fa
auth required pam_google_authenticator.so no_increment_hotp nullok' | sudo tee -a "$PAM_GDM"
			fi
		fi

		google-authenticator

	fi
}

function blockKmods() {

	function blockFirewire() {

		echo "# Select the legacy firewire stack over the new CONFIG_FIREWIRE one.

blacklist ohci1394
blacklist sbp2
blacklist dv1394
blacklist raw1394
blacklist video1394

blacklist firewire-ohci
blacklist firewire-sbp2
blacklist firewire-core" | sudo tee '/etc/modprobe.d/blacklist-firewire.conf'

	}

	function blockThunderbolt() {
		if [ -e '/etc/modprobe.d/blacklist-thunderbolt.conf' ]; then
			echo -e "${YELLOW}"'[!]'"${RESET}${BOLD}/etc/modprobe.d/blacklist-thunderbolt.conf already exists.${RESET}" 
			echo -e "${YELLOW}"'[!]'"${RESET}Holding current configuration for review."
			echo -e "${YELLOW}"'[!]'"${RESET}Only /etc/modprobe.d/blacklist-firewire.conf will be updated."

		else
			sudo touch '/etc/modprobe.d/blacklist-thunderbolt.conf'
			echo "# Disable Thunderbolt ports. Comment to enable

blacklist thunderbolt" | sudo tee '/etc/modprobe.d/blacklist-thunderbolt.conf'
		fi
	}

	# This needs fixed in case a `blacklist-thunderbolt.conf` ever ships by default
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Block thunderbolt and firewire kernel modules?" 
	echo "(prevents connected devices from loading)"
	echo ""
	until [[ $KMOD_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "[y/n]: " KMOD_CHOICE
	done

 	if [[ $KMOD_CHOICE == "y" ]]; then
		# Run both functions to block thunderbolt and firewire, also check if they already exist
		if ! (grep -qx 'blacklist firewire-core' '/etc/modprobe.d/blacklist-firewire.conf') ; then
			echo ""
			echo -e "${BLUE}[i]${RESET}Modifying /etc/modprobe.d/blacklist-firewire.conf"
			blockFirewire
			echo -e "${BLUE}[i]${RESET}Creating /etc/modprobe.d/blacklist-thunderbolt.conf"
			blockThunderbolt
			sudo update-initramfs -k all -u
			echo -e "${GREEN}[+]${RESET}Done."
			echo ""
		else
			echo ""
			echo -e "${BLUE}[i]${RESET}Already updated. Skipping."
		fi
	elif [[ $KMOD_CHOICE == "n" ]]; then
		# Reset the configurations back to their defaults
		if [ -e '/etc/modprobe.d/blacklist-thunderbolt.conf' ]; then
			echo -e "${BLUE}[-]${RESET}Removing /etc/modprobe.d/blacklist-thunderbolt.conf"
			sudo rm '/etc/modprobe.d/blacklist-thunderbolt.conf'
			echo -e "${BLUE}[-]${RESET}Resetting /etc/modprobe.d/blacklist-firewire.conf"
			echo "# Select the legacy firewire stack over the new CONFIG_FIREWIRE one.

blacklist ohci1394
blacklist sbp2
blacklist dv1394
blacklist raw1394
blacklist video1394

#blacklist firewire-ohci
#blacklist firewire-sbp2" | sudo tee '/etc/modprobe.d/blacklist-firewire.conf'

			sudo update-initramfs -k all -u

		fi

		echo -e "${BLUE}[i]${RESET}Set to default configuration."
	fi
}

function setLockdown() {
	if [ -e /sys/kernel/security/lockdown ]; then
		echo "======================================================================"
		if ! (mokutil --sb-state | grep -qx 'SecureBoot enabled'); then
			echo ""
			echo -e "${BLUE}[i]${RESET}SecureBoot is not enabled."
		else
			echo ""
			echo -e "${BLUE}[i]${RESET}SecureBoot is enabled."
		fi
		echo -e "${BLUE}[i]${RESET}Current kernel lockdown state: "
		grep -E "\[none\]|\[integrity\]|\[confidentiality\]" /sys/kernel/security/lockdown
		echo ""
		echo -e "${BLUE}[i]${RESET}Change kernel lockdown mode?"
		until [[ $LOCKDOWN_CHOICE =~ ^(y|n)$ ]]; do
			read -rp "CHOOSE NO IF RUNNING UNSIGNED THIRD PARTY KERNEL MODULES [y/n]: " LOCKDOWN_CHOICE
		done
		if [[ $LOCKDOWN_CHOICE == "y" ]]; then
			echo ""
			echo "Enable which mode?"
			echo ""
			until [[ $LOCKDOWN_MODE =~ ^(none|integrity|confidentiality)$ ]]; do
				read -rp "[none|integrity|confidentiality]: " LOCKDOWN_MODE
			done
			echo ""
			# Location of kernel commandline parameters on Ubuntu for Raspberry Pi (GRUB not present)
			if [ -e /boot/firmware/nobtcmd.txt ]; then
				KERNEL_CMDLINE=/boot/firmware/nobtcmd.txt
				if grep -q '^.*lockdown=.*'  "$KERNEL_CMDLINE" ; then
					# modify the GRUB command-line if a lockdown= arg already exists
					# note no space between `\1` and `lockdown=`
					sudo sed -i 's/\(^.*\)lockdown=[^[:space:]]*\(.*\)/\1lockdown='"$LOCKDOWN_MODE"' \2/'  "$KERNEL_CMDLINE"
				else 
					# no lockdown=arg is present, append it
					# note the additional space between `\1` and `lockdown=`
					sudo sed -i 's/\(^.*\)/\1 lockdown='"$LOCKDOWN_MODE"'/'  "$KERNEL_CMDLINE"
				fi
			# Otherwise default back to location to edit kernel commandline parameters on Ubuntu
			elif [ -e /etc/default/grub ]; then
				KERNEL_CMDLINE=/etc/default/grub
				if grep -q '^GRUB_CMDLINE_LINUX=.*lockdown=.*"'  "$KERNEL_CMDLINE" ; then
					# modify the GRUB command-line if a lockdown= arg already exists
					sudo sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)lockdown=[^[:space:]]*\(.*"\)/\1 lockdown='"$LOCKDOWN_MODE"' \2/'  "$KERNEL_CMDLINE"
				else
					# no lockdown=arg is present, append it
					sudo sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)"/\1 lockdown='"$LOCKDOWN_MODE"'"/'  "$KERNEL_CMDLINE"
				fi
				sudo update-grub
			else
				KERNEL_CMDLINE='null'
				echo -e "${YELLOW}[i]${RESET}Can't find a configuration file to enable lockdown. Skipping..."
			fi
			if ! [[ "$KERNEL_CMDLINE" == 'null' ]]; then
				echo -e "${BLUE}[i]${RESET}Kernel commandline arguments updated in $KERNEL_CMDLINE"
				echo -e "${BLUE}[i]${RESET}Lockdown mode changes won't take effect until next reboot."
			fi
		fi
	else
		# If lockdown mode doesn't exist for this kernel
		echo -e "${BLUE}[i]${RESET}Lockdown mode not supported."
	fi
}

function setGnupg() {

	# https://github.com/drduh/YubiKey-Guide#harden-configuration
	# https://github.com/drduh/config/blob/master/gpg.conf

	# https://github.com/drduh/YubiKey-Guide#create-configuration
	# https://github.com/drduh/config/blob/master/gpg-agent.conf

	# https://github.com/drduh/YubiKey-Guide#replace-agents

	if ! [ -e "$HOME"/.gnupg/gpg.conf ]; then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}GnuPG"
		echo "Harden gpg.conf and add smart card support for ssh to .bashrc file?"
		echo ""
		until [[ $GPG_CHOICE =~ ^(y|n)$ ]]; do
			read -rp "[y/n]: " GPG_CHOICE
		done
		if [[ $GPG_CHOICE == "y" ]]; then

			echo "personal-cipher-preferences AES256 AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
cert-digest-algo SHA512
s2k-digest-algo SHA512
s2k-cipher-algo AES256
charset utf-8
fixed-list-mode
no-comments
no-emit-version
keyid-format 0xlong
list-options show-uid-validity
verify-options show-uid-validity
with-fingerprint
require-cross-certification
no-symkey-cache
use-agent
throw-keyids" | tee "$HOME"/.gnupg/gpg.conf

			# Adjustment for 18.04
			if [[ $MAJOR_UBUNTU_VERSION -eq 18 ]]; then
				sed -i 's/^no-symkey-cache$//' "$HOME"/.gnupg/gpg.conf
			fi

			echo "enable-ssh-support
default-cache-ttl 60
max-cache-ttl 120
pinentry-program /usr/bin/pinentry-curses" | tee "$HOME"/.gnupg/gpg-agent.conf

			if ! (grep -qx '# enable gpg smart card support for ssh' "$HOME"/.bashrc); then
				echo '
# enable gpg smart card support for ssh
export GPG_TTY="$(tty)"
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
gpgconf --launch gpg-agent' | tee -a "$HOME"/.bashrc
			fi
		fi
	fi
}

function checkAppArmor() {

	AA_FIREFOX=/etc/apparmor.d/usr.bin.firefox
	AA_FIREFOX_LOCAL=/etc/apparmor.d/local/usr.bin.firefox

	echo "======================================================================"

	echo -e "${BLUE}[i]${RESET}Checking AppArmor profiles."

	if (command -v firefox | grep -Eq "^/usr/bin/firefox$"); then
		if [ -e "/etc/apparmor.d/disable/usr.bin.firefox" ]; then
		    sudo rm /etc/apparmor.d/disable/usr.bin.firefox
		fi

		echo "# Site-specific additions and overrides for usr.bin.firefox.
# For more details, please see /etc/apparmor.d/local/README.
  deny @{HOME}/Desktop/ r,
  deny @{HOME}/Documents/ r,
  deny @{HOME}/Templates/ r,
  deny @{HOME}/Music/ r,
  deny @{HOME}/Pictures/ r,
  deny @{HOME}/Videos/ r,
  deny @{HOME}/snap/ r, 
  deny /boot/ r,
  deny /opt/ r,
  deny /snap/ r," | sudo tee "$AA_FIREFOX_LOCAL"

		sudo apparmor_parser -r "$AA_FIREFOX"
	fi

	echo -e "${BLUE}[i]${RESET}Done."
}

function CleanUp() {

	if [ -e "$SETUPDIR" ]; then
		sudo rm -rf "$SETUPDIR"
	fi
}

# Command-Line-Arguments
function manageMenu() {
	echo ""
	echo "Welcome to the Ubuntu setup script!"
	echo ""
	echo "How would you like to install Ubuntu?"
	echo ""
	echo "   1) Ubuntu desktop as a virtual machine"
	echo "   2) Ubuntu desktop on real hardware"
	echo "   3) Ubuntu server as a cloud vps"
	echo "   4) Exit"
	until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
		read -rp "Select an option [1-4]: " MENU_OPTION
	done

	case $MENU_OPTION in
	1)
		installVM
		;;
	2)
		installHW
		;;
	3)
		installVPS
		;;
	4)
		exit 0
		;;
	esac
}

function installVM() {
	echo ""
	VM='true'
	# Functions
	MakeTemp
	checkKernel
	setPerms
	checkSudoers
	removeBrowser
	stopServices
	#updateServices
	#addVBox
	setIpv6
	checkNetworking
	setFirewall
	checkPackages
	installPdfTools
	setResolver
	installPackages
	addGroups
	removeGroups
	setPostfix
	#setAIDE
	setRkhunter
	setSSH
	setMFA
	#blockKmods
	setLockdown
	setGnupg
	checkAppArmor
	CleanUp
}

function installHW() {
	echo ""
	HW='true'
	# Functions
	MakeTemp
	checkKernel
	setPerms
	checkSudoers
	removeBrowser
	stopServices
	#updateServices
	addVBox
	setIpv6
	checkNetworking
	setFirewall
	checkPackages
	#installPdfTools
	setResolver
	installPackages
	#addGroups
	removeGroups
	setPostfix
	#setAIDE
	setRkhunter
	setSSH
	setMFA
	blockKmods
	setLockdown
	setGnupg
	#checkAppArmor
	CleanUp
}

function installVPS() {
	echo ""
	VPS='true'
	# Functions
	MakeTemp
	checkKernel
	setPerms
	checkSudoers
	#removeBrowser
	#stopServices
	updateServices
	#addVBox
	setIpv6
	checkNetworking
	setFirewall
	checkPackages
	#installPdfTools
	setResolver
	installPackages
	#addGroups
	removeGroups
	setPostfix
	setAIDE
	setRkhunter
	setSSH
	setMFA
	#blockKmods
	setLockdown
	#setGnupg
	#checkAppArmor
	CleanUp
}

manageMenu
