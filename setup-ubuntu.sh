#!/bin/bash

# This is a post install script for an Ubuntu 18.04+ workstation, vm, or server.
# The goal is to provide a minimal and hardened baseline environment with auditing capability

# Thanks to the following projects for code and inspiration:
# https://github.com/Disassembler0/Win10-Initial-Setup-Script
# https://github.com/g0tmi1k/OS-Scripts
# https://github.com/bfuzzy1/auditd-attack
# https://github.com/angristan/wireguard-install


# Vars

RED="\033[01;31m"      # Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings
BLUE="\033[01;34m"     # Success
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

UID1000="$(grep 1000 /etc/passwd | cut -d: -f1)"
AA_FIREFOX=/etc/apparmor.d/usr.bin.firefox
AA_FIREFOX_LOCAL=/etc/apparmor.d/local/usr.bin.firefox
ADDUSER_CONF=/etc/adduser.conf
AIDE_MACROS=/etc/aide/aide.conf.d
HOME_DIR=/home/"$UID1000"
VBOX_APT_LIST=/etc/apt/sources.list.d/virtualbox.list
RKHUNTER_CONF=/etc/rkhunter.conf
SSHD_CONF=/etc/ssh/sshd_config

#AUDIT_DOCS=/usr/share/doc/auditd/examples/rules
#AUDIT_CONF=/etc/audit/auditd.conf
#AUDIT_RULES_D=/etc/audit/rules.d
#NUM_LOGS=0
#LOG_SIZE=0
#LOG_FORMAT=0
#LOCKDOWN_MODE=0

#PUB_IPV4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
#PUB_IPV6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
GTWY="$(ip route | grep 'default' | cut -d ' ' -f3)"

VM='false'
HW='false'
VPS='false'


# Start

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
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
	# Check OS version
	OS="$(grep -E "^ID=" /etc/os-release | cut -d '=' -f 2)"
	CODENAME="$(grep VERSION_CODENAME /etc/os-release | cut -d '=' -f 2)" # debian or ubuntu
	echo -e "${BLUE}[i]${RESET}$OS $CODENAME detected."
	if [[ $OS == "ubuntu" ]]; then
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
	fi
}
checkOS





function setPerms() {
	# Applies to VM, HW, VPS
	echo "======================================================================"
	if ! (grep -qx 'DIR_MODE=0750' "$ADDUSER_CONF"); then
		sed -i 's/DIR_MODE=0755/DIR_MODE=0750/' "$ADDUSER_CONF"
		chmod 750 "$HOME_DIR"
		echo -e "${GREEN}[+]${RESET}User DAC policy updated successfully."
	else
		echo -e "${BLUE}[i]${RESET}User DAC policy already updated. Skipping."
	fi
}

function checkSudoers() {
	# Applies to pre-installed Raspberry Pi images
	for file in /etc/sudoers.d/* ; do
		if (grep -q "^$UID1000 ALL=(ALL) NOPASSWD:ALL$" "$file"); then
			echo -e "${BLUE}[i]${RESET}Commenting out 'NOPASSWD:ALL' in $file"
			sed -i 's/^'"$UID1000"' ALL=(ALL) NOPASSWD:ALL$/#'"$UID1000"' ALL=(ALL) NOPASSWD:ALL/' "$file"
		fi
	done
}

function removeBrowser() {
	# Applies to HW
	echo "======================================================================"
	if (command -v firefox); then
		for package in /usr/share/doc/firefox*;
			do apt-get autoremove --purge -y "${package:15:30}"; 
		done
		rm -rf /usr/lib/firefox*
	else
		echo -e "${BLUE}[i]${RESET}Default browser already removed. Skipping."
	fi
}


function stopServices() {
	# Applies to VM, HW
	echo "======================================================================"
	# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-standard.html
	# xccdf_org.ssgproject.content_rule_service_apport_disabled
	echo -e "${BLUE}[i]${RESET}Checking apport.service..."
	if (systemctl is-active apport); then
		systemctl stop apport
		systemctl disable apport
		systemctl mask --now apport.service
	elif (systemctl is-enabled apport); then
		systemctl disable apport
		systemctl mask --now apport.service
	fi

	# cups
	echo -e "${BLUE}[i]${RESET}Checking service: cups..."
	if (systemctl is-active cups); then
		systemctl stop cups
	fi
	if (systemctl is-enabled cups); then
		systemctl disable cups
		systemctl mask cups
	fi
	# cups-browsed
	echo -e "${BLUE}[i]${RESET}Checking service: cups-browsed..."
	if (systemctl is-active cups-browsed); then
		systemctl stop cups-browsed
	fi
	if (systemctl is-enabled cups-browsed); then
		systemctl disable cups-browsed
		systemctl mask cups-browsed
	fi
	# avahi
	echo -e "${BLUE}[i]${RESET}Checking service: avahi-daemon..."
	if (systemctl is-active avahi-daemon); then
		systemctl stop avahi-daemon
	fi
	if (systemctl is-enabled avahi-daemon); then
		systemctl disable avahi-daemon
		systemctl mask avahi-daemon
	fi
	echo -e "${BLUE}[i]${RESET}All non-essential services stopped and disabled."
}

function updateServices() {
	# Applies to VPS (only for Digital Ocean Agent)
	# For OSes with systemctl:
	# Modify the exec command
	if [ -e '/etc/systemd/system/do-agent.service' ]; then
		if ! (grep -q '\-\-no\-collector.process' '/etc/systemd/system/do-agent.service' ); then
			echo "======================================================================"
			echo -e "${BLUE}[i]${RESET}Checking do-agent.service's exec command options have been updated."
			sed -i 's%ExecStart=/opt/digitalocean/bin/do-agent%ExecStart=/opt/digitalocean/bin/do-agent --no-collector.processes%' /etc/systemd/system/do-agent.service
			# Restart the agent
			systemctl daemon-reload
			systemctl restart do-agent
		fi
	fi
}

function addVBox() {
	# Applies to HW
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Add Oracle's VirtualBox apt repository and key to keyring?"
	echo ""
	until [[ $VBOX_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "[y/n]: " VBOX_CHOICE
	done

	if [[ $VBOX_CHOICE == "y" ]]; then
		if ! [ -e ./oracle_vbox_2016.asc ]; then
			echo -e "${GREEN}[+]${RESET}Retrieving VirtualBox apt-key with Wget.${RESET}"
			(wget -O oracle_vbox_2016.asc 'https://www.virtualbox.org/download/oracle_vbox_2016.asc') || (echo -e "${RED}"'[!]'"${RESET}Unable to retrieve Oracle VirtualBox signing key.${RESET}" && rm oracle_vbox_2016.asc)
		fi
		if [ -e ./oracle_vbox_2016.asc ]; then
			echo -e "${GREEN}[+]${RESET}Adding VirtualBox apt-key from local file.${RESET}"
			echo -e "${GREEN}[+]${RESET}VirtualBox sources.list created at $VBOX_APT_LIST."
			apt-key add ./oracle_vbox_2016.asc
			echo "deb [arch=amd64] https://download.virtualbox.org/virtualbox/debian ${VERSION_CODENAME} contrib" >"$VBOX_APT_LIST"
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
			rm "$VBOX_APT_LIST"
			apt-key del 'B9F8 D658 297A F3EF C18D  5CDF A2F6 83C5 2980 AECF'
			apt update
			apt autoremove -y
			echo ""
			echo -e "${BLUE}[-]${RESET}VirtualBox removed from sources.list and apt keyring."
			echo ""
		fi
	fi
}

function setIpv6() {
	# Applies to VM, HW, VPS
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Disable IPV6?"
	echo ""
	until [[ $IPV6_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "[y/n]: " IPV6_CHOICE
	done
	if [[ $IPV6_CHOICE == "y" ]]; then
		sed -i 's/^IPV6=yes$/IPV6=no/' /etc/default/ufw && echo -e "${BOLD}[+] ipv6 settings changed.${RESET}"
	elif [[ $IPV6_CHOICE == "n" ]] && (grep -qx 'IPV6=no' /etc/default/ufw) ; then
		sed -i 's/^IPV6=no$/IPV6=yes/' /etc/default/ufw && echo -e "${BOLD}[+] ipv6 settings changed.${RESET}"
		# enable ipv6 privacy addressing
		sed -i 's/^#net\/ipv6\/conf\/default\/use_tempaddr=2$/net\/ipv6\/conf\/default\/use_tempaddr=2/' /etc/ufw/sysctl.conf
		sed -i 's/^#net\/ipv6\/conf\/all\/use_tempaddr=2/net\/ipv6\/conf\/all\/use_tempaddr=2/' /etc/ufw/sysctl.conf
	fi
}

function setFirewall() {
	# Applies to VM, HW, VPS
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Modify the firewall rules?"
	echo ""
	echo -e "${RED}[i]${RESET}(choose 'y' if the ipv6 settings were just changed or if this is the first run)"
	until [[ $UFW_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "[y/n]: " UFW_CHOICE
	done
	if [[ $UFW_CHOICE == "y" ]]; then

		echo -e "${BLUE}[i]${RESET}${BOLD}Resetting firewall rules. Answer 'y' to avoid errors${RESET}."
		ufw reset
		
		# ipv4
		sed -i 's/^-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT$/#-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT/' /etc/ufw/before.rules
		sed -i 's/^-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT$/#-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT/' /etc/ufw/before.rules
		# ipv6
		sed -i 's/^-A ufw6-before-input -p udp -d ff02::fb --dport 5353 -j ACCEPT$/#-A ufw6-before-input -p udp -d ff02::fb --dport 5353 -j ACCEPT/' /etc/ufw/before6.rules
		sed -i 's/^-A ufw6-before-input -p udp -d ff02::f --dport 1900 -j ACCEPT$/#-A ufw6-before-input -p udp -d ff02::f --dport 1900 -j ACCEPT/' /etc/ufw/before6.rules

		ufw enable
		ufw default deny incoming
		ufw default deny outgoing
		ufw allow out on "$PUB_NIC" to any proto tcp port 80,443
		ufw allow out on "$PUB_NIC" to any proto udp port 123
		ufw allow out on "$PUB_NIC" to any proto udp port 53
		ufw prepend deny out to 192.168.0.0/16
		ufw prepend deny out to 172.16.0.0/12
		ufw prepend deny out to 169.254.0.0/16
		ufw prepend deny out to 10.0.0.0/8
		ufw prepend deny out on "$PUB_NIC" to 127.0.0.0/8
		if (grep -qx 'IPV6=yes' /etc/default/ufw); then
			ufw prepend deny out to fc00::/7
			ufw prepend deny out on "$PUB_NIC" to ::1
		fi
		if echo "$GTWY" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
			ufw prepend allow out on "$PUB_NIC" to "$GTWY"
			if (dmesg | grep -q 'VirtualBox') && (echo "$GTWY" | grep -qx 10.0.2.2); then
				ufw insert 2 allow out on "$PUB_NIC" to '10.0.2.3'
			fi
		fi
		echo -e "${BLUE}[+]${RESET}Basic firewall egress rules are live."
	fi
}

function checkPackages() {

	# https://static.open-scap.org/ssg-guides/ssg-ubuntu1804-guide-standard.html
	# xccdf_org.ssgproject.content_rule_package_inetutils-telnetd_removed
	# xccdf_org.ssgproject.content_rule_package_telnetd-ssl_removed
	# xccdf_org.ssgproject.content_rule_package_telnetd_removed
	# xccdf_org.ssgproject.content_rule_package_nis_removed
	# xccdf_org.ssgproject.content_rule_package_ntpdate_removed

	echo "[-]Removing any deprecated packages and protocols..."
	apt-get autoremove --purge -y inetutils-telnetd telnetd-ssl telnetd nis ntpdate

	sleep 2

	echo -e "${BLUE}[i]${RESET}Upgrading apt packages..."
	sleep 3
	apt-get update && \
	apt-get upgrade -y
	sleep 2
	echo -e "${BLUE}[i]${RESET}Autoremoving old packages."
	apt-get clean
	apt-get autoremove --purge -y
	sleep 5


	if (command -v snap); then
		echo -e "${BLUE}[i]${RESET}Checking for snap packages..."
		snap refresh
	fi

	sleep 1

}

function setResolver() {
	# Applies to VM, HW, VPS
	if ! (command -v unbound); then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}Install Unbound?"
		echo ""
		until [[ $UNBOUND_CHOICE =~ ^(y|n)$ ]]; do
			read -rp "[y/n]: " UNBOUND_CHOICE
		done
		if [[ $UNBOUND_CHOICE == "y" ]]; then
			apt install -y unbound
			if [ -e ./unbound.conf ]; then
				# Replace any default conf files if we have our own in cwd
				cp ./unbound.conf -t /etc/unbound/
				rm /etc/unbound/unbound.conf.d/*.conf
			fi
			if ! (unbound-checkconf | grep 'no errors'); then
				echo -e "${RED}[i]${RESET}Error with unbound configuration. Quitting."
				echo -e "${RED}[i]${RESET}Address any configuration errors above then re-run this script."
				exit 1
			else
				echo -e "${BLUE}[i]${RESET}Stopping and disabling systemd-resolved service..."
				if (systemctl is-active systemd-resolved); then
					systemctl stop systemd-resolved
				fi
				if (systemctl is-enabled systemd-resolved); then
					systemctl disable systemd-resolved
				fi

				# Apply latest conf and restart
				systemctl restart unbound
				
				sleep 2
				
				if ! (grep -Eq "^nameserver[[:space:]]127.0.0.1$" /etc/resolv.conf); then
					echo -e "${YELLOW}[i]${RESET}Pointing /etc/resolv.conf to unbound on 127.0.0.1..."
					sed -i 's/^nameserver[[:space:]]127.0.0.53/nameserver 127.0.0.1/' /etc/resolv.conf || exit 1
				fi
			fi
			echo -e "${BLUE}[i]${RESET}Done."
		fi
	fi
}

function installPackages() {
	# Applies to VM, HW, VPS
	
	echo -e ""
	echo -e "${BLUE}[i]${RESET}Beginning installation of essential packages."
	if [ "$VPS" = "true" ]; then
		apt install -y aide auditd easy-rsa openvpn qrencode resolvconf rkhunter tmux wireguard
	elif [ "$HW" = "true" ]; then
		apt install -y auditd apparmor-utils curl git pcscd resolvconf rkhunter scdaemon tmux usb-creator-gtk usbguard wireguard
	elif [ "$VM" = "true" ]; then
		if (dmesg | grep -q 'vmware'); then
			apt install -y open-vm-tools-desktop
		fi
		apt install -y auditd apparmor-utils curl git hexedit libimage-exiftool-perl nmap pcscd python3-pip python3-venv resolvconf rkhunter scdaemon screen tmux usbguard wireguard wireshark
		snap install chromium
		snap install libreoffice
		snap install vlc
	fi
	echo -e "${BLUE}[+]${RESET}All essential packages installed.${RESET}"
	sleep 1
}

function addGroups() {
	# Applies to VM

	# Monitor && log execution of this or don't enable it.
	if (grep -q 'wireshark' /etc/group); then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}Add $UID1000 to wireshark group?"
		echo ""
		until [[ ${WIRESHARK_CHOICE} =~ ^(y|n)$ ]]; do
			read -rp "[y/n]: " WIRESHARK_CHOICE
		done
	fi
	if [[ $WIRESHARK_CHOICE == "y" ]]; then
		usermod -a -G wireshark "$UID1000"
		echo "Done."
		sleep 1
	elif [[ $WIRESHARK_CHOICE == "n" ]] && (groups "$UID1000" | grep -q wireshark); then
		echo -e "${BLUE}[i]${RESET}Remove $UID1000 from wireshark group?"
		until [[ ${WIRESHARK_REMOVE} =~ ^(y|n)$ ]]; do
			read -rp "[y/n]: " WIRESHARK_REMOVE
		done
		
		if [[ $WIRESHARK_REMOVE == "y" ]]; then
			deluser "$UID1000" wireshark
		fi
	fi
	
}

function removeGroups() {
	# Applies to VM, HW, VPS
	# Adjusts default user's groups to prevent non-root processes from reading system log files.
	if (groups "$UID1000" | grep -q ' adm '); then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}Removing user $UID1000 from administrative groups (adm)."
		deluser "$UID1000" adm
	fi
}

function setPostfix() {
	# Applies to VM, HW, VPS
	echo "======================================================================"
	# Prevents the postfix service from flagging the system as degraded if it's not configured.
	if (systemctl is-enabled postfix); then
		echo -e "${BLUE}[-]${RESET}Disabling postfix.service.${RESET}"
		systemctl disable postfix.service
	else
		echo -e "${BLUE}[i]${RESET}postfix.service already disabled. Skipping."
	fi
}

function setAIDE() {
	# Applies to VPS
	
	# Stops cron daily execution from altering database
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Checking aide's cron.daily execution (disabled, enable manually)."
	chmod -x '/etc/cron.daily/aide'

	if [ "$HW" = 'true' ] && ! [ -e "$AIDE_MACROS"/31_aide_home-dirs ]; then
		echo "!$HOME_DIR" > "$AIDE_MACROS"/31_aide_home-dirs
		echo -e "${GREEN}[+]${RESET}Adding AIDE policy file: $AIDE_MACROS/31_aide_home-dirs."
	else
		echo -e "${BLUE}[i]${RESET}AIDE policy file $AIDE_MACROS/31_aide_home-dirs already installed. Skipping."
	fi
}

function setRkhunter() {
	# Applies to VM, HW, VPS

	# Stops cron daily execution from altering database
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Checking rkhunter's cron.daily execution (disabled, enable manually)."
	chmod -x '/etc/cron.daily/rkhunter'

	if [ -e "$RKHUNTER_CONF" ]; then
		grep -q -x "DISABLE_TESTS=suspscan hidden_procs deleted_files apps" "$RKHUNTER_CONF" || (sed -i 's/^DISABLE_TESTS=.*$/DISABLE_TESTS=suspscan hidden_procs deleted_files apps/' "$RKHUNTER_CONF" && echo -e "${BLUE}[*]${RESET}Updating rkhunter test list.")
		grep -q -x "SCRIPTWHITELIST=/usr/bin/egrep" "$RKHUNTER_CONF" || (sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/egrep/SCRIPTWHITELIST=\/usr\/bin\/egrep/' "$RKHUNTER_CONF" && echo -e "${BLUE}[*]${RESET}Updating script whitelists. (1/5)")
		grep -q -x "SCRIPTWHITELIST=/usr/bin/fgrep" "$RKHUNTER_CONF" || (sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/fgrep/SCRIPTWHITELIST=\/usr\/bin\/fgrep/' "$RKHUNTER_CONF" && echo -e "${BLUE}[*]${RESET}Updating script whitelists. (2/5)")
		grep -q -x "SCRIPTWHITELIST=/usr/bin/which" "$RKHUNTER_CONF" || (sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/which/SCRIPTWHITELIST=\/usr\/bin\/which/' "$RKHUNTER_CONF" && echo -e "${BLUE}[*]${RESET}Updating script whitelists. (3/5)")
		grep -q -x "SCRIPTWHITELIST=/usr/bin/ldd" "$RKHUNTER_CONF" || (sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/ldd/SCRIPTWHITELIST=\/usr\/bin\/ldd/' "$RKHUNTER_CONF" && echo -e "${BLUE}[*]${RESET}Updating script whitelists. (4/5)")
		if [ "$VPS" = 'false' ]; then
			grep -q -x "SCRIPTWHITELIST=/usr/bin/lwp-request" "$RKHUNTER_CONF" || (sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/lwp-request/SCRIPTWHITELIST=\/usr\/bin\/lwp-request/' "$RKHUNTER_CONF" && echo -e "${BLUE}[*]${RESET}Updating script whitelists. (5/5)")
		fi
		grep -q -x "ALLOW_SSH_PROT_V1=0" "$RKHUNTER_CONF" || (sed -i 's/ALLOW_SSH_PROT_V1=2/ALLOW_SSH_PROT_V1=0/' "$RKHUNTER_CONF" && echo -e "${BLUE}[*]${RESET}Adding warning for detection of SSHv1 protocol.")
		grep -q -x '#WEB_CMD="/bin/false"' "$RKHUNTER_CONF" || (sed -i 's/WEB_CMD="\/bin\/false"/#WEB_CMD="\/bin\/false"/' "$RKHUNTER_CONF" && echo -e "${BLUE}[*]${RESET}Commenting out WEB_CMD="'"\/bin\/false"')
		rkhunter -C && echo -e "${GREEN}[+]${RESET}Reloading rkhunter profile."
	elif ! [ -e "$RKHUNTER_CONF" ]; then
		echo -e "${RED}"'[!]'"${RESET}rkhunter.conf file not found. Skipping."
	fi
}

function setSSH() {
	# Applies to VPS
	echo "======================================================================"
	if ! (grep -q -x 'PasswordAuthentication no' "$SSHD_CONF"); then
		# Removes example entry at the bottom of sshd_config
		sed -i 's/^PasswordAuthentication yes$//g' "$SSHD_CONF"
		sed -i 's/^.*PasswordAuthentication .*$/PasswordAuthentication no/g' "$SSHD_CONF" && echo -e "${GREEN}[+]${RESET}Prohibiting SSH password authentication."
	fi

	if ! (grep -q -x 'PermitRootLogin no' "$SSHD_CONF"); then
		sed -i 's/^#PermitRootLogin prohibit-password$/PermitRootLogin no/' "$SSHD_CONF" && echo -e "${GREEN}[+]${RESET}Prohibiting SSH root login."
	fi

	if ! (grep -q -x 'Protocol 2' "$SSHD_CONF"); then
		sed -i 's/^.*Port .*$/&\nProtocol 2/' "$SSHD_CONF" && echo -e "${GREEN}[+]${RESET}Prohibiting SSHv1 protocol."
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

	sed -i 's/.*Port .*$/Port '"${PORT}"'/' "$SSHD_CONF"

	echo ""
	ufw allow in on "$PUB_NIC" to any proto tcp port "${PORT}" comment 'ssh'
	echo -e "${GREEN}[+]${RESET}Added ufw rules for SSH port ${PORT}."
	echo ""
	echo "Restart sshd.service now?"
	echo ""
	echo "The current connection will remain established until exiting."
	echo "Confirm you can login via ssh from another terminal session"
	echo "after this script completes, and before exiting this current"
	echo "session."
	echo ""
	until [[ $SSHD_RESTART_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "[y/n]: " SSHD_RESTART_CHOICE
	done
	if [[ $SSHD_RESTART_CHOICE == "y" ]]; then

		systemctl restart sshd.service
		echo -e "${BLUE}[+]${RESET}Restarting sshd.service..."
	fi

	echo -e "${RED}"'[!]'"${RESET}${BOLD}Be sure to review all firewall rules before ending this session.${RESET}"
	sleep 3
}

function blockKmods() {
	# Applies to HW

	function blockFirewire() {

		echo "# Select the legacy firewire stack over the new CONFIG_FIREWIRE one.

blacklist ohci1394
blacklist sbp2
blacklist dv1394
blacklist raw1394
blacklist video1394

blacklist firewire-ohci
blacklist firewire-sbp2
blacklist firewire-core" >'/etc/modprobe.d/blacklist-firewire.conf'

	}

	function blockThunderbolt() {
		if [ -e '/etc/modprobe.d/blacklist-thunderbolt.conf' ]; then
			echo -e "${YELLOW}"'[!]'"${RESET}${BOLD}/etc/modprobe.d/blacklist-thunderbolt.conf already exists.${RESET}" 
			echo -e "${YELLOW}"'[!]'"${RESET}Holding current configuration for review."
			echo -e "${YELLOW}"'[!]'"${RESET}Only /etc/modprobe.d/blacklist-firewire.conf will be updated."

		else
			touch '/etc/modprobe.d/blacklist-thunderbolt.conf'
			echo "# Disable Thunderbolt ports. Comment to enable

	blacklist thunderbolt" >'/etc/modprobe.d/blacklist-thunderbolt.conf'
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
			update-initramfs -k all -u
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
			rm '/etc/modprobe.d/blacklist-thunderbolt.conf'
			echo -e "${BLUE}[-]${RESET}Resetting /etc/modprobe.d/blacklist-firewire.conf"
			echo "# Select the legacy firewire stack over the new CONFIG_FIREWIRE one.

blacklist ohci1394
blacklist sbp2
blacklist dv1394
blacklist raw1394
blacklist video1394

#blacklist firewire-ohci
#blacklist firewire-sbp2" >'/etc/modprobe.d/blacklist-firewire.conf'

			update-initramfs -k all -u

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
					sed -i 's/\(^.*\)lockdown=[^[:space:]]*\(.*\)/\1lockdown='"$LOCKDOWN_MODE"' \2/'  "$KERNEL_CMDLINE"
				else 
					# no lockdown=arg is present, append it
					# note the additional space between `\1` and `lockdown=`
					sed -i 's/\(^.*\)/\1 lockdown='"$LOCKDOWN_MODE"'/'  "$KERNEL_CMDLINE"
				fi
			# Otherwise default back to location to edit kernel commandline parameters on Ubuntu
			elif [ -e /etc/default/grub ]; then
				KERNEL_CMDLINE=/etc/default/grub
				if grep -q '^GRUB_CMDLINE_LINUX=.*lockdown=.*"'  "$KERNEL_CMDLINE" ; then
					# modify the GRUB command-line if a lockdown= arg already exists
					sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)lockdown=[^[:space:]]*\(.*"\)/\1 lockdown='"$LOCKDOWN_MODE"' \2/'  "$KERNEL_CMDLINE"
				else
					# no lockdown=arg is present, append it
					sed -i 's/\(^GRUB_CMDLINE_LINUX=".*\)"/\1 lockdown='"$LOCKDOWN_MODE"'"/'  "$KERNEL_CMDLINE"
				fi
				update-grub
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
	# Applies to VM,HW
	if ! [ -e "$HOME_DIR"/.gnupg/gpg.conf ]; then
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
throw-keyids" >"$HOME_DIR"/.gnupg/gpg.conf

			echo "enable-ssh-support
default-cache-ttl 60
max-cache-ttl 120
pinentry-program /usr/bin/pinentry-curses" >"$HOME_DIR"/.gnupg/gpg-agent.conf

			if ! (grep -qx '# enable gpg smart card support for ssh' "$HOME_DIR"/.bashrc); then
				echo '
# enable gpg smart card support for ssh
export GPG_TTY="$(tty)"
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
gpgconf --launch gpg-agent' >>"$HOME_DIR"/.bashrc
			fi
			chown -R "$UID1000":"$UID1000" "$HOME_DIR"/.gnupg/gpg*
		fi
	fi
}

function checkAppArmor() {
	# Applies to VM,HW,VPS

	echo "======================================================================"

	echo -e "${BLUE}[i]${RESET}Checking AppArmor profiles."

	if (command -v firefox); then
		if [ -e "/etc/apparmor.d/disable/usr.bin.firefox" ]; then
		    rm /etc/apparmor.d/disable/usr.bin.firefox
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
  deny /snap/ r," >"$AA_FIREFOX_LOCAL"

		apparmor_parser -r "$AA_FIREFOX"
	fi

	echo -e "${BLUE}[i]${RESET}Done."
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
	setPerms
	checkSudoers
	#removeBrowser
	stopServices
	#updateServices
	#addVBox
	setIpv6
	setFirewall
	checkPackages
	setResolver
	installPackages
	addGroups
	removeGroups
	setPostfix
	#setAIDE
	setRkhunter
	#setSSH
	#blockKmods
	setLockdown
	setGnupg
	checkAppArmor
}

function installHW() {
	echo ""
	HW='true'
	# Functions
	setPerms
	checkSudoers
	removeBrowser
	stopServices
	#updateServices
	addVBox
	setIpv6
	setFirewall
	checkPackages
	setResolver
	installPackages
	#addGroups
	removeGroups
	setPostfix
	#setAIDE
	setRkhunter
	#setSSH
	blockKmods
	setLockdown
	setGnupg
	#checkAppArmor
}

function installVPS() {
	echo ""
	VPS='true'
	# Functions
	setPerms
	checkSudoers
	#removeBrowser
	#stopServices
	updateServices
	#addVBox
	setIpv6
	setFirewall
	checkPackages
	setResolver
	installPackages
	#addGroups
	removeGroups
	setPostfix
	setAIDE
	setRkhunter
	setSSH
	#blockKmods
	setLockdown
	#setGnupg
	#checkAppArmor
}

manageMenu
