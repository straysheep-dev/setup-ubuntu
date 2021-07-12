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
AUDIT_DOCS=/usr/share/doc/auditd/examples/rules/
AUDITD_CONF=/etc/audit/auditd.conf
AUDIT_RULES_D=/etc/audit/rules.d/
ADDUSER_CONF=/etc/adduser.conf
AIDE_MACROS=/etc/aide/aide.conf.d/
HOME_DIR=/home/"${UID1000}"/
VBOX_APT_LIST=/etc/apt/sources.list.d/virtualbox.list
RKHUNTER_CONF=/etc/rkhunter.conf
SSHD_CONF=/etc/ssh/sshd_config
UFW_RULES=/etc/ufw/user.rules

NUM_LOGS=0
LOG_SIZE=0
LOG_FORMAT=0
LOCKDOWN_MODE=0

PUB_IPV4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
PUB_IPV6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
GTWY="$(ip route | grep "default" | cut -d " " -f3)"

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
	if  ! [ -e 'setup-ubuntu.sh' ]; then
		echo "To avoid issues, execute this script from it's current working directory. Quitting."
		exit 1
	fi
}
checkCwd

function checkOS() {
	# Check OS version
	source /etc/os-release
	OS="${VERSION_CODENAME}" # debian or ubuntu
	echo -e "${BLUE}[i]${RESET}Ubuntu '${VERSION_CODENAME}' detected."
	if [[ $ID == "ubuntu" ]]; then
		OS="ubuntu"
		MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
		if [[ $MAJOR_UBUNTU_VERSION -lt 18 ]]; then
			echo "⚠️ Your version of Ubuntu is not supported."
			echo ""
			echo "However, if you're using Ubuntu >= 16.04 or beta, then you can continue, at your own risk."
			echo ""
			until [[ $CONTINUE =~ (y|n) ]]; do
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
	if ! (grep -qx 'DIR_MODE=0750' "${ADDUSER_CONF}"); then
  		sed -i 's/DIR_MODE=0755/DIR_MODE=0750/' "${ADDUSER_CONF}"
  		chmod 750 "${HOME_DIR}"
		echo -e "${GREEN}[+]${RESET}User DAC policy updated successfully."
	else
		echo -e "${BLUE}[i]${RESET}User DAC policy already updated. Skipping."
	fi
}

function removeBrowser() {
	# Applies to HW
	echo "======================================================================"
	FF_LOCALE=$(dpkg --list | grep "firefox-locale" | cut -d ' ' -f 3)

	if ( dpkg --list | grep -q 'firefox' ); then
		echo ""
  		echo -e "${BLUE}[-]${RESET}Removing all Firefox package files."
		echo ""
		apt-get autoremove --purge -y firefox "${FF_LOCALE}"
		rm -rf /usr/lib/firefox*
	else
		echo -e "${BLUE}[i]${RESET}Default browser already removed. Skipping."
	fi
}


function stopServices() {
	# Applies to VM, HW
	echo "======================================================================"
	(pgrep cups-browsed &>/dev/null && systemctl stop cups-browsed.service && systemctl disable cups-browsed.service)
	(pgrep cups &>/dev/null && systemctl stop cups.service && systemctl disable cups.service)
	#NOTE: doesn't automate unless disabled first, then stopped
	(pgrep avahi-daemon &>/dev/null && systemctl disable avahi-daemon.service && systemctl stop avahi-daemon.service)
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
	until [[ $VBOX_CHOICE =~ (y|n) ]]; do
		read -rp "[y/n]: " VBOX_CHOICE
	done

	if [[ $VBOX_CHOICE == "y" ]]; then
		if ! [ -e "oracle_vbox_2016.asc" ]; then
			echo -e "${GREEN}[+]${RESET}Retrieving VirtualBox apt-key with Wget.${RESET}"
			(wget -O oracle_vbox_2016.asc 'https://www.virtualbox.org/download/oracle_vbox_2016.asc') || (echo -e "${RED}"'[!]'"${RESET}Unable to retrieve Oracle VirtualBox signing key.${RESET}" && rm oracle_vbox_2016.asc)
		fi
		if [ -e "oracle_vbox_2016.asc" ]; then
			echo -e "${GREEN}[+]${RESET}Adding VirtualBox apt-key from local file.${RESET}"
			echo -e "${GREEN}[+]${RESET}VirtualBox sources.list created at ${VBOX_APT_LIST}."
			apt-key add oracle_vbox_2016.asc
			echo "deb [arch=amd64] https://download.virtualbox.org/virtualbox/debian ${VERSION_CODENAME} contrib" >"${VBOX_APT_LIST}"
		fi
	elif [[ $VBOX_CHOICE == "n" ]] && [ -e "${VBOX_APT_LIST}" ]; then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}Looks like the VirtualBox gpg key is present."
		echo "Remove Oracle's VirtualBox apt repository and key from keyring?"
		echo ""
		until [[ $REMOVE_VBOX =~ (y|n) ]]; do
			read -rp "[y/n]: " REMOVE_VBOX
		done

		if [[ $REMOVE_VBOX == "y" ]]; then
			rm "${VBOX_APT_LIST}"
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
	until [[ $IPV6_CHOICE =~ (y|n) ]]; do
		read -rp "[y/n]: " IPV6_CHOICE
	done
	if [[ $IPV6_CHOICE == "y" ]]; then
		sed -i 's/^IPV6=yes$/IPV6=no/' /etc/default/ufw
	elif [[ $IPV6_CHOICE == "n" ]] && (grep -qx 'IPV6=no' /etc/default/ufw) ; then
		sed -i 's/^IPV6=no$/IPV6=yes/' /etc/default/ufw
	fi
}

function setFirewall() {
	# Applies to VM, HW, VPS
	echo "======================================================================"
	echo "Would you like to modify the firewall rules?"
	echo -e "${YELLOW}[i]${RESET}WARNING: risk of lock-out if this is a remote connection."
	echo ""
	echo -e "${RED}[i]${RESET}(choose 'y' if you've changed ipv6 settings above)"
	until [[ $UFW_CHOICE =~ (y|n) ]]; do
		read -rp "[y/n]: " UFW_CHOICE
	done
	if [[ $UFW_CHOICE == "y" ]]; then

		echo -e "${BLUE}[i]${RESET}Setting up firewall egress policy (answer 'y' below to continue)."
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
		ufw allow out on "${PUB_NIC}" to any proto tcp port 80,443
		ufw allow out on "${PUB_NIC}" to any proto udp port 53
		ufw prepend deny out to 192.168.0.0/16
		ufw prepend deny out to 172.16.0.0/12
		ufw prepend deny out to 169.254.0.0/16
		ufw prepend deny out to 10.0.0.0/8
		ufw prepend deny out on "${PUB_NIC}" to 127.0.0.0/8
		if (grep -qx 'IPV6=yes' /etc/default/ufw); then
			ufw prepend deny out to fc00::/7
			ufw prepend deny out on "${PUB_NIC}" to ::1
		fi
		if echo "$GTWY" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
			ufw prepend allow out on "${PUB_NIC}" to "${GTWY}"
			if (dmesg | grep -q 'VirtualBox') && (echo "$GTWY" | grep -qx 10.0.2.2); then
				ufw insert 2 allow out on "${PUB_NIC}" to '10.0.2.3'
			fi
		fi
		echo -e "${BLUE}[+]${RESET}Basic firewall egress rules are live."
	fi
}

function updatePackages() {
	# Applies to VM, HW, VPS
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Updating packages."
	apt update
	apt upgrade -y
	sleep 1
	echo ""
	echo -e "${BLUE}[i]${RESET}Autoremoving packages."
	apt autoremove -y
}

function installPackages() {
	# Applies to VM, HW, VPS
	
	echo -e ""
	echo -e "${BLUE}[i]${RESET}Beginning installation of essential packages."
	if [ "${VPS}" = "true" ]; then
		apt install -y aide auditd easy-rsa openvpn qrencode resolvconf rkhunter wireguard
	elif [ "${HW}" = "true" ]; then
		apt install -y auditd apparmor-utils curl git pcscd resolvconf rkhunter scdaemon usb-creator-gtk usbguard wireguard
	elif [ "${VM}" = "true" ]; then
		if (dmesg | grep -q 'vmware'); then
			apt install -y open-vm-tools-desktop
		fi
		apt install -y auditd apparmor-utils curl git hexedit nmap pcscd python3-pip python3-venv rkhunter scdaemon usbguard wireshark
	fi
	echo -e "${BLUE}[+]${RESET}All essential packages installed.${RESET}"
	sleep 1
}

function addGroups() {
	# Applies to VM

	# Monitor && log execution of this or don't enable it.
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Allow Wireshark to capture traffic?"
	echo -e "${BOLD}This runs dpkg-reconfigure wireshark-common twice.${RESET}"
	echo -e "Answering 'yes' then 'no' will create the system group without permitting capture"
	echo ""
	until [[ ${WIRESHARK_CHOICE} =~ (y|n) ]]; do
		read -rp "[y/n]: " WIRESHARK_CHOICE
	done
	if [[ $WIRESHARK_CHOICE == "y" ]]; then
		dpkg-reconfigure wireshark-common
		echo -e "${BLUE}[i]${RESET}Adding user ${UID1000} to group 'wireshark'."
		sleep 2
		if ! (groups "${UID1000}" | grep -q wireshark); then
			usermod -a -G wireshark "${UID1000}"
		fi
		dpkg-reconfigure wireshark-common
	fi
}

function removeGroups() {
	# Applies to VM, HW, VPS
	# Adjusts default user's groups to prevent non-root processes from reading system log files.
	if (groups "${UID1000}" | grep -q ' adm '); then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}Removing user ${UID1000} from administrative groups (adm)."
		deluser "${UID1000}" adm
	fi
}

function setPostfix() {
	# Applies to VM, HW, VPS
	echo "======================================================================"
	# Prevents the postfix service from flagging the system as degraded if it's not configured.
	if [ -e '/etc/systemd/system/multi-user.target.wants/postfix.service' ]; then
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

	if [ "${HW}" = 'true' ] && ! [ -e "${AIDE_MACROS}"31_aide_home-dirs ]; then
		echo "!${HOME_DIR}" > "${AIDE_MACROS}"31_aide_home-dirs
		echo -e "${GREEN}[+]${RESET}Adding AIDE policy file: '${AIDE_MACROS}31_aide_home-dirs'."
	elif [ "${HW}" = 'true' ] && [ -e "${AIDE_MACROS}"31_aide_home-dirs ]; then
		echo -e "${BLUE}[i]${RESET}AIDE policy file '${AIDE_MACROS}31_aide_home-dirs' already installed. Skipping."
	fi
}

function setRkhunter() {
	# Applies to VM, HW, VPS

	# Stops cron daily execution from altering database
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Checking rkhunter's cron.daily execution (disabled, enable manually)."
	chmod -x '/etc/cron.daily/rkhunter'

	if [ -e "${RKHUNTER_CONF}" ]; then
		grep -q -x "DISABLE_TESTS=suspscan deleted_files apps" "${RKHUNTER_CONF}" || (sed -i 's/DISABLE_TESTS=suspscan hidden_ports hidden_procs deleted_files packet_cap_apps apps/DISABLE_TESTS=suspscan deleted_files apps/' "${RKHUNTER_CONF}" && echo -e "${BLUE}[*]${RESET}Updating rkhunter test list.")
		grep -q -x "SCRIPTWHITELIST=/usr/bin/egrep" "${RKHUNTER_CONF}" || (sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/egrep/SCRIPTWHITELIST=\/usr\/bin\/egrep/' "${RKHUNTER_CONF}" && echo -e "${BLUE}[*]${RESET}Updating script whitelists. (1/5)")
		grep -q -x "SCRIPTWHITELIST=/usr/bin/fgrep" "${RKHUNTER_CONF}" || (sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/fgrep/SCRIPTWHITELIST=\/usr\/bin\/fgrep/' "${RKHUNTER_CONF}" && echo -e "${BLUE}[*]${RESET}Updating script whitelists. (2/5)")
		grep -q -x "SCRIPTWHITELIST=/usr/bin/which" "${RKHUNTER_CONF}" || (sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/which/SCRIPTWHITELIST=\/usr\/bin\/which/' "${RKHUNTER_CONF}" && echo -e "${BLUE}[*]${RESET}Updating script whitelists. (3/5)")
		grep -q -x "SCRIPTWHITELIST=/usr/bin/ldd" "${RKHUNTER_CONF}" || (sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/ldd/SCRIPTWHITELIST=\/usr\/bin\/ldd/' "${RKHUNTER_CONF}" && echo -e "${BLUE}[*]${RESET}Updating script whitelists. (4/5)")
		if [ "${VPS}" = 'false' ]; then
			grep -q -x "SCRIPTWHITELIST=/usr/bin/lwp-request" "${RKHUNTER_CONF}" || (sed -i 's/#SCRIPTWHITELIST=\/usr\/bin\/lwp-request/SCRIPTWHITELIST=\/usr\/bin\/lwp-request/' "${RKHUNTER_CONF}" && echo -e "${BLUE}[*]${RESET}Updating script whitelists. (5/5)")
		fi
		grep -q -x "ALLOW_SSH_PROT_V1=0" "${RKHUNTER_CONF}" || (sed -i 's/ALLOW_SSH_PROT_V1=2/ALLOW_SSH_PROT_V1=0/' "${RKHUNTER_CONF}" && echo -e "${BLUE}[*]${RESET}Adding warning for detection of SSHv1 protocol.")
		grep -q -x '#WEB_CMD="/bin/false"' "${RKHUNTER_CONF}" || (sed -i 's/WEB_CMD="\/bin\/false"/#WEB_CMD="\/bin\/false"/' "${RKHUNTER_CONF}" && echo -e "${BLUE}[*]${RESET}Commenting out WEB_CMD="'"\/bin\/false"')
		rkhunter -C && echo -e "${GREEN}[+]${RESET}Reloading rkhunter profile."
	elif ! [ -e "${RKHUNTER_CONF}" ]; then
		echo -e "${RED}"'[!]'"${RESET}rkhunter.conf file not found. Skipping."
	fi
}

function setSSH() {
	# Applies to VPS
	echo "======================================================================"
	if ! (grep -q -x 'PasswordAuthentication no' "${SSHD_CONF}"); then
		# Removes example entry at the bottom of sshd_config
		sed -i 's/^PasswordAuthentication yes$//g' "${SSHD_CONF}"
		sed -i 's/^.*PasswordAuthentication .*$/PasswordAuthentication no/g' "${SSHD_CONF}" && echo -e "${GREEN}[+]${RESET}Prohibiting SSH password authentication."
	fi

	if ! (grep -q -x 'PermitRootLogin no' "${SSHD_CONF}"); then
		sed -i 's/^#PermitRootLogin prohibit-password$/PermitRootLogin no/' "${SSHD_CONF}" && echo -e "${GREEN}[+]${RESET}Prohibiting SSH root login."
	fi

	if ! (grep -q -x 'Protocol 2' "${SSHD_CONF}"); then
		sed -i 's/^.*Port .*$/&\nProtocol 2/' "${SSHD_CONF}" && echo -e "${GREEN}[+]${RESET}Prohibiting SSHv1 protocol."
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

	sed -i 's/.*Port .*$/Port '"${PORT}"'/' "${SSHD_CONF}"

	echo ""
	ufw allow in on "${PUB_NIC}" to any proto tcp port "${PORT}" comment 'ssh'
	echo -e "${GREEN}[+]${RESET}Added ufw rules for SSH port ${PORT}."
	echo ""
	echo "Restart sshd.service now?"
	echo ""
	echo "The current connection will remain established until exiting."
	echo "Confirm you can login via ssh from another terminal session"
	echo "after this script completes, and before exiting this current"
	echo "session."
	echo ""
	until [[ $SSHD_RESTART_CHOICE =~ (y|n) ]]; do
		read -rp "[y/n]: " SSHD_RESTART_CHOICE
	done
	if [[ $SSHD_RESTART_CHOICE == "y" ]]; then

		systemctl restart sshd.service
		echo -e "${BLUE}[+]${RESET}Restarting sshd.service..."
	fi

	echo -e "${RED}"'[!]'"${RESET}${BOLD}Be sure to review any and all firewall rules before disonnecting from this session.${RESET}"
}

function blockFirewire() {
	# Applies to HW

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
	# Applies to HW
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

function blockKmods() {
	# Applies to HW

	# This needs fixed in case a blacklist-thunderbolt.conf ever ships by default
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Block thunderbolt and firewire kernel modules?" 
	echo "(prevents connected devices from loading)"
	echo ""
	until [[ $KMOD_CHOICE =~ (y|n) ]]; do
		read -rp "[y/n]: " KMOD_CHOICE
	done

 	if [[ $KMOD_CHOICE == "y" ]]; then
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
	echo "======================================================================"
	if ! (mokutil --sb-state | grep -qx 'SecureBoot enabled'); then
		echo ""
		echo -e "${BLUE}[i]${RESET}SecureBoot is not enabled."
		echo -e "${BLUE}[i]${RESET}Update kernel lockdown mode? (modifies GRUB_CMDLINE_LINUX in /etc/default/grub)"
		echo -e "${BLUE}[i]${RESET}Current state: "
		if (cat /sys/kernel/security/lockdown | grep -E "\[none\]|\[integrity\]|\[confidentiality\]"); then
			echo ""
			until [[ $LOCKDOWN_CHOICE =~ (y|n) ]]; do
				read -rp "[y/n]: " LOCKDOWN_CHOICE
			done
			if [[ $LOCKDOWN_CHOICE == "y" ]]; then

				echo ""
				echo "Which mode?"
				echo ""
				until [[ $LOCKDOWN_MODE =~ (none|integrity|confidentiality) ]]; do
					read -rp "[none|integrity|confidentiality]: " LOCKDOWN_MODE
				done

				sed -i 's/GRUB_CMDLINE_LINUX=".*"/GRUB_CMDLINE_LINUX="lockdown='"${LOCKDOWN_MODE}"'"/g' /etc/default/grub
				echo -e "${BLUE}[i]${RESET}Updating grub..."
				sudo update-grub
				echo -e "${BLUE}[i]${RESET}Lockdown mode changes won't take effect until next reboot."
			fi
		fi
	fi
}

function setGnupg() {
	# Applies to VM,HW
	if ! [ -e "${HOME_DIR}"/.gnupg/gpg.conf ]; then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}GnuPG"
		echo "Harden gpg.conf and add smart card support for ssh to .bashrc file?"
		echo ""
		until [[ $GPG_CHOICE =~ (y|n) ]]; do
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
throw-keyids" >"${HOME_DIR}"/.gnupg/gpg.conf

			echo "enable-ssh-support
default-cache-ttl 60
max-cache-ttl 120
pinentry-program /usr/bin/pinentry-curses" >"${HOME_DIR}"/.gnupg/gpg-agent.conf

			if !(grep -qx '# enable gpg smart card support for ssh' "${HOME_DIR}"/.bashrc); then
				echo '
# enable gpg smart card support for ssh
export GPG_TTY="$(tty)"
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
gpgconf --launch gpg-agent' >>"${HOME_DIR}"/.bashrc
			fi
			chown "${UID1000}" "${HOME_DIR}"/.gnupg/gpg*
			chgrp "${UID1000}" "${HOME_DIR}"/.gnupg/gpg*
		fi
	fi
}

function updateAppArmor() {
	# Applies to VM
	echo "======================================================================"
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
  deny /snap/ r," >"${AA_FIREFOX_LOCAL}"

	apparmor_parser -r "${AA_FIREFOX}"
  
  	echo -e "${BLUE}[i]${RESET}Checking Firefox AppArmor profile."
}

function setPolicies() {
	# Applies to VM

	# Policy files
	FF_CFG="firefox.cfg"
	FF_AUTOJS="autoconfig.js"
	FF_POLICY_JSON="policies.json"
	# Install policies
	echo -e "${BLUE}[i]${RESET}Checking Firefox policy files."

	if ! [ -e "/usr/lib/firefox/${FF_CFG}" ] && [ "${VM}" = "true" ]; then
		chmod 644 "${FF_CFG}" && cp "${FF_CFG}" -t /usr/lib/firefox/ 2>/dev/null && rm "${FF_CFG}" && echo -e "${GREEN}[+]${RESET}Installing ${FF_CFG}." || echo -e "${RED}"'[!]'"Missing ${FF_CFG}, and cannot locate policy file to install.${RESET}"
	fi
	if ! [ -e "/usr/lib/firefox/defaults/pref/${FF_AUTOJS}" ] && [ "${VM}" = "true" ]; then
		chmod 644 "${FF_AUTOJS}" && cp "${FF_AUTOJS}" -t /usr/lib/firefox/defaults/pref/ 2>/dev/null && rm "${FF_AUTOJS}" && echo -e "${GREEN}[+]${RESET}Installing ${FF_AUTOJS}." || echo -e "${RED}"'[!]'"Missing ${FF_AUTOJS}, and cannot locate policy file to install.${RESET}"
	fi
	if ! [ -e "/usr/lib/firefox/distribution/${FF_POLICY_JSON}" ] && [ "${VM}" = "true" ]; then
		chmod 644 "${FF_POLICY_JSON}" && cp "${FF_POLICY_JSON}" -t /usr/lib/firefox/distribution/ 2>/dev/null && rm "${FF_POLICY_JSON}" && echo -e "${GREEN}[+]${RESET}Installing ${FF_POLICY_JSON}." || echo -e "${RED}"'[!]'"Missing ${FF_POLICY_JSON}, and cannot locate policy file to install.${RESET}"
	fi
}


function makeTemp() {
	export SETUPAUDITDIR=$(mktemp -d)
	if (ls -l | grep -q "40-.*.rules"); then
		cp 40-*.rules $SETUPAUDITDIR
	fi
	cd $SETUPAUDITDIR
	echo ""
	echo -e "${BLUE}[i]${RESET}Changing working directory to $SETUPAUDITDIR"

}

function checkCurrentRules() {
	# Save any potentialy custom rules
	if $(ls "${AUDIT_RULES_D}" | grep -q ".rules"); then
		echo "======================================================================"
		echo -e "${BLUE}[i]${RESET}Custom rule file(s) discovered:"
		echo "$(ls ${AUDIT_RULES_D} | grep 40-.*.rules || echo 'none')"
		echo ""
		echo -e "${RED}[i]${RESET}NOTE: Proceeding removes all currently installed rules."
		echo -e "${RED}[i]${RESET}Ctrl+C here to abort"
		echo ""
		until [[ $MERGE_CURRENT_RULE =~ (y|n) ]]; do
			read -rp "Merge current custom rule files into next rule set? [y/n]: " -e -i n MERGE_CURRENT_RULE
		done
		if [[ $MERGE_CURRENT_RULE == "n" ]]; then
			rm ${AUDIT_RULES_D}*
		elif [[ $MERGE_CURRENT_RULE == "y" ]]; then
			echo "##-------- Begin previously installed local rules --------" > 40-current-rules-to-merge.rules
			cat "${AUDIT_RULES_D}"40-*.rules >> 40-current-rules-to-merge.rules
			echo "##-------- End previously installed local rules --------" >> 40-current-rules-to-merge.rules
			rm ${AUDIT_RULES_D}*
		fi
	# Reset all other rules
	else
		rm ${AUDIT_RULES_D}* 2>/dev/null
	fi
}

function setLogFormat() {
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Set the logging format"
	echo -e "${BOLD}RAW${RESET} = Machine-readable"
	echo -e "${BOLD}ENRICHED${RESET} = Human-readable"
	echo ""
	until [[ $LOG_FORMAT =~ (RAW|ENRICHED) ]]; do
		read -rp "log_format = " -e -i ENRICHED LOG_FORMAT
	done
}

function setLogSize() {
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Set the ${BOLD}file size${RESET} of each log"
	echo -e "${BLUE}[i]${RESET}Default setting: ${BOLD}8${RESET} (8MB)"
	echo ""
	until [[ $LOG_SIZE =~ ^[0-9]+$ ]] && [ "$LOG_SIZE" -ge 1 ] && [ "$LOG_SIZE" -le 50 ]; do
		read -rp "max_log_file = " -e -i 8 LOG_SIZE
	done
}

function setLogNumber() {
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Set the number of log files to maintain locally"
	echo -e "${BLUE}[i]${RESET}Default setting: ${BOLD}8${RESET}"
	echo ""
	echo "NOTE: use more than 8 logs if you are unable to ship"
	echo "them to a central logging server." 
	echo ""
	until [[ $NUM_LOGS =~ ^[0-9]+$ ]] && [ "$NUM_LOGS" -ge 1 ] && [ "$NUM_LOGS" -le 65535 ]; do
		read -rp "num_logs = " -e -i 8 NUM_LOGS
	done
}

function setBuffer() {
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Set auditd's buffer size"
	echo -e "${BLUE}[i]${RESET}For busy systems, increase and test this number"
	echo -e "${BLUE}[i]${RESET}Default setting: ${BOLD}8192${RESET}"
	echo ""
	echo "NOTE: 8192 is a good choice for workstations."
	until [[ $BUFFER_SIZE =~ ^[0-9]+$ ]] && [ "$BUFFER_SIZE" -ge 1 ] && [ "$BUFFER_SIZE" -le 65535 ]; do
		read -rp "buffer_size (-b) = " -e -i 8192 BUFFER_SIZE
	done
}

function setSiteRules() {
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Set site-specific rules"
	echo "The default policy templates that ship with auditd include:"
	echo -e "${BOLD}	nispom | ospp | pci | stig | none${RESET}"
	echo "If not using custom rules, stig is a good choice"
	echo "If custom rules will be installed, choosing none is recommended"
	echo ""
	until [[ $SITE_RULES =~ (nispom|ospp|pci|stig|none) ]]; do
			read -rp "Enter a choice (lowercase): " -e -i none SITE_RULES
	done
}

function checkLocalRules() {
	# Check to make sure user's custom/local rules are present 
	if [[ ${SITE_RULES} == 'none' ]]; then
		if ! (ls | grep -q '40-'); then
			echo -e "${RED}[i]${RESET}No custom rules found in CWD, quitting."
			exit 1
		fi
	fi
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Auditd expects custom rules to be named ${BOLD}'40-<name>.rules'${RESET}"
	echo -e "${BLUE}[i]${RESET}Be sure all rules are compatible and in the CWD before proceeding."
	echo -e "${BLUE}[i]${RESET}If needed, Ctrl+c quit here to make changes, then rerun this script."
	echo ""
	until [[ ${COMBINE_RULES_OK} =~ ^(OK)$ ]]; do
		read -rp "Type 'OK' then press enter to continue > " COMBINE_RULES_OK
	done
	echo "======================================================================"
}

function collectAllRules() {
	# Gather all rule files to cwd
	BASE="${AUDIT_DOCS}10-base-config.rules"
	LOGINUID="${AUDIT_DOCS}11-loginuid.rules"
	NO32BIT="${AUDIT_DOCS}21-no32bit.rules"
	LOCAL="$(pwd)/40-*.rules"
	CONTAINER="${AUDIT_DOCS}41-containers.rules"
	INJECT="${AUDIT_DOCS}42-injection.rules"
	KMOD="${AUDIT_DOCS}43-module-load.rules"
	NET="${AUDIT_DOCS}71-networking.rules"
	FIN="${AUDIT_DOCS}99-finalize.rules"

	cp "${BASE}" "${LOGINUID}" "${NO32BIT}" "${CONTAINER}" "${INJECT}" "${KMOD}" "${NET}" "${FIN}" .

	# Site rules need gathered separately, too many ospp rules for one variable?
	if [[ ${SITE_RULES} == 'nispom' ]]; then
		cp "${AUDIT_DOCS}"30-nispom*.rules* .
	elif [[ ${SITE_RULES} == 'pci' ]]; then
		cp "${AUDIT_DOCS}"30-pci*.rules* .
	elif [[ ${SITE_RULES} == 'ospp' ]]; then
		cp "${AUDIT_DOCS}"$(ls "${AUDIT_DOCS}" | grep "30-ospp-v[0-9][0-9].rules*") .
	elif [[ ${SITE_RULES} == 'stig' ]]; then
		cp "${AUDIT_DOCS}"30-stig*.rules* .
	elif [[ ${SITE_RULES} == 'none' ]]; then
		echo "## Site specific rules placeholder file" > 30-site.rules
	fi

	# Gunzip package rules if they're archived
	if [ -e *.rules.gz ]; then
		gunzip *.rules.gz
	fi

	# Use default local rules placeholder if none / no custom rules are present
	if ! (ls | grep -q '40-'); then
		cp "${AUDIT_DOCS}40-local.rules" .
	fi
}

function applySettings() {
	# Apply the settings chosen by user during setup
	# /etc/audit/auditd.conf changes:
	if [ -e "${AUDITD_CONF}" ]; then
		echo ""
		grep -q -x "log_format = ${LOG_FORMAT}" "${AUDITD_CONF}" || (sed -i 's/^log_format = .*$/log_format = '"${LOG_FORMAT}"'/' "${AUDITD_CONF}")
		grep -q -x "num_logs = ${NUM_LOGS}" "${AUDITD_CONF}" || (sed -i 's/^num_logs = .*$/num_logs = '"${NUM_LOGS}"'/' "${AUDITD_CONF}")
		grep -q -x "max_log_file = ${LOG_SIZE}" "${AUDITD_CONF}" || (sed -i 's/^max_log_file = .*$/max_log_file = '"${LOG_SIZE}"'/' "${AUDITD_CONF}")
	else
		echo -e "${RED}[!]Missing auditd.conf file.${RESET}"
		exit 1
	fi
	# Next, set the buffer size in 10-base-config.rules, if this file is missing we'll see below
	if [ -e 10-base-config.rules ]; then
		sed -i 's/^-b.*$/-b '"${BUFFER_SIZE}"'/' 10-base-config.rules
	fi
}

function adjustRules() {
	# Make any adjustments to the built in rule files from /usr/share/**rules here
	# This will need a better solution going forward

	# Offer to comment out non-essential built in rules if using a local/custom rules file
	if [[ ${SITE_RULES} == 'none' ]]; then
		echo "To avoid overlap with custom rules, would you like"
		echo "comment out the non-essential built in rules?"
		echo ""
		until [[ $COMMENT_BUILTINS =~ (y|n) ]]; do
			read -rp "[y/n]?: " -e -i y COMMENT_BUILTINS
		done
	fi
	if [[ $COMMENT_BUILTINS == 'y' ]]; then
		sed -i 's/^-a/#-a/' "21-no32bit.rules"
		sed -i 's/^-a/#-a/' "42-injection.rules"
		sed -i 's/^-a/#-a/' "43-module-load.rules"
		sed -i 's/^-a/#-a/' "71-networking.rules"
	fi
}

function setAuditing() {
	# Putting everything together

	# Set rules to be immutable
	sed -i 's/#-e 2/-e 2/' "99-finalize.rules"

	# Remove placeholder policy file
	if [ -e "${AUDIT_RULES_D}"audit.rules ]; then
		rm "${AUDIT_RULES_D}"audit.rules
	fi

	RULES[0]="10-base-config.rules"
	RULES[1]="11-loginuid.rules"
	RULES[2]="21-no32bit.rules"
	RULES[3]="30-*.rules"
	RULES[4]="40-*.rules"
	RULES[5]="41-containers.rules"
	RULES[6]="42-injection.rules"
	RULES[7]="43-module-load.rules"
	RULES[8]="71-networking.rules"
	RULES[9]="99-finalize.rules"

	for RULE in ${RULES[@]}; do
		if [[ -e "${RULE}" ]]; then
			chmod 440 "${RULE}" && cp "${RULE}" -t "${AUDIT_RULES_D}" 2>/dev/null && rm "${RULE}" && echo -e "${GREEN}[+]${RESET}${BOLD}Installing ${RULE}${RESET}"
		else
			echo -e "${RED}[!]Missing ${RULE}, and cannot locate rule file to install.${RESET}"
		fi
	done

	# Cleanup
	cd /tmp && \
	rm -rf $SETUPAUDITDIR

	# Check for any errors
	echo ""
	echo -e "${GREEN}[i]${RESET}Running augenrules --check"
	augenrules --check 2>&1
	echo -e "${GREEN}[i]${RESET}Running augenrules --load to update rules"
	augenrules --load 2>&1
	echo "======================================================================"
	echo -e "${BLUE}[^]${RESET}Any errors above this line should be fixed in their rule file"
	echo -e "${BLUE}[^]${RESET}Review the line numbers called out in /etc/audit/audit.rules"
	echo -e "${BLUE}[^]${RESET}Rerun this script choosing to NOT merge the current (broken) rules"

	echo ""
	echo -e "${BLUE}[>]${RESET}${BOLD}Log format = ${LOG_FORMAT}${RESET}"
	echo -e "${BLUE}[>]${RESET}${BOLD}Log file size = ${LOG_SIZE}MB${RESET}"
	echo -e "${BLUE}[>]${RESET}${BOLD}Number of logs = ${NUM_LOGS}${RESET}"
	echo -e "${BLUE}[>]${RESET}${BOLD}Buffer size = ${BUFFER_SIZE}${RESET}"
	echo ""
	echo -e "${BLUE}[✓]${RESET}Done. Reminder: auditd rules aren't locked until ${BOLD}after${RESET} next reboot."
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
	#Functions
	setPerms
	#removeBrowser
	stopServices
	#updateServices
	#addVBox
	setIpv6
	setFirewall
	updatePackages
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
	updateAppArmor
	setPolicies
	makeTemp
	checkCurrentRules
	setLogFormat
	setLogSize
	setLogNumber
	setBuffer
	setSiteRules
	checkLocalRules
	collectAllRules
	applySettings
	adjustRules
	setAuditing
}

function installHW() {
	echo ""
	HW='true'
	#Functions
	setPerms
	removeBrowser
	stopServices
	#updateServices
	addVBox
	setIpv6
	setFirewall
	updatePackages
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
	#updateAppArmor
	#setPolicies
	makeTemp
	checkCurrentRules
	setLogFormat
	setLogSize
	setLogNumber
	setBuffer
	setSiteRules
	checkLocalRules
	collectAllRules
	applySettings
	adjustRules
	setAuditing
}

function installVPS() {
	echo ""
	VPS='true'
	#Functions
	setPerms
	#removeBrowser
	#stopServices
	updateServices
	#addVBox
	setIpv6
	setFirewall
	updatePackages
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
	#updateAppArmor
	#setPolicies
	makeTemp
	checkCurrentRules
	setLogFormat
	setLogSize
	setLogNumber
	setBuffer
	setSiteRules
	checkLocalRules
	collectAllRules
	applySettings
	adjustRules
	setAuditing
}

manageMenu
