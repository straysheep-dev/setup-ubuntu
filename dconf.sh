#!/bin/bash

# To test keys use `dconf read/write` not `gsettings`

# The profile file itself must be named 'user' -> /etc/dconf/profile/user
# user-db:<name> must also be named 'user'
# system-db:<name> can be any name

BLUE="\033[01;34m"     # Information
RESET="\033[00m"       # Reset

UID1000="$(grep 1000 /etc/passwd | cut -d ':' -f 1)"
MAJOR_UBUNTU_VERSION=$(grep VERSION_ID /etc/os-release | cut -d '"' -f2 | cut -d '.' -f 1)

# Locked key / value pairs are still changeable on 18.04 for some reason.
if [[ $MAJOR_UBUNTU_VERSION -lt 20 ]]; then
	echo "[i] Some settings aren't locking on 18.04. Use gsettings.sh"
	echo "Quitting..."
	exit 1
fi


function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}
isRoot

# Create a dconf profile
if ! [ -e /etc/dconf/profile/user ]; then
	echo "[i]Creating dconf user profile..."
	echo "user-db:user
system-db:site" > /etc/dconf/profile/user
fi

if ! [ -e /etc/dconf/db/site.d ]; then
	echo "[i]Creating dconf site database..."
	mkdir /etc/dconf/db/site.d
	mkdir /etc/dconf/db/site.d/locks
fi

DCONFS=/etc/dconf/db/site.d
LOCKS=/etc/dconf/db/site.d/locks


#======================================================================
# User Preferences (may need to make these in /etc/dconf/db/local.d? not working under user's home dir...)

# See /usr/share/glib-2.0/schemas/org.gnome.Terminal.gschema.xml
# See dconf list /org/gnome/terminal
# See dconf read /org/gnome/terminal/[..]/next-tab
# Some settings require a literal path
# Sets the hotkey combination of Ctrl+Shift+Left/Right Arrows to change terminal tabs
#org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ prev-tab '<Primary><Shift>Left'
#org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ next-tab '<Primary><Shift>Right'

# Auto-hide the dock
#org.gnome.shell.extensions.dash-to-dock dock-fixed 'false'

# NOTE: these are likely overridden when disabling apport and kernel memory dumping
# Don't automatically send techincal reports, but prompt user for OK
# Crash reports still generate under /var/crash/ to review
#org.gnome.desktop.privacy report-technical-problems 'false'
#org.gnome.desktop.privacy send-software-usage-stats 'false'


#======================================================================
# System-wide Locked Settings

echo '# Disable autorun and automount of software and external media
[org/gnome/desktop/media-handling]
autorun-never=true
automount=false
automount-open=false' > "$DCONFS"/00_media-handling
echo '# Disable autorun and automount of software and external media
/org/gnome/desktop/media-handling/automount
/org/gnome/desktop/media-handling/automount-open
/org/gnome/desktop/media-handling/autorun-never' > "$LOCKS"/media-handling
echo -e "${BLUE}[i]${RESET}Automount disabled"
echo -e "${BLUE}[i]${RESET}Autorun disabled"


echo '# Enable screen locking
[org/gnome/desktop/screensaver]
lock-enabled=true' > "$DCONFS"/00_screen-lock
echo '# Enable screen locking
/org/gnome/desktop/screensaver/lock-enabled' > "$LOCKS"/screen-lock
echo -e "${BLUE}[i]${RESET}Screenlock enabled"


echo "# Idle timeout for screen lock
[org/gnome/desktop/session]
idle-delay='uint32 300'" > "$DCONFS"/00_screen-idle-lock
echo '# Idle timeout for screen lock
/org/gnome/desktop/session/idle-delay' > "$LOCKS"/screen-idle-lock
echo -e "${BLUE}[i]${RESET}Screenlock on idle enabled"


echo "# Prevent notifications from appearing in the lock screen
[org/gnome/desktop/notifications]
show-in-lock-screen='false'" > "$DCONFS"/00_notifications
echo '# Prevent notifications from appearing in the lock screen
/org/gnome/desktop/notifications/show-in-lock-screen' > "$LOCKS"/notifications
echo -e "${BLUE}[i]${RESET}Notifications on lock screen disabled"


echo '# Show hidden files and folders
[org/gtk/settings/file-chooser]
show-hidden=true' > "$DCONFS"/00_show-hidden
echo '# Show hidden files and folders
/org/gtk/settings/file-chooser/show-hidden' > "$LOCKS"/show-hidden
echo -e "${BLUE}[i]${RESET}Show hidden files enabled"


echo '# Disable location settings
[org/gnome/system/location]
enabled=false' > "$DCONFS"/00_location
echo '# Disable location settings
/org/gnome/system/location/enabled' > "$LOCKS"/location
echo -e "${BLUE}[i]${RESET}Location settings disabled"


echo "# Prevent usb devices from being mounted and read while screen is locked
[org/gnome/desktop/privacy]
usb-protection-level='lockscreen'
usb-protection=true" > "$DCONFS"/00_usb-protection
echo '# Prevent usb devices from being mounted and read while screen is locked
/org/gnome/desktop/privacy/usb-protection
/org/gnome/desktop/privacy/usb-protection-level' > "$LOCKS"/usb-protection
echo -e "${BLUE}[i]${RESET}USB mount protection added to lock screen"


echo "[i]Updating dconf databases..."

dconf update

echo "[i]Changes will not take effect system-wide until the next login."
