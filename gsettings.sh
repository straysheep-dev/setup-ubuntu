#!/bin/bash

# gsettings / dconf config
# must be run separetly as UID1000/normal user

# Screen never goes to sleep
gsettings set org.gnome.desktop.session idle-delay 'uint32 0'
# Screen goes to sleep after 10 minutes
#gsettings set org.gnome.desktop.session idle-delay 'uint32 600'


# Gedit Preferences
gsettings set org.gnome.gedit.preferences.editor scheme 'solarized-light'
#gsettings set org.gnome.gedit.preferences.editor scheme 'oblivion'
#gsettings set org.gnome.gedit.preferences.editor scheme 'kate'
#gsettings set org.gnome.gedit.preferences.editor wrap-mode 'none'

# Disable autorun of software and media
gsettings set org.gnome.desktop.media-handling autorun-never 'true'

# Disable automounting of media and drives
gsettings set org.gnome.desktop.media-handling automount false
gsettings set org.gnome.desktop.media-handling automount-open false

# See /usr/share/glib-2.0/schemas/org.gnome.Terminal.gschema.xml
# See dconf list /org/gnome/terminal
# See dconf read /org/gnome/terminal/[..]/next-tab
# Some settings require a literal path
# Sets the hotkey combination of Ctrl+Shift+Left/Right Arrows to change terminal tabs
gsettings set org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ prev-tab '<Primary><Shift>Left'
gsettings set org.gnome.Terminal.Legacy.Keybindings:/org/gnome/terminal/legacy/keybindings/ next-tab '<Primary><Shift>Right'

# Show hidden files and folders
gsettings set org.gtk.Settings.FileChooser show-hidden 'true'

# Disable location settings
gsettings set org.gnome.system.location enabled 'false'

# Auto-hide the dock
gsettings set org.gnome.shell.extensions.dash-to-dock dock-fixed 'false'

# Prevent usb devices from being mounted and read while screen is locked
gsettings set org.gnome.desktop.privacy usb-protection-level 'lockscreen'
gsettings set org.gnome.desktop.privacy usb-protection 'true'

# Don't automatically send techincal reports, but prompt user for OK
# Crash reports still generate under /var/crash/ to review
gsettings set org.gnome.desktop.privacy report-technical-problems 'false'
gsettings set org.gnome.desktop.privacy send-software-usage-stats 'false'

# Prevent notifications from appearing in the lock screen
gsettings set org.gnome.desktop.notifications show-in-lock-screen 'false'
