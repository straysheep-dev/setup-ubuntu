# setup-ubuntu
Automatically configure an Ubuntu 18.04 (or later) workstation, vm, or server.

```bash
sudo ./dconf.sh
sudo ./setup-ubuntu.sh
```
If you encounter:
```bash
$ ssh-add ~/.ssh/id_rsa
Could not add identity "/home/test/.ssh/id_rsa": agent refused operation
```
It's because gpg-agent is handling ssh identities.
Run:
```bash
$ gpg-connect-agent updatestartuptty /bye
OK
```
Then:
```bash
$ ssh-add ~/.ssh/id_rsa
Identity added: /home/test/.ssh/id_rsa (test@test)
```
## To do:

- [ ] Make revert functions to undo all changes
- [ ] Break groups of functions apart into separate files, keep the ability to combine them into a single script or only those selected (?)
- [x] Review output of `shellcheck` and make any fixes
- [ ] Review Ubuntu 18.04/20.04 guidelines from [OpenSCAP](https://www.open-scap.org/security-policies/choosing-policy/)
- [x] Check unbound and systemd-resolved services 
- [ ] Review inconsistencies with Raspberry Pi and aarch64 packages (auditd rules + boot parameters need revised for aarch64)
