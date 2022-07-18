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

- [ ] Revert functions
- [ ] Separate files for functions(?)
- [x] Review [OpenSCAP](https://www.open-scap.org/security-policies/choosing-policy/)
- [ ] Issues with auditd rules on aarch64
- [x] Issues with boot params on aarch64

## Credits & Licenses

This project takes code, ideas, or guidance from the following sources:

- [g0tmi1k, os-scripts](https://github.com/g0tmi1k/os-scripts/blob/master/kali2.sh)
	* [MIT License](https://github.com/g0tmi1k/os-scripts/blob/master/kali2.sh)

- [angristan, wireguard-install](https://github.com/angristan/wireguard-install/blob/master/wireguard-install.sh)
	* [MIT License](https://github.com/angristan/wireguard-install/blob/master/LICENSE)

- [drduh, config](https://github.com/drduh/config)
	* [MIT License](https://github.com/drduh/config/blob/master/LICENSE)

- [drduh, YubiKey-Guide](https://github.com/drduh/YubiKey-Guide)
	* [MIT License](https://github.com/drduh/YubiKey-Guide/blob/master/LICENSE)

- [Canonical Ubuntu 20.04 LTS Security Technical Implementation Guide (STIG) V1R1](https://static.open-scap.org/ssg-guides/ssg-ubuntu2004-guide-stig.html)
	* [ComplianceAsCode, content](https://github.com/ComplianceAsCode/content)
	* [BSD 3-Clause License](https://github.com/ComplianceAsCode/content/blob/master/LICENSE)
