# setup-ubuntu
Automatically configure an Ubuntu 18.04 (or later) workstation, vm, or server.

```bash
./gsettings.sh
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
