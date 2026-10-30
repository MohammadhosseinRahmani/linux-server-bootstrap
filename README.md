# linux-server-bootstrap

Hardens a fresh Debian-family or RPM-family server in three steps: SSH, firewall, then fail2ban. Each step backs up what it changes and restores that backup if validation or a service reload fails.

Supported systems are Debian 11+, Ubuntu 20.04+, RHEL, Rocky, and AlmaLinux 8+, and Fedora. Debian-family firewall rules use `ufw`. RPM-family rules use `firewalld`. On RPM, fail2ban is installed from EPEL when it is not in the base repositories. Fedora and Amazon Linux use their own repositories.

## Before you run it

1. Copy this directory to the server.
2. Create a normal user and install an SSH public key in `~/.ssh/authorized_keys`.
3. Open a second SSH session and keep it open until `tests/verify.sh` passes.
4. Run the scripts as root. `bash` is enough, so the files do not need the executable bit.

The SSH step refuses to continue unless every `--user` account exists and has a public key. It also refuses `--user root`, because root login is disabled. If the account you are logged in as is not in the allow list, pass `--yes` only when you intend to switch to another account.

## Apply

```bash
sudo bash bootstrap.sh --user deploy --port 22
```

`--port` defaults to the port saved in `/etc/linux-server-bootstrap/state.env`, or 22. Repeat `--user` for more than one account.

Non-interactive run:

```bash
sudo bash bootstrap.sh --user deploy --port 22 --yes
```

Run one step:

```bash
sudo bash hardening/ssh.sh --user deploy --port 22
sudo bash hardening/firewall.sh --port 22
sudo bash hardening/fail2ban.sh --port 22
```

Skip a step from the full run with `--skip-firewall` or `--skip-fail2ban`.

## What SSH changes

The template is `config/sshd_config.conf`. It is installed as `/etc/ssh/sshd_config.d/00-linux-server-bootstrap.conf`. The `00-` prefix matters: OpenSSH keeps the first value it sees, so this file is read before snippets such as `50-redhat.conf`.

| Setting | Value |
|---|---|
| Port | the `--port` value |
| PermitRootLogin | no |
| PubkeyAuthentication | yes |
| PasswordAuthentication | no |
| AuthenticationMethods | publickey |
| AllowUsers | the `--user` accounts |
| MaxAuthTries | 3 |
| MaxSessions | 4 |
| LoginGraceTime | 30 |
| ClientAliveInterval / CountMax | 300 / 2 |
| X11, TCP, agent, and tunnel forwarding | no |

The script also disables keyboard-interactive login, and it appends ciphers, MACs, and key-exchange algorithms that this `sshd` build reports through `ssh -Q`. If the main `sshd_config` does not include `/etc/ssh/sshd_config.d/*.conf`, the Include line is added at the top and the previous file is backed up.

On Debian, a custom port is written for `ssh.socket`, but the socket is not restarted automatically. Restart it only after a second session works on the new port:

```bash
sudo systemctl restart ssh.socket
```

## Firewall and fail2ban

The firewall allows the SSH port, denies other inbound traffic, and leaves outbound traffic allowed. If you move off port 22, port 22 stays open while the current session is still using it. Run the firewall script again after you reconnect on the new port.

fail2ban enables the `sshd` jail: 3 failures in 10 minutes, then a 1 hour ban. Debian bans through ufw. RPM bans through firewalld rich rules.

## Backups and rollback

Backups go to `/var/backups/linux-server-bootstrap/<component>/<timestamp>`. `latest` points at the newest backup. A rollback restores that copy, then points `latest` at the previous timestamp, so a second `--rollback` walks further back. Installed packages are left installed.

A failed `sshd -t`, SSH reload, or fail2ban reload restores the files from the backup taken at the start of that step and reloads the restored service. An unexpected command failure after the backup does the same.

Roll back everything, newest component first:

```bash
sudo bash bootstrap.sh --rollback
```

Roll back one component:

```bash
sudo bash hardening/fail2ban.sh --rollback
sudo bash hardening/firewall.sh --rollback
sudo bash hardening/ssh.sh --rollback
```

Logs are appended to `/var/log/linux-server-bootstrap.log`. The saved port and users are in `/etc/linux-server-bootstrap/state.env`.

## Check

```bash
sudo bash tests/verify.sh
```

The check is read-only. It confirms the effective SSH settings, the firewall, the fail2ban jail, the listener, and the backup symlinks.
