# linux-server-bootstrap

Turns a fresh Linux server into a locked-down one in a single run: thirteen stages,
each of which backs up what it is about to change, proves the change afterwards, and
restores the backup if the proof fails. Pure Bash, no agents, no daemons to install,
no configuration language to learn.

Run it on the machine you intend to harden, as root, after you have an SSH key in place.

## Supported systems

| Family | Distributions | Firewall | MAC | Notes |
| --- | --- | --- | --- | --- |
| Debian | Debian 11+, Ubuntu 20.04+, and their derivatives | ufw | AppArmor | works without systemd |
| RPM (EL) | RHEL, Rocky, AlmaLinux, CentOS, Amazon Linux | firewalld | SELinux | EL7 tested on bash 4.2, `yum`, sysvinit |
| RPM (Fedora) | Fedora | firewalld | SELinux | fail2ban from base repos |
| SUSE | openSUSE Leap, SLES | firewalld | AppArmor | `zypper`, `crypto-policies-config` |

Each family has a driver in `lib/drivers/` that owns every family-specific command. The
stages themselves never branch on the distribution. A host whose family is not listed is
refused before anything changes, rather than guessed at.

## Start here

```bash
# 1. See exactly what would change. Nothing on the host is touched.
sudo bash bootstrap.sh --user deploy --port 22 --dry-run

# 2. Open a second SSH session on the current port and keep it open.

# 3. Apply.
sudo bash bootstrap.sh --user deploy --port 22

# 4. Prove it, and prove it from the session you did not just use.
sudo bash tests/verify.sh
```

`--yes` skips the confirmation for an unattended run. `--dry-run` never writes: not to
configuration, not to the state file, and not to the backup tree, so a plan cannot be
mistaken for a change.

Before the first run, the account named by `--user` must exist and have a public key in
`~/.ssh/authorized_keys`. The SSH stage checks this and refuses to continue otherwise,
because disabling password login for an account that has no key locks everyone out.
`--user root` is refused for the same reason: root login is switched off.

## The stages

Thirteen stages run in this order. A stage whose option is absent still runs with its
own defaults, except `base` and `users`, which only do what they are told.

| # | Stage | What it does | To change it |
| --- | --- | --- | --- |
| 1 | `base` | package updates, hostname, timezone, locale, time sync, unattended upgrades | `--updates --timesync --autoupdates --hostname --timezone --locale` |
| 2 | `users` | creates accounts, installs keys, grants sudo through `/etc/sudoers.d` | `--new-user --key --sudo --groups` |
| 3 | `ssh` | the SSH drop-in described below | `--user --port` |
| 4 | `firewall` | allows the SSH port, denies other inbound, keeps outbound | `--skip-firewall` |
| 5 | `fail2ban` | sshd jail: 3 failures in 10 minutes, 1 hour ban | `--skip-fail2ban` |
| 6 | `sysctl` | 38 kernel parameters, trimmed to what this kernel exposes | `--disable-routing` |
| 7 | `limits` | core dump limit, concurrent login cap | `--core-size N --max-logins N` |
| 8 | `perms` | modes and owners on account files, cron, setuid binaries, host keys | `--fix-world-writable` |
| 9 | `audit` | 34 `auditd` rules | `--watch-privileged --immutable` |
| 10 | `mac` | SELinux enforcing, or AppArmor profiles in enforce mode | `--install-mac` |
| 11 | `services` | disables and masks legacy units | `--include-optional` |
| 12 | `banner` | login banner in `/etc/issue`, `/etc/issue.net`, `Banner` | |
| 13 | `auth` | lockout, password length and aging, umask, PAM quality | `--deny --min-len --umask` |

`--only STAGE[,STAGE...]` runs a subset in the same order and `--skip NAME` removes one.
`--status` prints what the host currently holds and what each stage recorded; `--report`
prints the same as JSON.

## What SSH changes

`config/sshd_config.conf` is installed as
`/etc/ssh/sshd_config.d/00-linux-server-bootstrap.conf`. The `00-` prefix is deliberate:
OpenSSH keeps the first value it reads, so this file wins over distro snippets such as
`50-redhat.conf`.

| Setting | Value |
| --- | --- |
| `Port` | the `--port` value |
| `PermitRootLogin` | no |
| `PubkeyAuthentication` | yes |
| `PasswordAuthentication` | no |
| `AuthenticationMethods` | publickey |
| `AllowUsers` | the `--user` accounts |
| `MaxAuthTries` | 3 |
| `MaxSessions` | 4 |
| `LoginGraceTime` | 30 |
| `ClientAliveInterval` / `ClientAliveCountMax` | 300 / 2 |
| X11, TCP, agent and tunnel forwarding | no |

Keyboard-interactive login is disabled, and ciphers, MACs and key-exchange algorithms are
appended from the list this `sshd` build reports with `ssh -Q`, so a host that cannot
negotiate an algorithm is never configured to require it. If the main `sshd_config` does
not include `/etc/ssh/sshd_config.d/*.conf`, the `Include` line is added at the top and
the previous file is backed up.

On Debian, a custom port is also written for `ssh.socket`, but the socket is not restarted
automatically. Restart it once a second session works on the new port:

```bash
sudo systemctl restart ssh.socket
```

## Firewall and fail2ban

The firewall opens the SSH port and denies other inbound connections; outbound is left
alone. It uses ufw on the Debian family and firewalld everywhere else. If you move off
port 22, port 22 stays open while your current session is still using it, and is closed by
the next run once you have reconnected.

fail2ban's ban action is taken from the firewall that is actually installed: ufw on the
Debian family, firewalld rich rules elsewhere. If the firewall was skipped, fail2ban keeps
its own default action rather than being configured with a ban command that does not
exist. On RPM hosts fail2ban is installed from EPEL when the base repositories do not
carry it.

## The rest of the baseline

**Kernel.** The 38 keys in `config/sysctl.conf` are filtered against `/proc/sys` before
anything is written, so the same file works on a minimal container and a full server.
Values are read back after `sysctl -p`, and one the kernel silently ignored is a failure
rather than a footnote. Routing keys (`ip_forward`, IPv6 forwarding) are left alone unless
you pass `--disable-routing`, because a host that forwards today is usually a router on
purpose and turning that off over SSH strands everything behind it.

**Permissions** are corrected only for paths that exist. The world-writable scan reports
unless you pass `--fix-world-writable`, since removing a bit from a file you did not
inspect is how services break.

**Audit** writes `/etc/audit/rules.d/99-linux-server-bootstrap.rules` and loads it through
`augenrules`. `--immutable` locks the ruleset until the next reboot, which also means a
mistake needs a reboot to undo.

**MAC** puts SELinux in enforcing mode or moves AppArmor profiles from complain to
enforce. Enabling SELinux on a host where it was disabled is not attempted: it needs a
full relabel and a reboot, so the stage prints the two commands instead of running them.

**Legacy services** covers telnet, rsh, rlogin, rexec, tftp, xinetd and NIS.
`--include-optional` adds avahi, CUPS, NFS and rpcbind, which are often there on purpose.

**Authentication policy** is 3 failures before a 15-minute lockout, a 15-minute unlock, a
minimum password length of 14, aging at 365/1/7 days and umask 027. Where `login.defs`
does not exist at all, aging and umask are left at the distribution's values and the state
records only what was actually written.

## Backups and rollback

Everything goes to `/var/backups/linux-server-bootstrap/<component>/<timestamp>/` with a
manifest of what was taken, and `latest` points at the newest. Undo the last pass, newest
component first:

```bash
sudo bash bootstrap.sh --rollback
```

Roll back one component with `bash hardening/ssh.sh --rollback`. A rollback restores the
files and then points `latest` at the previous timestamp, so a second `--rollback` walks
further back. Packages stay installed: removing them is more dangerous than leaving them.
Permission changes are reverted by restoring the recorded modes, not by copying files
back, so a shadow file another process changed in the meantime is not overwritten.

A failed `sshd -t`, a failed reload, a service that will not start, or any unexpected error
after the backup triggers the same restore automatically.

`/etc/linux-server-bootstrap/state.env` holds the port, the allowed accounts and each
stage's recorded values, so a later run reads them without being told again. The log is
`/var/log/linux-server-bootstrap.log`.

## Verification

`bash tests/verify.sh` is read-only and answers one question: did each stage actually
change this host? A stage with no backup is reported as not applied rather than failed, so
a partially-selected run still verifies cleanly. Everything else is compared against the
values the stage itself recorded.

```bash
sudo bash tests/verify.sh --skip-firewall --skip-fail2ban   # match the bootstrap run
```

## Checking it before you trust it on a server

```bash
sudo bash ci/selfcheck.sh --with-daemons
```

Runs the syntax sweep, the unit suites, the whole baseline as a dry run and the verifier,
then compares a fingerprint of the host taken before the run with one taken after: a dry
run that changed anything is a bug, not a result. `--expect-driver rhel` fails the run if
the repository loaded a driver for a different family. The GitHub Actions workflow runs
the same script in seven containers, so a green check here means what a green check on
your server means. See [ci/README.md](ci/README.md) for the WSL and Vagrant matrix.

To prove a stage can also be undone on a machine you are willing to change:

```bash
sudo bash tests/live_check.sh --family rhel
```

Applies for real, verifies, rolls back and diffs the host fingerprint.

## Layout

```
bootstrap.sh          stage selection, plan, confirmation, rollback
setup/                base setup, user preparation
hardening/            eleven modules, one per stage
lib/                  common.sh (backups, state, traps), init.sh, os.sh, drivers/
config/               sshd, sysctl, audit, limits, fail2ban, banner templates
tests/                verify.sh, live_check.sh, unit/
ci/                   selfcheck.sh and the matrix documentation
.github/workflows/    the Actions gate
docs/THREAT_MODEL.md  what this defends against, and what it deliberately does not
```

## What this is not

It is a baseline, not a compliance framework. There is no disk partitioning or encryption,
no kernel module blacklisting, no network architecture, no log shipping, no configuration
management loop, no application hardening, and no certificate or secret handling.
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) lists the gaps and the assumptions an operator
has to satisfy for the controls to mean anything. Passing a scanner is not a side effect of
running this; OpenSCAP and Lynis are how you measure it.

Licensed under Apache-2.0. See [LICENSE](LICENSE) and [CHANGELOG.md](CHANGELOG.md).
