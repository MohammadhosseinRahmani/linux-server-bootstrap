# Threat model and non-goals

What this baseline defends, what it deliberately does not, and the assumptions an
operator has to accept for the rest to hold. It is written against the code in this
repository, not against a benchmark: each section names the stage that provides the
control.

## What is being protected

| Asset | Why it matters |
| --- | --- |
| The credentials that unlock the host | SSH keys and, for a local login, passwords. Losing one means losing the machine. |
| The audit trail | Without it, a compromise cannot be dated or scoped, and the operator cannot prove what happened. |
| Availability of the admin path | A hardened host nobody can log into is an outage, and an outage invites an insecure rollback. |
| The configuration itself | Unmonitored drift — a package that rewrites `sshd_config`, a cron job added by another admin — silently undoes everything here. |

## Adversaries assumed

- A network scanner that reaches the published ports and guesses credentials.
- An unprivileged local account that wants to read another user's material or
  escalate.
- A previous compromise looking for a way to persist and to erase its trail.
- An operator who does the expedient thing under pressure: root login with a
  password, from memory, at 3 a.m.

Nothing here is designed against an attacker who already has root on the host, nor
against a hardware or hypervisor adversary. Physical access defeats every control in
this repository.

## Threats and the control that answers them

| Threat | Control | Stage |
| --- | --- | --- |
| Brute force against SSH | Password and keyboard-interactive login are off; `AllowUsers` narrows the account set; fail2ban bans repeat offenders; `pam_faillock` locks local accounts after `--deny` failures. | `ssh.sh`, `fail2ban.sh`, `auth_policy.sh` |
| Weak or obsolete SSH algorithms | Only ciphers, MACs and KEX this `sshd` build reports as available are written, in the order the template prefers, so nothing silently fails to load. | `ssh.sh` |
| Moving SSH to a non-default port | `AllowUsers`, the port and the firewall are applied together and validated before `sshd` reloads; a refused reload restores the previous files. | `ssh.sh`, `firewall.sh` |
| Other services reachable | Default-deny inbound, allow only the SSH port, outbound left alone. | `firewall.sh` |
| Cleartext daemons | Known telnet/rsh/ftp-style units are stopped and masked, and only units the host actually has are touched. | `services.sh` |
| Credential files read by the wrong person | Modes and owners fixed on the identity, sudo, cron and SSH server key files; `/etc/shadow` group is read from the host instead of assuming a family's answer. | `perms.sh` |
| Secrets leaking through core dumps | Core size is set to 0 for all accounts, including through the systemd manager default, because services never pass through `pam_limits`. | `limits.sh` |
| Shared or over-open home directories, weak file creation defaults | `UMASK` and `HOME_MODE` in the managed block of `login.defs`. | `auth_policy.sh` |
| Weak passwords on accounts that must use them | `pam_pwquality` minimum length and character classes; aging through `login.defs`. | `auth_policy.sh` |
| Privilege escalation through unchecked sudo | Sudo is granted by a drop-in validated with `visudo -c` before it is installed; `/etc/sudoers.d` permissions are enforced. | `users.sh`, `perms.sh` |
| Kernel network and memory defaults | The `sysctl` baseline, trimmed to keys the running kernel exposes and read back from `/proc/sys` after load. | `sysctl.sh` |
| Undocumented access to a system | Legal banner on the consoles, on the network login, and as SSH `Banner`. | `banner.sh` |
| Mandatory access control left off | The family's own MAC system is put in enforcing mode; a *Disabled* SELinux is deliberately not enabled, because that requires a relabel and a reboot. | `mac.sh` |
| Actions that cannot be attributed | `audit.rules` watch the identity, sudo, and audit-configuration files, plus privilege escalation and modification of the audit trail itself. | `audit.sh` |
| The audit trail being switched off | `--immutable` ends the ruleset with `-e 2`, so `auditctl` cannot change it until the next reboot. | `audit.sh` |
| A change that breaks login | Every stage backs up what it edits, verifies the live system rather than the file it wrote, and restores the backup on failure. `bootstrap.sh --rollback` walks the components back in reverse order. | all stages |
| Silent partial application | `tests/verify.sh` refuses to call a stage applied unless that stage left a backup, and checks each parameter against the target the stage recorded. | `tests/verify.sh` |

## Where the controls are weakest

Being honest about the parts that are thin is the point of this section.

- **Key material is out of scope.** The baseline checks that an allowed account has a
  public key; it cannot tell a stolen key from a legitimate one, and it never
  generates or transports private keys. Hardware-backed keys (`sk-ssh-ed25519`) are
  accepted by the algorithm list, but their protection comes from the token.
- **Lockout is also a denial-of-service lever.** `pam_faillock` and fail2ban will
  lock out a real administrator who mistypes a password. Console or cloud-serial
  access is required to recover, and `auth_policy.sh` deliberately authenticates an
  existing account after editing the PAM stack to prove the stack still works.
- **`--immutable` costs a reboot to undo.** A locked audit ruleset is the point, and
  the operator cannot change it from inside the running system.
- **File-system permissions are only as good as the process that changes them.**
  A service running as root can reopen anything. The audit rules record the change;
  they do not prevent it.
- **A container is not a hardened host.** `/proc/sys` is often read-only, there may
  be no MAC, and the kernel parameters belong to the host. `sysctl.sh` fails loudly
  instead of pretending, which is correct behaviour but means the container case
  gets fewer controls, not more.
- **The rollback restores files, not packages.** A stage that installs a package
  leaves it installed, so a rolled-back host still has fail2ban, auditd or the MAC
  tools present.
- **Automatic patching is a supply-chain decision handed to the distribution.**
  `setup/base.sh --autoupdates` turns it on only when asked; who signs the repository
  is the distribution's problem, not this baseline's.
- **Drift is detected only when the verifier is run.** Nothing here schedules a
  re-check. Running `tests/verify.sh` from cron or a pipeline is the operator's step.

## Non-goals

These are not oversights. They are the boundaries that keep the tool small enough to
audit in an afternoon.

- Partitioning, filesystem layout, LVM, `/home` or `/var/tmp` on their own mount with
  `nodev`/`nosuid`, and disk encryption.
- Kernel module blacklisting and `usbguard`.
- Network architecture: VLANs, VPNs, bastion hosts, DDoS protection, rate limiting in
  front of SSH.
- Centralised logging, log shipping, SIEM integration, and log retention.
- Configuration management, host fleet orchestration, and enforcement over time.
  This tool configures one host it is run on.
- Application hardening for anything it does not configure: web servers, databases,
  containers, language runtimes.
- Certificate authorities, internal PKI, secret storage and rotation.
- User and group inventory: it prepares the accounts named on the command line and
  removes nothing.
- File integrity monitoring (`AIDE`, `rpm -V`, `debsums`).
- Compliance certification. The values follow CIS Distribution Independent guidance,
  but running this baseline does not produce a CIS-conformant system and does not
  claim one. `Lynis` and OpenSCAP are the right judges, and both are expected to keep
  reporting findings that belong to the operator's environment.
- Support for anything other than Debian-family, RPM-family and SUSE Linux hosts with
  systemd, SysV or runit as the init system.

## Assumptions the operator accepts

1. The scripts run as root on the target host, from a copy the operator has read.
2. A second session is open for the whole run, and stays open until
   `tests/verify.sh` passes.
3. Out-of-band console access exists for the case where SSH is moved to a new port
   and the firewall closes the old one.
4. The host's package repositories are the distribution's own; this baseline adds a
   repository only where the driver does it deliberately, such as EPEL on EL.
5. Time is broadly correct: file timestamps, fail2ban's `findtime` and certificate
   checks all depend on it, which is why `--timesync` exists.
6. A future change to this repository is reviewed by a human before it is applied to
   a production host — pin the commit or tag you ran, and re-run
   `ci/selfcheck.sh --expect-driver <family>` on the host before applying.
