# Changelog

Notable changes for this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — unreleased

The first release that describes itself as a baseline rather than a set of SSH
scripts. Everything below was added or fixed on the way from the original SSH,
firewall and fail2ban trio.

### Added

- One command for a full pass: `bootstrap.sh` runs the stages in a fixed order,
  shows one plan, and takes `--only`, `--skip`, `--yes`, `--dry-run`, `--status`,
  `--report` and `--rollback`.
- Driver plugins in `lib/drivers/` (`debian`, `rhel`, `suse`) behind one `drv_*`
  contract checked at load time. Stages and the verifier name no distribution; SUSE
  support, `ufw` versus `firewalld`, SELinux versus AppArmor, `authselect` versus
  `authconfig`, and the crypto-policy commands all live there.
- Base setup: `setup/base.sh` for package updates, hostname, timezone, locale, time
  sync and automatic patching — each action opt-in, none implied.
- Account preparation: `setup/users.sh` creates or prepares the accounts SSH will
  allow, installs public keys, and grants sudo through a drop-in validated with
  `visudo -c`.
- Eight hardening stages that did not exist: `sysctl.sh`, `limits.sh`, `perms.sh`,
  `audit.sh`, `mac.sh`, `services.sh`, `banner.sh`, `auth_policy.sh`.
- A read-only verifier, `tests/verify.sh`, that covers all thirteen stages, checks
  the live value rather than the file on disk, reports a stage that never ran as
  *not applied*, and requires every recorded state key to have a rollback point.
- Unit suites that need no server: `tests/unit/run_all.sh` (338 checks) with
  `os-release` fixtures, PATH stubs and dry-run transcripts, including
  `test_drivers_matrix.sh` for Debian, Ubuntu, Devuan, RHEL 9, CentOS 7 with and
  without systemd, Fedora, Amazon Linux, openSUSE Leap and the skip paths.
- `ci/selfcheck.sh`: host gate, syntax, unit suite, full dry-run, verifier gate and
  a before/after host fingerprint, so a check can prove it changed nothing.
- `.github/workflows/test.yml` (shellcheck plus the self-check in seven images),
  `Vagrantfile` for the cases that need a real init system, and
  `tests/live_check.sh` to apply, verify, roll back and re-fingerprint a throwaway
  host.
- Documentation: `ci/README.md` for the gates and the local matrix,
  `docs/THREAT_MODEL.md` for what is defended and what is deliberately out of scope,
  and the Apache-2.0 `LICENSE`.
- The baseline was run on five real instances before release — Ubuntu 26.04, Debian 13,
  AlmaLinux 8.10, openSUSE Leap 16.0 and Oracle Linux 7.9 — each without and with
  `--with-daemons`. The EL7 row is the one that earns its place: bash 4.2, `yum`, no
  `dnf`, no systemd, and no `update-crypto-policies`.

### Changed

- Per-component backups and rollback replaced the single-file restore: every stage
  writes a timestamped backup with a manifest, keeps a `latest` pointer, and restores
  itself when its own proof fails.
- `/etc/shadow` ownership and the locale name are read from the host instead of
  assuming one family's answer, so Debian's `shadow:0640` and EL's `root:0600` are
  both correct.
- `--status` and `--report` read the backup tree rather than the state file: a stage
  with nothing to put back has nothing to roll back.
- The firewall closes the port an earlier run opened unless that port is carrying the
  session in front of it.
- `auth_policy.sh` skips aging and umask on a host that ships without
  `login.defs`, instead of failing a policy whose other two mechanisms are valid.

### Fixed

- A fresh clone could not run: `lib/` and `config/fail2ban-sshd.conf` were untracked,
  and `.gitattributes` now forces LF endings so the scripts stay runnable.
- `tests/verify.sh` died on `--skip-firewall` and `--skip-fail2ban`, the flags
  `bootstrap.sh` forwards, because it parsed its arguments with the stage parser.
- A `ufw` rule for `222/tcp` or `22x/tcp` was reported as port 22 being open; the port
  column is compared exactly now.
- fail2ban configured a firewall ban action for a firewall CLI that was not installed
  after `--skip-firewall`, so bans failed silently; the command is probed first.
- `${STAGE_TITLE_${name}}` is not valid bash, so every stage looked up by name failed
  before it ran; the registry is a real associative array.
- A PAM splice could lock everyone out: it now writes through the symlink
  `authselect` owns, raises every `[success=N]` jump it steps over by the number of
  lines it inserts, and refuses a stack with no `pam_unix` line.
- A dry run that promised not to touch the host still called `auditctl`, and the
  AppArmor profile scan skipped any directory whose name contained a dot.
- A dry run also wrote its backup directory and the `latest` symlink inside it. That
  symlink is the gate `tests/verify.sh` uses to decide a stage was applied, so a plan
  could be mistaken for a change and the verifier then failed values the plan never
  wrote. No stage now touches the filesystem when `--dry-run` is set.
- `${key//./\/}` keeps the backslash on bash 4.2, so the sysctl stage looked for
  `/proc/sys/net\/ipv4\/ip_forward`, matched no key on an EL7 host, and reported a
  template of 38 supported parameters as empty.
- An empty array under `set -u` is an error on bash 4.2 but not on 4.4, so the shared
  `save_state` aborted any stage that carried no SSH user list — the firewall stage
  among them.
- `detect_init` replaced `INIT_SYSTEM` even when the caller had pinned it, which made a
  systemd assertion depend on the runner rather than on the case being described.
- `--sudo` refused to plan on a minimal image that has no `/etc/sudoers.d` yet, because
  the simulated package install that creates it under `--dry-run` never ran. The
  directory is checked when the change is real.
