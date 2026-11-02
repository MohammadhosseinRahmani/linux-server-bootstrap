# CI

One script does all the checking: `ci/selfcheck.sh`. GitHub Actions runs it inside
each image, and an operator runs the same command on the server before and after a
change. The script is the same everywhere; what an image can prove is not, so
"Container versus host" below says which gates a container leaves to a VM.

```bash
sudo bash ci/selfcheck.sh                      # default: expects the debian driver
sudo bash ci/selfcheck.sh --expect-driver rhel # fails if the host loads another driver
sudo bash ci/selfcheck.sh --expect-driver suse
sudo bash ci/selfcheck.sh --with-daemons       # also test ssh, firewall and fail2ban paths
sudo bash ci/selfcheck.sh --skip-unit          # only the syntax, dry-run and verifier gates
```

## What a run proves

| Gate | Command | What it catches |
| --- | --- | --- |
| host | `id -u`, `os-release` | a non-root or unsupported runner says so immediately |
| syntax | `bash -n` on every `.sh` | a typo that would only surface mid-change |
| unit suite | `tests/unit/run_all.sh` | driver contracts, detection, stage plans, verifier proofs |
| orchestrator | `bootstrap.sh --dry-run` with every option | a stage that aborts, or a plan that stops early |
| verifier gate | `tests/verify.sh` against an empty backup root | a check that reports success for work nobody did |
| host fingerprint | sha256 of `/etc` samples before and after | any side effect that escaped the sandbox |

Every writable path a stage uses is redirected into a temporary directory for the
whole run (`BACKUP_ROOT`, `STATE_DIR`, `LOG_FILE`), and the fingerprint compares the
host before and after anyway: a passing self-check must never leave a mark. The
`ssh`, `firewall` and `fail2ban` stages are left out unless `--with-daemons` is
passed, because a container or WSL instance usually has no daemon to talk to and a
refused prerequisite is the correct behaviour there, not a failure.

A host with no service manager at all gets the same treatment one level up: several
stages refuse to plan when they cannot find a way to start a daemon, which is what a
container reports, so the orchestrator pass describes a sysv host there and prints
that it did. The plan is still the product's; only the answer to "what starts this
service" is borrowed.

`--expect-driver` exists because an image that silently loads the wrong driver would
still print a passing dry run. The check compares the driver named by `detect_os`
with the one the matrix row claims to be testing.

## Container versus host

| | Container image | VM or WSL instance |
| --- | --- | --- |
| driver and package paths | yes | yes |
| plan of every stage, `--dry-run` | yes, sysv where the image has no init | yes, with the host's own service manager |
| stage that talks to `sshd`, `ufw`, `fail2ban` | no (`--with-daemons` is not passed) | yes |
| timezone and locale actually generated | only after the driver installs `tzdata` / `locales` | already installed on a normal image |
| unit suite | yes, and it is pinned so the image's missing tools cannot change a result | yes |
| applied baseline and rollback | no | `tests/live_check.sh` |

A minimal image may not ship the timezone database or the `locales` package, so the
driver installs what it needs instead of refusing the operator's request; in a dry run
it says the install was simulated rather than pretending the zone was checked. The unit
suites do not depend on any of that: they pin `INIT_SYSTEM`, an `os-release` fixture and
`ZONEINFO_DIR`, and stub the binaries the pinned family owns, so the same commit gives
the same 361 checks on every runner.

## The workflow

`.github/workflows/test.yml` runs two jobs:

1. `lint` — shellcheck over every shell file (`--severity=info --external-sources`),
   then `bash -n`.
2. `distro-matrix` — `ci/selfcheck.sh --expect-driver <family>` in ubuntu 24.04 and
   22.04, debian 12, rocky 9, alma 8, fedora 42 and opensuse/leap 15.6.
   `fail-fast: false`, so one broken image does not hide the state of the others.

Each image installs only `git` and the core utilities the workflow needs to check the
code out; the repository's own package choices stay inside the stages.

EL7 is deliberately not a job: its `yum` mirrors are retired, so an image that cannot
install git proves nothing. EL7 is covered locally instead, below.

## Local matrix

The table above lists what a container leaves unproven. Before a release, run the
self-check on a real or semi-real instance of each family, ideally with
`--with-daemons`:

| Case | Image | What only this case proves |
| --- | --- | --- |
| Debian | `debian:12`, `devuan/chimaera` | ufw, `apt` paths, and a family without systemd |
| Ubuntu | `ubuntu:24.04` | `ssh.socket`, `sshd_config.d` Include, unattended-upgrades |
| EL7 | `oraclelinux:7-slim` | bash 4.2, `authconfig` instead of `authselect`, no crypto-policy command |
| EL8 | `almalinux:8` | `dnf` and `update-crypto-policies`, SELinux enforcing |
| EL9/EL10 | `rockylinux:9` | `dnf4`, EPEL for fail2ban, `dnf-automatic` timers |
| SUSE | `opensuse/leap:15.6` | `zypper`, `crypto-policies-config`, AppArmor profiles |

The bash 4.2 column matters most: an empty array under `set -u` is an error there but
not on 4.4, so a stage can pass everywhere else and fail on EL7. Any change to a
loop that builds a list should be run on a 4.2 shell.

### Results on the instances used so far

Each row is `ci/selfcheck.sh --expect-driver <family>` and the same command with
`--with-daemons`, run inside the distro's own filesystem. `dry_actions` is the number
of host commands the plan intercepted instead of running. The suite counts are the
pinned-fixture ones, so they match on every row.

| Instance | Family | Driver | Init | bash | Unit checks | Dry-run stages | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Ubuntu 26.04 | debian | debian | systemd | 5.3 | 361 | 9 then 11 | pass |
| Debian 13 | debian | debian | systemd | 5.2 | 361 | 9 then 11 | pass |
| AlmaLinux 8 | rhel | rhel | systemd | 4.4 | 361 | 9 then 11 | pass |
| Oracle Linux 7.9 | rhel | rhel | sysv | 4.2 | 361 | 9 then 11 | pass |
| openSUSE Leap 16.0 | suse | suse | systemd | 5.2 | 361 | 9 then 11 | pass |

The same five instances also run with `INIT_SYSTEM=none` in the environment, which is
how the container case is reproduced without a container: the orchestrator pass plans
for a sysv host and the suite still reports 361 checks.

EL7 supplied two findings no other row could: `${key//./\/}` keeps the backslash on
4.2, which made every `/proc/sys` path unreadable and the kernel template look empty,
and `${arr[*]}` of an empty array aborts a stage under `set -u`. Both are fixed, and
the 4.2 row is the only proof they stay fixed.

That instance also has no systemd, so it is the sysv row: the firewall stage plans
`chkconfig`/`service` instead of `systemctl`, and the base stage does the same for
chrony. `INIT_SYSTEM` can be pinned for a test that needs the other half.

### WSL

On Windows, the same matrix is available through WSL images, which is how this
repository's per-distro results were produced:

```powershell
wsl --install -d Debian                       # also: OpenSUSE-Leap-16.0, AlmaLinux-8
wsl --install -d <Distro>
```

Oracle Linux 7 is not in the gallery a `wsl --install -d` can reach, and asking for it
returns exit 0 without registering anything. Import its rootfs instead: pull the amd64
layer from `ghcr.io/oracle/oraclelinux:7`, check its sha256 against the layer digest in
the manifest, decompress it, and `wsl --import OracleLinux-7 <dir> <tar>`.

```powershell
wsl --import OracleLinux-7 C:\wsl\ol7 C:\tmp\ol7-rootfs.tar
```

Copy the repository into the distro's own filesystem — a `/mnt/c` path reports NTFS
ownership and modes, and the permission stage reads those numbers as facts — then:

```bash
sudo bash ci/selfcheck.sh --expect-driver debian   # or rhel / suse
```

### Vagrant and libvirt

For a case that needs a real init system (EL7, a systemd-less image, a host with
`sshd` running), a VM is the honest environment:

```bash
vagrant up ubuntu-2404 && vagrant provision ubuntu-2404
vagrant ssh ubuntu-2404 -c 'sudo bash /vagrant/ci/selfcheck.sh --with-daemons'
```

`tests/live_check.sh` applies the whole baseline to the machine it runs on, verifies
it, rolls it back, and compares a fingerprint of the configuration it touched:

```bash
vagrant ssh ubuntu-2404 -c 'sudo bash /vagrant/tests/live_check.sh --family debian \
    --user vagrant --key /home/vagrant/.ssh/authorized_keys'
```

It is the only script here that changes the host by design, so it belongs in a VM you
are willing to destroy. Pass `--keep` to stop after the verification pass and leave
the baseline applied, which is what an acceptance scan needs:

```bash
sudo bash tests/live_check.sh --family rhel --user admin --key /root/.ssh/id_ed25519.pub --keep
sudo lynis audit system --quick
```

`vagrant up <name> && vagrant provision <name>` runs `ci/selfcheck.sh --with-daemons`
in each box, and the box names are the rows of the table above.

## Acceptance

A self-check pass means the tooling works. It does not mean the server meets a
benchmark. For that, run an external scanner against the hardened host:

```bash
sudo oscap xccdf eval --profile CIS_RHEL_8_Benchmark \
     --report /tmp/oscap.html /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
sudo lynis audit system --quick
```

Both are installed from the distro's own repository and are not dependencies of this
project. The expected result after a full baseline is a materially smaller finding
list than the same scan on an untouched image; the residual findings are the ones
this project deliberately leaves to the operator (partition layout, kernel module
blacklists, and anything that would break a running service).

## Adding a driver

`lib/os.sh` declares `DRIVER_CONTRACT`. Implement every name in it in
`lib/drivers/<family>.sh`, point one `case` arm of `detect_os` at the family, and add
a fixture row to `tests/unit/test_os.sh` plus a section to
`tests/unit/test_drivers_matrix.sh`. The stages and the verifier never name a
distribution; if a change requires them to, the driver boundary is in the wrong place
and should be fixed here instead.
