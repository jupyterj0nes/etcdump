# etcdump

**The configuration of every Linux root of a machine, as text and as a timeline.** etcdump is
[hivedump](https://github.com/jupyterj0nes/hivedump) for Linux: where hivedump dumps every
registry hive, etcdump reads every file an investigation looks at under `/etc`, the users'
homes and the spools, area by area, judges every item with persistence and hardening rules,
and writes one text dump per area and one timeline in the c00pr 19-column format shared with
masstin, caarea, faramir, allymacb, webfoot, exfilter, hivedump and hostsweep.

```text
etcdump -f uac-lnx01-linux-20261028.tar.gz -o lnx01-etc --summary
etcdump -d D:\cases\LNX01-triage --area sudo,ssh,keys,cron,systemd --only-hunted -o out
etcdump -f web01.E01 --json -o out
```

## What goes in

Anything [evidencefs](https://github.com/jupyterj0nes/evidencefs) opens: a folder (a copied or
mounted volume, a triage package; a UAC collection keeps the root under `[root]` and it is found
by its `etc/passwd`), a zip, a tar or tar.gz, or a disk image (E01, raw, split raw, VHD, VHDX,
VMDK) with ext4, XFS or LVM volumes inside. Every folder that plays `/` (it holds `etc/passwd`
or `etc/hostname`) is a root; only the configuration folders under it are walked, never the
whole volume, so a full image takes seconds once its volumes are open.

## What comes out

| Area | Files |
|---|---|
| accounts | passwd, group, shadow (state and scheme of each password and its last change; **never the hash**), gshadow, login.defs |
| sudo | sudoers, sudoers.d (rules, Defaults, aliases, includes) |
| ssh | sshd_config and ssh_config with their .d folders (Match blocks keyed `Match <criteria>\|<Keyword>`), per-user ssh config |
| keys | every user's authorized_keys (options, type, comment, key head) and known_hosts |
| network | hosts, resolv.conf, nsswitch.conf, hostname, interfaces, netplan, NetworkManager (secrets redacted), hosts.allow/deny |
| mounts | fstab, crypttab, exports |
| cron | crontab, cron.d, cron.hourly/daily/weekly/monthly, anacrontab, user crontabs |
| at | at jobs (the commands after at's header) |
| systemd | system and user units, drop-ins, timers, generators, systemd's own conf |
| init | init.d, rc.local, rc?.d links, inittab, upstart |
| shell | system and per-user profiles and rc files (bash, zsh, csh, fish, X session) |
| preload | ld.so.preload, ld.so.conf and ld.so.conf.d |
| modules | modules, modules-load.d, modprobe.d |
| udev | udev rules under /etc |
| pam | pam.d, pam.conf, pam_env |
| sources | APT sources (both formats) and apt.conf.d hooks, yum/dnf/zypper repositories |
| autostart | XDG autostart entries, system and per user |
| motd | motd, update-motd.d, issue |
| environment | environment, /etc/default, os-release, sysctl |
| firewall | iptables, nftables, ufw and firewalld saved rules |
| logrotate | logrotate.conf and logrotate.d, pre/post-rotate scripts |
| web | Apache and nginx sites |
| packages | dpkg status (each package dated by its file list under var/lib/dpkg/info); RPM databases listed |

The output folder holds `timeline.csv`, one `<mount>[_<root>]_<area>.txt` text dump per root
and area (live files first, then `[DELETED AND PREVIOUS VERSIONS]`, every item with its line and
a `<<<` marker where a rule fired), `files.txt` (one line per configuration file: source, area,
parser, state, size, modified, status, items, rows, rule hits), `roots.txt`, and with `--json`
`timeline.jsonl`. See [docs/csv-format.md](docs/csv-format.md) and [docs/CLI.md](docs/CLI.md).

**Deleted files and previous versions.** On an image, the deleted entries the file system still
describes (the ext4 journal's copies of inodes and directory blocks, through evidencefs's
`/$DELETED` folder) whose original path is a configuration file are read back: their rows carry
the `deleted` state and the `:deleted` artifact segment, so a cron job or a sudoers drop-in
removed after use is still seen.

**Secrets stay out.** shadow and gshadow are read only to classify each password (set, empty,
locked, disabled) and name its scheme (yescrypt, sha512crypt, md5crypt, des...). A value whose
key names a password, pre-shared key, token or secret (NetworkManager `psk=`, `DB_PASSWORD=`, an
fstab `password=` option) is replaced by `<redacted N chars>`. Private SSH keys are never read.

## Rules and the hunt columns

Fifty-one built-in rules (`etcdump --list-rules`, [src/builtin/rules.yaml](src/builtin/rules.yaml))
look for what attackers leave: a second uid 0, empty passwords, system accounts with a shell,
NOPASSWD sudo, shells and editors granted through sudo, root login and empty passwords over SSH,
odd AuthorizedKeysFile/Command, forced commands on keys, keys of service accounts, scheduled or
start-up commands that download and run, run from /tmp, decode base64 or open a reverse shell,
units running from homes, user units, generators, rc.local, ld.so.preload, LD_PRELOAD in the
environment, pam_exec, a sufficient pam_permit, PAM modules from odd places, APT hooks, unsigned
sources, motd and logrotate scripts reaching the network, udev RUN+=, modules loaded at boot,
hosts-file redirects, sudo aliases in profiles, PROMPT_COMMAND, history switched off, at jobs,
user crontabs, opened firewall ports and /tmp without noexec. Add yours with `--rules FILE|DIR`
(a rule with a built-in name replaces it).

A hit fills the row's analysis tail the way caarea does ([caarea docs/hunting.md](https://github.com/jupyterj0nes/caarea/blob/main/docs/hunting.md)):

- `hunt`: `significant` for a high rule, `candidate` for a medium or low one, `habitual` when a
  clean reference host holds the very same item and the same rule fired on it there;
- `hunt_score`: the rules' **measured** rarity, `-10 · log10(hits / items)` on the clean
  reference (the bound `-10 · log10(1 / (items + 1))` for a rule that never fired), added and
  capped at 100; a rule below 10 points fires on more than one reference item in ten and is
  noise: no state, no points;
- `hunt_why`: `rule <NAME> (<severity>): <why> [<technique>]`, strongest first.

The shipped rarity table and reference ([src/builtin/rarity.tsv](src/builtin/rarity.tsv),
[src/builtin/reference.tsv](src/builtin/reference.tsv)) were measured with
`etcdump --measure` on the clean RangeForge lab host LEO-LNX01 (Ubuntu 22.04 on GCE: its UAC
collection of 2026-10-28 and its triage of 2026-11-03, 10,017 items). Four rules fired on stock
items there and are worth less than the 40-point bound: `LNX-APT-HOOK` (9 stock hooks:
update-notifier, needrestart, packagekit, command-not-found, debconf, 30 points),
`LNX-PRIVILEGED-GROUP-MEMBER` and `LNX-SUDO-NOPASSWD-ALL` (3 each: the cloud image's `ubuntu`
user, google-sudoers, 35 points). Those stock items are habitual anywhere else. The lab's own
deliberate weakness (`%Leadership ALL=(ALL) NOPASSWD:ALL`) was left out of the reference on
purpose: it stays a finding. Measure your own golden image with
`etcdump -d clean-host --measure -o measured` and give `--reference measured/reference.tsv`.

## Reliability

The output is the same byte for byte whatever `--threads` says and however often it runs:
rows are sorted and deduplicated, diagnostics are absorbed in input and file order, the access
times of host folders (which reading changes) are never used, and a tar unpacked to a temporary
folder keeps only the modification time the archive stores (its creation and change times would
be the moment of unpacking). Tests check it over synthetic trees and over the lab evidence.

## Diagnostics and exit codes

Every message carries a code `ED###_NAME` ([docs/codes.md](docs/codes.md), `--codes`,
`--explain ED215`); codes from evidencefs keep their `EF###`. Exit codes: 0 rows written, 1
nothing to write (no Linux root, no configuration, or every row filtered out), 2 the command
line was wrong, 3 the output could not be written. `ETCDUMP_PROGRESS_PIPE=1` turns the progress
into `@@pb <done>/<total> <message>` lines for agentc00pr.

## Limits

- File owner and mode are not shown: evidencefs does not expose them yet, so set-uid shells and
  world-writable configuration cannot be flagged.
- RPM databases are listed, not read; journald, logs and shell histories are not configuration
  (exfilter, opentrail, caarea and masstin read them).
- udev rules are read under /etc only; the vendor rules under /lib are not.

## Build and test

```text
cargo build --release
ETCDUMP_WRITE_DOCS=1 cargo test --release
```

AGPL-3.0-only. Tono Diaz (@jupyterj0nes).
