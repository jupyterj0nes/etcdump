# Command line

Generated from `etcdump --help` by `ETCDUMP_WRITE_DOCS=1 cargo test --release --bin etcdump cli_reference`; a test fails when this file is stale.

```text
etcdump finds every Linux root in the inputs (a folder that plays / because it holds etc/passwd or
etc/hostname: a mounted or copied volume, a UAC, CyLR or KAPE-style triage package, a zip or tar
archive, or a disk image E01/raw/VHD/VHDX/VMDK with ext4, XFS or LVM volumes inside) and reads the
configuration an investigation looks at, area by area: accounts (passwd, group, the state of each
shadow password and its scheme, never the hash), sudo, SSH (daemon and client configuration,
authorized keys, known hosts of every user), network, mounts, cron and at, systemd units, drop-ins,
timers and generators, init scripts and rc.local, system and per-user shell profiles, ld.so.preload,
kernel modules, udev rules, PAM, APT/yum/dnf sources and APT hooks, XDG autostart, motd scripts,
environment and /etc/default, firewall rules, logrotate scripts, web server sites and installed
packages (dpkg, dated by their file lists). Deleted configuration files and previous versions the
file system still describes (the ext4 journal) are read too, with state deleted. Every item is
checked against persistence and hardening rules (built in, plus your YAML files with --rules); a hit
fills the row's hunt columns: significant for a high rule, candidate for a medium or low one,
habitual when a clean reference host holds the same item, and a score that is the rule's measured
rarity.

The output folder gets timeline.csv in the c00pr 19-column format (one row per item at its file's
modification time, or the item's own time where it has one: a password's last change, a package's
install), one text dump per root and area that any grep can read, files.txt (one line per
configuration file) and roots.txt.

Exit codes: 0 rows were written; 1 nothing to write (no Linux root, no configuration, or the filters
excluded every row); 2 the command line was wrong; 3 the output folder or the timeline could not be
written.

Environment: ETCDUMP_PROGRESS_PIPE=1 makes the progress plain stderr lines `@@pb <done>/<total>
<message>` for a program that runs etcdump as a child (agentc00pr).

Usage: etcdump [OPTIONS]

Options:
  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version

Input:
  -d, --dir <FOLDER>
          Evidence to read, a folder: a mounted or copied volume, a triage package (UAC keeps the
          root under `[root]`, it is found by its etc/passwd), or any folder holding one or more
          Linux roots. Archives inside it are opened as mounts of their own, two levels deep. Repeat
          for several; each is read on its own thread and every row names its item first in
          source_file when more than one is given

  -f, --file <FILE>
          Evidence to read, a file: a disk image (E01 or its first segment, raw .dd/.raw/.img, split
          .001, VHD, VHDX, VMDK; every ext4, XFS and LVM volume inside is walked), a .zip (read in
          place) or a .tar/.tgz/.tar.gz (unpacked to a temporary folder). Repeat for several. A
          loose configuration file on its own holds no root and gives nothing: copy it under an etc/
          folder and give that folder with -d

      --hostname <NAME>
          The computer name written in every row's `computer` column. Without it the name comes from
          the evidence (etc/hostname of the root, the triage package name), else from the input's
          file or folder name

      --no-deleted
          Do not read deleted configuration files and previous versions. By default the deleted
          entries the file system still describes (the ext4 journal's copies of inodes and directory
          blocks, NTFS records) whose original path is a configuration file are read back and
          written with the `deleted` state and the `:deleted` artifact segment, so a sudoers line or
          a cron job removed after use is still seen

      --no-vss
          Do not read snapshot mounts (Volume Shadow Copies of an image, LVM snapshots). By default
          their configuration is read too, with the `vss` state

      --max-file-bytes <BYTES>
          Configuration files larger than this many bytes are listed as one file item and not parsed
          (a huge package database, a log someone named like a config). Default 32 MiB
          
          [default: 33554432]

      --max-items <N>
          At most this many items are taken from one file; the rest of the file is not read and
          ED205 says so. 0 means no limit. Default 200000
          
          [default: 200000]

Rules:
      --rules <PATH>
          More rules, as a YAML file or a folder of .yaml/.yml files, added to the built-in set (a
          rule with the name of a built-in one replaces it). Each rule names an area, a path glob, a
          key and a value wildcard, texts the value must or must not contain, a severity, a reason
          and a technique: `--list-rules` prints the built-in ones in that format. Repeat for
          several

      --no-builtin-rules
          Do not run the built-in rules; only those of --rules. With neither, no row is judged

      --reference <FILE>
          A reference list (the reference.tsv that --measure writes) of items a clean host of yours
          holds: rule hits on the very same items are habitual, not findings. Added to the built-in
          reference (stock RangeForge lab hosts). Repeat for several

      --no-hunt
          Do not run any rule: the hunt columns stay empty and the run is a little faster

      --list-rules
          Print the rules that would run (built-in, plus --rules) as YAML, with their measured
          rarity, then exit

      --measure
          Measure the rules instead of writing a timeline: the inputs are taken as stock, clean
          hosts, every rule is run over every item, and rarity.tsv (per rule: hits, items, points)
          and reference.tsv (the items a rule fired on) are written into -o. Copy them into
          src/builtin/ to ship them, or give reference.tsv with --reference

Output:
  -o, --output <DIR>
          The output folder, created if missing: timeline.csv (19 columns, UTF-8, RFC 4180,
          fixed-width UTC timestamps, sorted by time, duplicates collapsed), one
          `<mount>[_<root>]_<area>.txt` text dump per root and area (the item's name first when
          several inputs were given), files.txt (one line per configuration file: source, area,
          parser, state, size, modified, status, items, rows, rule hits), roots.txt, and with --json
          timeline.jsonl

      --json
          Also write timeline.jsonl: one JSON object per row with the same fields as the CSV and the
          hunt columns, for tools that prefer JSON lines

      --no-dumps
          Do not write the text dumps; only timeline.csv, files.txt and roots.txt

      --summary
          Print a summary to standard output after the run: per input its computer and roots, per
          area the files, rows and rule hits, and the ten rows to read first

Filter:
      --grep <TEXT>
          Keep only the rows whose path, key or detail contains this text, ignoring case. Repeat for
          several texts: any of them matches. Applies to the timeline; the dumps keep every item so
          the context stays readable

      --grep-not <TEXT>
          Drop the rows whose path, key or detail contains this text, ignoring case. Repeat for
          several. Applied after --grep

      --area <AREA>
          Read only these areas, comma-separated or repeated: accounts, sudo, ssh, keys, network,
          mounts, cron, at, systemd, init, shell, preload, modules, udev, pam, sources, autostart,
          motd, environment, firewall, logrotate, web, packages (`--list-areas` explains each).
          Other files are not even read

      --since <UTC>
          Keep only rows at or after this UTC time: `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SS` or the full
          `YYYY-MM-DDTHH:MM:SS.ffffffZ`. Rows without a time are dropped when a bound is given

      --until <UTC>
          Keep only rows before this UTC time (exclusive), same formats as --since

      --only-hunted
          Keep only the rows a rule made significant or candidate (not habitual, not unjudged): the
          findings alone

Run:
      --threads <N>
          Worker threads: inputs are opened in parallel up to this many, and files are parsed and
          judged on a pool of this size. 0 (the default) uses every core. The output is identical
          whatever the count
          
          [default: 0]

  -v, --verbose...
          More console detail: -v shows informational diagnostics (roots found, files, counts), -vv
          also every decision of etcdump and of evidencefs underneath. Errors and warnings always
          show

  -q, --quiet
          Nothing on standard error: no progress bar, no diagnostics. The exit code still says how
          the run went and files.txt says what was read

Help:
      --list-areas
          List the configuration areas etcdump reads and what each holds, then exit

      --codes
          List every diagnostic code etcdump can print (ED000 to ED699) with what it means and what
          to do about it, as a Markdown table, then exit. Codes starting with EF (evidencefs) are
          explained in that crate's docs/codes.md

      --explain <CODE>
          Explain one diagnostic code seen in a run, given as `ED210`, `ED210_NAME`, `210` or its
          bare name, then exit. Exit code 2 when the code does not exist

      --cli-reference
          Print the command-line reference (this help as Markdown, with the exit codes, the
          environment variables and examples), which is what docs/CLI.md holds, then exit
```

## Exit codes

| Code | Meaning |
|-----:|---------|
| 0 | Rows were written (or a listing, --codes, --explain or --measure succeeded) |
| 1 | Nothing to write: no Linux root, no configuration, or the filters excluded every row |
| 2 | The command line was wrong (no input, no output, a bad time or area, an unknown code to explain) |
| 3 | The output folder or the timeline could not be written |

## Environment

| Variable | Effect |
|----------|--------|
| `ETCDUMP_PROGRESS_PIPE=1` | Progress as plain stderr lines `@@pb <done>/<total> <message>` (one per update, at most four a second, an empty `@@pb` at the end) for a parent program that draws the bar itself |

## Examples

```text
etcdump -d D:\cases\LNX01-triage -o D:\cases\LNX01-etc
etcdump -f uac-lnx01-linux-20261028.tar.gz -o out --summary
etcdump -f disk.E01 --hostname WEB01 --json -o out
etcdump -d triage --area sudo,ssh,keys,cron,systemd --only-hunted -o out
etcdump -d triage --rules D:\rules\linux --reference clean\reference.tsv -o out
etcdump -d triage --grep /tmp/ --since 2026-11-01 -o out
etcdump -d clean-host-1 -d clean-host-2 --measure -o measured
etcdump --list-rules
etcdump --list-areas
etcdump --explain ED215
```
