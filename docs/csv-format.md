# timeline.csv

UTF-8, RFC 4180, one header line, every text field in double quotes (inner quotes doubled, line
breaks replaced by spaces), the two numbers bare, the analysis tail bare when empty (`,,,,,`), as
masstin writes it. Sorted by time, then by every other column; rows identical in every column
are written once.

| # | Column | masstin vertical | What it holds |
|--:|---|---|---|
| 1 | `timestamp` | time_created | `YYYY-MM-DDTHH:MM:SS.ffffffZ`, UTC, 27 characters; the file's modification time, or the item's own (see `time_source`); empty when nothing has a time |
| 2 | `computer` | dst_computer | `--hostname`, else what the evidence says (the triage package name, etc/hostname), else the input's name |
| 3 | `artifact` | event_type | `etc:<area>`, with `:deleted` for a deleted file or previous version and `:vss` for a snapshot mount |
| 4 | `event_id` | event_id | always 0 |
| 5 | `state` | logon_type | `live`, `deleted` or `vss` |
| 6 | `user` | target_user_name | the account the item concerns: the passwd/shadow account, the sudo rule's user, the user crontab's owner, the home folder's owner |
| 7 | `area` | target_domain_name | accounts, sudo, ssh, keys, network, mounts, cron, at, systemd, init, shell, preload, modules, udev, pam, sources, autostart, motd, environment, firewall, logrotate, web, packages |
| 8 | `path` | workstation_name | the file's path from the root: `etc/sudoers.d/90-cloud-init-users`, `home/bob/.bashrc` |
| 9 | `key` | ip_address | what the item is called: the account, the directive (`Service.ExecStart`, `Match User x\|ForceCommand`), the schedule, the command's first word, the package |
| 10 | `item_type` | subject_user_name | account, group, shadow, sudo_rule, sudo_default, sudo_alias, include, directive, block, authorized_key, known_host, host_entry, setting, mount, crypt, export, cron_job, cron_env, at_command, pam, apt_source, apt_conf, package, logrotate_script, shebang, command, line, link, file, unparsed |
| 11 | `time_source` | subject_domain_name | what the timestamp is: `modified`, `changed`, `created` (the file's), `shadow_last_change` (the password's last change), `dpkg_info_list` (the package's install or upgrade), or empty |
| 12 | `size` | logon_id | the file's size in bytes |
| 13 | `detail` | detail | the value, then ` \| line=N \| file_modified=… \| file_changed=… \| file_created=…` and for a deleted file ` \| deleted_id=… \| deleted_at=…` |
| 14 | `source_file` | filename | `<mount>/<path on the mount>` (`folder/etc/passwd`, `partition_0/$DELETED/1234/etc/shadow`), the input's name first (`HOST.tar.gz:tar/...`) when several were given |
| 15 | `hunt` | hunt | significant, candidate, habitual, or empty |
| 16 | `hunt_score` | hunt_score | 0 to 100, the measured rarity of the rules that fired; empty when no state |
| 17 | `hunt_why` | hunt_why | `rule <NAME> (<severity>): <why> [<technique>]`, `; ` between rules, strongest first |
| 18 | `verdict` | verdict | the analyst's; never written by etcdump |
| 19 | `notes` | notes | the analyst's |

Two rows:

```csv
"2026-11-03T12:21:09.000000Z","lnx-test","etc:accounts",0,"live","toor","accounts","etc/passwd","toor","account","modified",142,"uid=0 gid=0 home=/root shell=/bin/bash system=no interactive=yes gecos= | line=4 | file_modified=2026-11-03T12:21:09.000000Z","folder/etc/passwd","significant",40,"rule LNX-UID0-ACCOUNT (high): an account other than root has uid 0: a second root, the classic backdoor account [T1136.001]",,
"2023-05-23T00:00:00.000000Z","lnx-test","etc:accounts",0,"live","bob","accounts","etc/shadow","bob","shadow","shadow_last_change",98,"password=set scheme=yescrypt last_change=2023-05-23 min=0 max=99999 warn=7 inactive= expire= | line=2 | file_modified=2026-11-03T12:21:09.000000Z","folder/etc/shadow",,,,,
```
