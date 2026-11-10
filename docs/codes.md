# Diagnostic codes

Every code etcdump can print, with what it means and what to do about it. The ranges are in `src/diag.rs`. Codes starting with `EF` come from [evidencefs](https://github.com/jupyterj0nes/evidencefs); they are printed as that crate records them and explained in its own `docs/codes.md`.

| Code | Meaning |
|---|---|
| `ED000_RUN_STARTED` | the run started; the message gives the inputs and the thread count (shown with -v) |
| `ED001_RUN_DONE` | the run finished; the message gives the roots, files, items and rows (shown with -v) |
| `ED002_CLI_NO_INPUT` | no -d or -f was given: name at least one evidence item (a folder, a triage package, an archive or a disk image) |
| `ED003_CLI_NO_OUTPUT` | no -o was given: name the output folder (it is created when missing) |
| `ED004_CLI_EXPLAIN_UNKNOWN` | --explain names no etcdump code; --codes lists them all |
| `ED005_RUN_INPUT_MISSING` | an input path does not exist; it is skipped and the run goes on with the others |
| `ED006_RUN_NO_ROOT_ANYWHERE` | no input held a Linux root: there is nothing to read (hivedump reads Windows registry hives) |
| `ED007_RUN_THREADS` | the worker pool size: --threads, or every core when it is 0 (shown with -v) |
| `ED008_RUN_FILE_UNREADABLE` | a configuration file could not be read; it is in files.txt as unreadable and gives no rows |
| `ED009_RUN_FILE_TOO_LARGE` | a configuration file is larger than --max-file-bytes; it is one file item in the timeline and not parsed |
| `ED010_RUN_DELETED_READ` | a deleted configuration file or a previous version was read back from the file system; its rows carry state deleted |
| `ED011_RUN_DELETED_EMPTY` | a deleted configuration file is described by the metadata but nothing can be read back; it is in files.txt with no rows |
| `ED012_RUN_HUNT` | rules were run over every item; the message gives the significant, candidate and habitual rows (shown with -v) |
| `ED013_RUN_LIST_RULES` | --list-rules printed the rules that would run (built-in and --rules), then exited |
| `ED014_RUN_LIST_AREAS` | --list-areas printed the configuration areas etcdump reads, then exited |
| `ED015_RUN_MEASURE` | --measure: instead of a timeline, the rules were measured on the inputs taken as clean reference evidence; rarity.tsv and reference.tsv were written |
| `ED016_RUN_ITEM_DONE` | an input was read; the message gives its roots and configuration files (shown with -v) |
| `ED100_DISC_OPENED` | an evidence item was opened; the message gives its kind and mounts (shown with -v) |
| `ED101_DISC_OPEN_FAILED` | an evidence item could not be opened (not an image, archive or folder evidencefs reads; damaged; missing); it is skipped and the run goes on with the others |
| `ED102_DISC_NO_ROOT` | no Linux root (a folder holding etc/passwd or etc/hostname) was found in an item; it gives no configuration |
| `ED103_DISC_ROOT` | a Linux root was found; the message gives the mount and the folder that plays / (shown with -v) |
| `ED104_DISC_FILE` | a configuration file was found and given its area and parser (shown with -vv) |
| `ED105_DISC_WALK_LIMIT` | a walk under a root stopped at its limit (entries or depth); some configuration may be missing; the message names the folder |
| `ED106_DISC_READ_FAILED` | a configuration file could not be read from the evidence (damaged extents, a decompression error); it is listed in the inventory as unreadable |
| `ED107_DISC_TOO_LARGE` | a configuration file is larger than --max-file-bytes; it is listed as one file item and not parsed |
| `ED108_DISC_DELETED_SCAN` | the deleted entries of a mount were listed (ext4 journal, NTFS $MFT); the message gives how many fall under a root's configuration folders |
| `ED109_DISC_DELETED_UNREADABLE` | a deleted configuration file is described by the metadata but its content cannot be read back; it is listed with no items |
| `ED110_DISC_DELETED_SKIPPED` | --no-deleted: the deleted entries and previous versions of the mounts were not looked at |
| `ED111_DISC_SNAPSHOT` | a mount is a snapshot (a Volume Shadow Copy, an LVM snapshot); its rows carry state vss |
| `ED112_DISC_DPKG_LISTS` | the file lists under var/lib/dpkg/info were read for their times (one per installed package) to date the package rows |
| `ED113_DISC_HOSTNAME` | the computer name was taken from the evidence (etc/hostname, the triage package name) (shown with -v) |
| `ED114_DISC_HOSTNAME_FROM_NAME` | the computer name was taken from the item's file or folder name: no --hostname and nothing in the evidence names the host |
| `ED115_DISC_WINDOWS_ONLY` | an item holds a Windows root and no Linux one: etcdump reads Linux configuration (hivedump reads Windows hives) |
| `ED116_DISC_LINK` | a configuration file is a symbolic link; it is listed with its target and not followed (shown with -vv) |
| `ED117_DISC_USER_HOME` | a home folder was found under a root (home/<user>, root); its dotfiles, SSH files and autostart entries are read (shown with -vv) |
| `ED118_DISC_UNKNOWN_FILE` | a file under a configuration folder has no area etcdump knows (a backup, an editor swap file); it is skipped (shown with -vv) |
| `ED119_DISC_SKIPPED_BACKUP` | a backup or editor copy (passwd-, shadow-, *.bak, *.dpkg-old, *~, .swp) was read as its own file: backups keep the state before the last change |
| `ED120_DISC_ITEM_THREAD_FAILED` | the worker reading one evidence item stopped unexpectedly; that item gives nothing and the others go on |
| `ED121_DISC_NESTED` | an archive inside the item was opened as a mount of its own (shown with -v) |
| `ED122_DISC_ARCHIVE_TIMES` | a tar was unpacked to a temporary folder to be read: its files keep the modification time the archive stores, their creation, change and access times (the moment of unpacking) are left out so two runs give the same rows |
| `ED123_DISC_FOLDER_ATIME` | the access times of a host folder are left out: reading the files changes them, they are the collector's or this run's, not the suspect's (shown with -vv) |
| `ED200_PARSE_STARTED` | a configuration file is about to be parsed with the parser named in the message (shown with -vv) |
| `ED201_PARSE_DONE` | a configuration file was parsed; the message gives the parser and the item count (shown with -vv) |
| `ED202_PARSE_BINARY` | the file holds NUL bytes in its first 8 KB: it is not text (a compiled generator, a database), so it is listed as one file item and not parsed |
| `ED203_PARSE_NOT_UTF8` | the file is not valid UTF-8; invalid sequences were replaced with U+FFFD and the rest parsed as text |
| `ED204_PARSE_EMPTY` | the file is empty (or holds only comments and blank lines); it is listed in the inventory with no items |
| `ED205_PARSE_TOO_MANY_ITEMS` | the file gave more items than --max-items allows; the rest of the file was not read (raise the limit for a huge package database) |
| `ED210_PARSE_PASSWD_BAD_LINE` | lines of a passwd file do not have the seven colon-separated fields; they were skipped and counted |
| `ED211_PARSE_PASSWD_BAD_UID` | a passwd line has a uid or gid that is not a number; the account is kept with the text as written |
| `ED212_PARSE_PASSWD_DUPLICATE` | the same account name appears twice in a passwd file; both lines are kept (the first one wins at login), worth a look |
| `ED213_PARSE_GROUP_BAD_LINE` | lines of a group file do not have the four colon-separated fields; they were skipped and counted |
| `ED214_PARSE_SHADOW_BAD_LINE` | lines of a shadow or gshadow file do not have enough colon-separated fields; they were skipped and counted |
| `ED215_PARSE_SHADOW_HASH_WITHHELD` | password hashes were read from shadow/gshadow only to classify them (set, empty, locked, disabled) and name the scheme; no hash is written anywhere |
| `ED216_PARSE_SHADOW_BAD_DATE` | a shadow field that holds days since 1970 (last change, expiry) is not a number; it is shown as written and gives no row time |
| `ED220_PARSE_SUDO_BAD_LINE` | a sudoers line is neither a Defaults line, an alias, an include nor a user specification with an equal sign; it is kept as an unparsed line |
| `ED221_PARSE_SUDO_CONTINUATION` | a sudoers or shell line ends with a backslash and was joined with the next line before parsing (shown with -vv) |
| `ED222_PARSE_SUDO_INCLUDE` | a sudoers file includes another file or folder (@include, #includedir); the target is read when it is in the evidence, and the include itself is an item |
| `ED230_PARSE_SSH_BAD_LINE` | an SSH configuration line has a keyword and no value; it is kept with an empty value |
| `ED231_PARSE_SSH_MATCH_BLOCK` | an SSH configuration has Match or Host blocks: the directives inside are keyed `Match <criteria>\|<Keyword>` so a rule can tell them from the global ones |
| `ED232_PARSE_KEY_BAD_LINE` | an authorized_keys or known_hosts line holds no recognised key type (ssh-rsa, ssh-ed25519, ecdsa-sha2-*, sk-*, ssh-dss); it is kept as an unparsed line |
| `ED233_PARSE_KEY_HASHED_HOST` | known_hosts entries are hashed (HashKnownHosts): the host names cannot be read, only the key types (shown with -vv) |
| `ED234_PARSE_HOSTS_BAD_LINE` | a hosts-file line has an address and no name; it is kept with an empty value |
| `ED240_PARSE_FSTAB_BAD_LINE` | an fstab, crypttab or exports line has fewer fields than the format needs; it is kept with what it has |
| `ED241_PARSE_CRON_BAD_LINE` | a crontab line has neither five schedule fields nor an @keyword before the command; it is kept as an unparsed line |
| `ED242_PARSE_CRON_ENV` | a crontab sets an environment variable (SHELL, PATH, MAILTO...) for its jobs; it is an item of kind cron_env |
| `ED243_PARSE_AT_JOB` | an at job file was read: the shell header at writes is skipped and the commands after it are items |
| `ED250_PARSE_UNIT_BAD_LINE` | a line of a systemd unit or INI file is neither a [Section] header nor Key=Value; it is kept as an unparsed line |
| `ED251_PARSE_UNIT_NO_SECTION` | a Key=Value line comes before any [Section] header; it is keyed without a section |
| `ED252_PARSE_UNIT_DROPIN` | a systemd drop-in (unit.d/*.conf) was read; its directives override the unit's and are keyed the same way (shown with -vv) |
| `ED260_PARSE_PAM_BAD_LINE` | a PAM line does not have a type, a control and a module; it is kept as an unparsed line |
| `ED261_PARSE_PAM_INCLUDE` | a PAM file includes or substacks another one (@include, include, substack); the target is its own file and the include is an item |
| `ED270_PARSE_APT_BAD_LINE` | an APT sources line does not start with deb or deb-src followed by a URI; it is kept as an unparsed line |
| `ED271_PARSE_APT_DEB822` | an APT .sources file in the deb822 format was read: each stanza is one source item keyed by its URIs |
| `ED272_PARSE_DPKG_STANZA_BAD` | a stanza of /var/lib/dpkg/status has no Package field; it was skipped and counted |
| `ED273_PARSE_DPKG_INSTALL_TIME` | package rows take the time of the package's file list under /var/lib/dpkg/info (written at install or upgrade); packages without one take the status file's time |
| `ED274_PARSE_RPM_UNSUPPORTED` | an RPM database (rpmdb.sqlite, Packages) is in the evidence; it is listed as a file but its packages are not read (use rpm --dbpath on a copy) |
| `ED280_PARSE_KV_BAD_LINE` | a line of a key=value, key: value or key value file has no separator; it is kept with an empty value |
| `ED281_PARSE_SECRET_REDACTED` | a value whose key names a password, pre-shared key, token or secret was replaced by its length (`<redacted N chars>`); the setting is visible, its secret is not |
| `ED282_PARSE_LOGROTATE_SCRIPT` | a logrotate file runs a prerotate/postrotate/firstaction/lastaction script; its lines are items of kind logrotate_script |
| `ED290_PARSE_SCRIPT_SHEBANG` | a script's first line names its interpreter; it is an item of kind shebang (shown with -vv) |
| `ED291_PARSE_SCRIPT_LONG_LINE` | a line longer than 4096 characters was cut there in the item (the full line is in the evidence) |
| `ED292_PARSE_LINK` | the file is a symbolic link (an rc?.d entry, an enabled unit); it is one item whose value is the link target |
| `ED293_PARSE_FILE_ONLY` | the file is listed as one item (name and size) because its kind is not parsed line by line (a generator binary, a database, a lock) |
| `ED350_RULES_BUILTIN` | the built-in rules were loaded; the message gives how many (shown with -v) |
| `ED351_RULES_FILE_LOADED` | a rules file given with --rules was loaded; the message gives how many rules it adds (shown with -v) |
| `ED352_RULES_FILE_UNREADABLE` | a rules file or folder given with --rules cannot be read; the run goes on with the other rules |
| `ED353_RULES_YAML_INVALID` | a rules file is not a valid YAML list of rules; the message gives the line and column; none of its rules are used |
| `ED354_RULES_RULE_NO_NAME` | a rule has no name; it is skipped (every rule needs a stable name for hunt_why and the rarity table) |
| `ED355_RULES_RULE_NO_CONDITION` | a rule has neither an area, a path, a key, a value nor data texts: it would fire on everything, so it is skipped |
| `ED356_RULES_RULE_DUPLICATE` | two rules have the same name; the later one replaces the earlier one (a user rule can override a built-in one this way) |
| `ED357_RULES_BAD_SEVERITY` | a rule's severity is not high, medium or low; it is read as medium |
| `ED358_RULES_HIT` | a rule fired on an item (shown with -vv); the row's hunt columns say which and why |
| `ED359_RULES_HABITUAL` | a rule fired on an item the clean reference holds too, where the same rule fired: the row is habitual, not a finding |
| `ED360_RULES_NOISE` | a rule fired that the reference measured as noise (below 10 points: more than one reference item in ten); its clause is kept, it gives neither state nor points |
| `ED361_RULES_NOT_MEASURED` | a rule fired that the rarity table has no measurement for (a user rule, a new built-in one); it gives its state and 0 points until `etcdump --measure` is run |
| `ED362_RULES_DISABLED` | --no-hunt: no rule was run and the hunt columns are empty |
| `ED363_RULES_NO_BUILTIN` | --no-builtin-rules: only the rules of the --rules files were run |
| `ED364_RULES_SCORE_CAPPED` | a row's rules added up to more than 100 points; its score is 100 (shown with -vv) |
| `ED365_RULES_RARITY_TABLE` | the rarity table of the built-in rules was loaded; the message gives the reference size (shown with -v) |
| `ED366_RULES_RARITY_BAD_LINE` | a line of a rarity or reference table is not tab-separated as expected; it was skipped |
| `ED367_RULES_REFERENCE_LOADED` | a reference list (items of a clean host) was loaded with --reference; items in it are habitual (shown with -v) |
| `ED368_RULES_REFERENCE_UNREADABLE` | a reference list given with --reference cannot be read; the built-in one is used alone |
| `ED369_RULES_BAD_PATTERN` | a rule's wildcard has an unbalanced brace; it is matched as plain text |
| `ED450_ROWS_SORTED` | the rows were sorted by time, then by every other column, and rows identical in every column were written once |
| `ED451_ROWS_DUPLICATES` | rows identical in every column were collapsed: the same item reached etcdump twice (a file and its backup with the same content, two overlapping inputs) |
| `ED452_ROWS_NO_TIME` | a file has no usable time (a deleted entry without times, an archive member without a date); its rows carry an empty timestamp and sort first |
| `ED453_ROWS_JSON_FAILED` | a row could not be serialised to JSON (not expected: the fields are text and numbers); the row was skipped |
| `ED454_ROWS_EMPTY` | no row came out of the configuration: no Linux root, every file empty, or every row filtered out |
| `ED455_ROWS_ITEM_TIME` | rows of this file take the time the item itself carries (shadow's last change, a package's install) rather than the file's (shown with -vv) |
| `ED456_ROWS_FILE_TIME` | the row time is the file's modification time; the change and birth times are in detail when the file system keeps them (shown with -vv) |
| `ED500_OUT_DIR_FAILED` | the output folder could not be created; check the path and the permissions |
| `ED501_OUT_TIMELINE_FAILED` | timeline.csv could not be written (disk full, permissions, a program holding the file) |
| `ED502_OUT_JSON_FAILED` | timeline.jsonl could not be written; the CSV was |
| `ED503_OUT_DUMP_FAILED` | a text dump could not be written; the timeline still holds its rows |
| `ED504_OUT_INVENTORY_FAILED` | files.txt or roots.txt could not be written; the timeline was |
| `ED505_OUT_WRITTEN` | the outputs were written; the message gives the folder, the rows and the dumps (shown with -v) |
| `ED506_OUT_DUMP_NAME` | two roots would give the same dump name; the root folder was added to tell them apart (shown with -vv) |
| `ED507_OUT_NO_DUMPS` | --no-dumps: only the timeline, files.txt and roots.txt were written |
| `ED508_OUT_OVERWRITE` | the output folder already held an etcdump timeline; it was replaced (shown with -v) |
| `ED600_FILTER_TIME_INVALID` | a --since or --until value is not a UTC time; give `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SS` or the full `YYYY-MM-DDTHH:MM:SS.ffffffZ` |
| `ED601_FILTER_TIME_ORDER` | --since is after --until, so nothing can pass; check the two values |
| `ED602_FILTER_EXCLUDED_ALL` | the filters excluded every row; nothing is written, loosen --grep, --area, --since, --until or --only-hunted |
| `ED603_FILTER_APPLIED` | the filters kept this many rows out of the total |
| `ED604_FILTER_AREA_UNKNOWN` | an --area name is not one etcdump knows; --help lists the areas (accounts, sudo, ssh, keys, cron, systemd...) |
| `ED605_FILTER_GREP_EMPTY` | an empty --grep or --grep-not text matches everything or nothing and was ignored |
| `ED606_FILTER_ONLY_HUNTED` | --only-hunted: only rows a rule made significant or candidate were kept |
| `ED650_MEASURE_STARTED` | measuring the rules on the inputs, taken as clean reference evidence (shown with -v) |
| `ED651_MEASURE_NO_ITEMS` | the reference inputs gave no configuration item: nothing can be measured (is there a Linux root in them?) |
| `ED652_MEASURE_WRITTEN` | rarity.tsv and reference.tsv were written into the output folder; copy them into src/builtin/ to ship them |
| `ED653_MEASURE_WRITE_FAILED` | rarity.tsv or reference.tsv could not be written |
| `ED654_MEASURE_RULE_NOISE` | a rule fires on more than one reference item in ten (below 10 points): it is noise on stock hosts and gives neither state nor points |
| `ED655_MEASURE_FILTERED` | --measure ignores the filters (--grep, --area, --since, --until, --only-hunted): a measurement needs every item |
