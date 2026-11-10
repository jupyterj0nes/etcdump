//! Filters over the rows and the text dumps: `--grep`, `--grep-not`, `--area`, `--since`,
//! `--until`, `--only-hunted`.

use crate::timeline::Row;

pub mod code {
    crate::codes! {
        FILTER_TIME_INVALID = 600, "a --since or --until value is not a UTC time; give `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SS` or the full `YYYY-MM-DDTHH:MM:SS.ffffffZ`";
        FILTER_TIME_ORDER = 601, "--since is after --until, so nothing can pass; check the two values";
        FILTER_EXCLUDED_ALL = 602, "the filters excluded every row; nothing is written, loosen --grep, --area, --since, --until or --only-hunted";
        FILTER_APPLIED = 603, "the filters kept this many rows out of the total";
        FILTER_AREA_UNKNOWN = 604, "an --area name is not one etcdump knows; --help lists the areas (accounts, sudo, ssh, keys, cron, systemd...)";
        FILTER_GREP_EMPTY = 605, "an empty --grep or --grep-not text matches everything or nothing and was ignored";
        FILTER_ONLY_HUNTED = 606, "--only-hunted: only rows a rule made significant or candidate were kept";
    }
}

/// The filters of a run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    /// Lower-cased texts, any of which must appear in the path, key or detail.
    pub grep: Vec<String>,
    /// Lower-cased texts, none of which may appear.
    pub grep_not: Vec<String>,
    /// Areas to keep (lower case); empty: all.
    pub areas: Vec<String>,
    /// Inclusive lower bound, fixed-width UTC text.
    pub since: Option<String>,
    /// Exclusive upper bound, fixed-width UTC text.
    pub until: Option<String>,
    /// Only rows with hunt significant or candidate.
    pub only_hunted: bool,
}

/// `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SS` or the full text, padded to the fixed width.
pub fn normalise_time(s: &str) -> Option<String> {
    let t = s.trim().replace(' ', "T");
    let t = t.trim_end_matches('Z');
    let digits_ok = |x: &str| x.chars().all(|c| c.is_ascii_digit());
    let (date, time) = match t.split_once('T') {
        Some((d, tm)) => (d, tm),
        None => (t, ""),
    };
    let dp: Vec<&str> = date.split('-').collect();
    if dp.len() != 3 || dp[0].len() != 4 || dp[1].len() != 2 || dp[2].len() != 2 || !dp.iter().all(|x| digits_ok(x)) {
        return None;
    }
    let (m, d): (u32, u32) = (dp[1].parse().ok()?, dp[2].parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, b),
        None => (time, ""),
    };
    let (hh, mm, ss) = if hms.is_empty() {
        ("00", "00", "00")
    } else {
        let tp: Vec<&str> = hms.split(':').collect();
        if tp.len() != 3 || !tp.iter().all(|x| x.len() == 2 && digits_ok(x)) {
            return None;
        }
        let (h, mi, se): (u32, u32, u32) = (tp[0].parse().ok()?, tp[1].parse().ok()?, tp[2].parse().ok()?);
        if h > 23 || mi > 59 || se > 60 {
            return None;
        }
        (tp[0], tp[1], tp[2])
    };
    if !digits_ok(frac) || frac.len() > 6 {
        return None;
    }
    let mut f = frac.to_string();
    while f.len() < 6 {
        f.push('0');
    }
    Some(format!("{date}T{hh}:{mm}:{ss}.{f}Z"))
}

impl Filter {
    /// Builds the filter from the command line texts; errors for bad times and areas.
    pub fn new(grep: &[String], grep_not: &[String], areas: &[String], since: Option<&str>, until: Option<&str>, only_hunted: bool) -> crate::diag::Result<Filter> {
        let mut f = Filter { only_hunted, ..Default::default() };
        for g in grep {
            if g.trim().is_empty() {
                crate::diag::info(code::FILTER_GREP_EMPTY, "--grep");
            } else {
                f.grep.push(g.to_lowercase());
            }
        }
        for g in grep_not {
            if g.trim().is_empty() {
                crate::diag::info(code::FILTER_GREP_EMPTY, "--grep-not");
            } else {
                f.grep_not.push(g.to_lowercase());
            }
        }
        for a in areas.iter().flat_map(|a| a.split(',')).map(|a| a.trim().to_lowercase()).filter(|a| !a.is_empty()) {
            if !crate::discover::is_area(&a) {
                return Err(crate::diag::fail(code::FILTER_AREA_UNKNOWN, format!("--area {a}")));
            }
            f.areas.push(a);
        }
        if let Some(s) = since {
            f.since = Some(normalise_time(s).ok_or_else(|| crate::diag::fail(code::FILTER_TIME_INVALID, format!("--since {s}")))?);
        }
        if let Some(u) = until {
            f.until = Some(normalise_time(u).ok_or_else(|| crate::diag::fail(code::FILTER_TIME_INVALID, format!("--until {u}")))?);
        }
        if let (Some(s), Some(u)) = (&f.since, &f.until) {
            if s > u {
                return Err(crate::diag::fail(code::FILTER_TIME_ORDER, format!("{s} > {u}")));
            }
        }
        Ok(f)
    }

    /// No filter at all.
    pub fn is_empty(&self) -> bool {
        self.grep.is_empty() && self.grep_not.is_empty() && self.areas.is_empty() && self.since.is_none() && self.until.is_none() && !self.only_hunted
    }

    /// Does an area pass?
    pub fn area_passes(&self, area: &str) -> bool {
        self.areas.is_empty() || self.areas.iter().any(|a| a.eq_ignore_ascii_case(area))
    }

    /// Does a timestamp pass since/until? An empty timestamp passes only without bounds.
    pub fn time_passes(&self, ts: &str) -> bool {
        if ts.is_empty() {
            return self.since.is_none() && self.until.is_none();
        }
        if let Some(s) = &self.since {
            if ts < s.as_str() {
                return false;
            }
        }
        if let Some(u) = &self.until {
            if ts >= u.as_str() {
                return false;
            }
        }
        true
    }

    /// Does a text pass grep / grep-not?
    pub fn text_passes(&self, haystack_lower: &str) -> bool {
        if self.grep_not.iter().any(|g| haystack_lower.contains(g.as_str())) {
            return false;
        }
        self.grep.is_empty() || self.grep.iter().any(|g| haystack_lower.contains(g.as_str()))
    }

    /// Does a row pass every filter?
    pub fn row_passes(&self, r: &Row) -> bool {
        if !self.area_passes(&r.area) || !self.time_passes(&r.timestamp) {
            return false;
        }
        if self.only_hunted && !matches!(r.tail.hunt.as_str(), "significant" | "candidate") {
            return false;
        }
        if self.grep.is_empty() && self.grep_not.is_empty() {
            return true;
        }
        let hay = format!("{}\n{}\n{}", r.path, r.key, r.detail).to_lowercase();
        self.text_passes(&hay)
    }

    /// Keeps the rows that pass; says how many were kept.
    pub fn apply(&self, rows: &mut Vec<Row>) {
        if self.is_empty() {
            return;
        }
        let before = rows.len();
        rows.retain(|r| self.row_passes(r));
        if self.only_hunted {
            crate::diag::info(code::FILTER_ONLY_HUNTED, format!("{} row(s)", rows.len()));
        }
        crate::diag::info(code::FILTER_APPLIED, format!("{} of {before} rows kept", rows.len()));
        if rows.is_empty() && before > 0 {
            crate::diag::warn(code::FILTER_EXCLUDED_ALL, format!("{before} rows"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Tail;
    use crate::timeline::State;

    fn row(area: &str, ts: &str, detail: &str, hunt: &str) -> Row {
        Row { timestamp: ts.into(), computer: "c".into(), artifact: format!("etc:{area}"), event_id: 0, state: State::Live, user: String::new(), area: area.into(), path: "etc/x".into(), key: "k".into(), item_type: "t".into(), time_source: "modified".into(), size: 1, detail: detail.into(), source_file: "s".into(), tail: Tail { hunt: hunt.into(), score: None, why: String::new() } }
    }

    #[test]
    fn times_normalise() {
        assert_eq!(normalise_time("2026-01-02").as_deref(), Some("2026-01-02T00:00:00.000000Z"));
        assert_eq!(normalise_time("2026-01-02 03:04:05").as_deref(), Some("2026-01-02T03:04:05.000000Z"));
        assert_eq!(normalise_time("2026-01-02T03:04:05.12Z").as_deref(), Some("2026-01-02T03:04:05.120000Z"));
        for bad in ["2026-13-01", "26-01-01", "2026-01-01T25:00:00", "x", "2026-01-01T00:00", "2026-01-01T00:00:00.1234567"] {
            assert!(normalise_time(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn building_and_errors() {
        crate::diag::set_quiet(true);
        assert!(Filter::new(&[], &[], &[], None, None, false).unwrap().is_empty());
        assert!(Filter::new(&[], &[], &[], Some("bad"), None, false).is_err());
        assert!(crate::diag::has(code::FILTER_TIME_INVALID));
        assert!(Filter::new(&[], &[], &[], Some("2026-02-01"), Some("2026-01-01"), false).is_err());
        assert!(crate::diag::has(code::FILTER_TIME_ORDER));
        assert!(Filter::new(&[], &[], &["bogus".into()], None, None, false).is_err());
        assert!(crate::diag::has(code::FILTER_AREA_UNKNOWN));
        let f = Filter::new(&["".into(), "X".into()], &["".into()], &["SUDO,cron".into()], None, None, false).unwrap();
        assert_eq!(f.grep, vec!["x"]);
        assert_eq!(f.areas, vec!["sudo", "cron"]);
        assert!(crate::diag::has(code::FILTER_GREP_EMPTY));
        crate::diag::drain();
    }

    #[test]
    fn rows_pass_or_not() {
        crate::diag::set_quiet(true);
        let f = Filter::new(&["curl".into()], &["safe".into()], &["cron".into()], Some("2026-01-01"), Some("2027-01-01"), false).unwrap();
        assert!(f.row_passes(&row("cron", "2026-05-01T00:00:00.000000Z", "curl x", "")));
        assert!(!f.row_passes(&row("sudo", "2026-05-01T00:00:00.000000Z", "curl x", "")));
        assert!(!f.row_passes(&row("cron", "2025-05-01T00:00:00.000000Z", "curl x", "")));
        assert!(!f.row_passes(&row("cron", "2027-01-01T00:00:00.000000Z", "curl x", "")));
        assert!(!f.row_passes(&row("cron", "", "curl x", "")));
        assert!(!f.row_passes(&row("cron", "2026-05-01T00:00:00.000000Z", "curl safe", "")));
        assert!(!f.row_passes(&row("cron", "2026-05-01T00:00:00.000000Z", "wget", "")));
        let h = Filter::new(&[], &[], &[], None, None, true).unwrap();
        let mut rows = vec![row("cron", "", "a", "significant"), row("cron", "", "b", "habitual"), row("cron", "", "c", ""), row("cron", "", "d", "candidate")];
        h.apply(&mut rows);
        assert_eq!(rows.len(), 2);
        assert!(crate::diag::has(code::FILTER_ONLY_HUNTED));
        let none = Filter::new(&["zzz".into()], &[], &[], None, None, false).unwrap();
        none.apply(&mut rows);
        assert!(rows.is_empty());
        assert!(crate::diag::has(code::FILTER_EXCLUDED_ALL));
        assert!(crate::diag::has(code::FILTER_APPLIED));
        crate::diag::drain();
    }
}
