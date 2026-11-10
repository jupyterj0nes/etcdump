//! The timeline rows and how they are written: the c00pr 19-column CSV and JSON lines.
//!
//! The layout is masstin's: fourteen event columns, each etcdump field in the vertical of
//! the masstin field that means the same thing, under etcdump's own names, then the
//! shared analysis tail of five columns. etcdump fills `hunt`, `hunt_score` and
//! `hunt_why` from its rules and leaves `verdict` and `notes`, the analyst's, empty. See
//! `docs/csv-format.md`.

use std::io::Write;

use crate::rules::Tail;

pub mod code {
    crate::codes! {
        ROWS_SORTED = 450, "the rows were sorted by time, then by every other column, and rows identical in every column were written once";
        ROWS_DUPLICATES = 451, "rows identical in every column were collapsed: the same item reached etcdump twice (a file and its backup with the same content, two overlapping inputs)";
        ROWS_NO_TIME = 452, "a file has no usable time (a deleted entry without times, an archive member without a date); its rows carry an empty timestamp and sort first";
        ROWS_JSON_FAILED = 453, "a row could not be serialised to JSON (not expected: the fields are text and numbers); the row was skipped";
        ROWS_EMPTY = 454, "no row came out of the configuration: no Linux root, every file empty, or every row filtered out";
        ROWS_ITEM_TIME = 455, "rows of this file take the time the item itself carries (shadow's last change, a package's install) rather than the file's (shown with -vv)";
        ROWS_FILE_TIME = 456, "the row time is the file's modification time; the change and birth times are in detail when the file system keeps them (shown with -vv)";
    }
}

/// The fourteen event column names, in masstin's order.
pub const HEADERS: [&str; 14] = ["timestamp", "computer", "artifact", "event_id", "state", "user", "area", "path", "key", "item_type", "time_source", "size", "detail", "source_file"];

/// The analysis tail every c00pr tool shares.
pub const TAIL: [&str; 5] = ["hunt", "hunt_score", "hunt_why", "verdict", "notes"];

/// How a row was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum State {
    /// Read from the file as it is.
    Live,
    /// Read from a deleted file or a previous version the file system still describes.
    Deleted,
    /// Read from a snapshot mount.
    Vss,
}

impl State {
    /// The `state` column.
    pub fn text(self) -> &'static str {
        match self {
            State::Live => "live",
            State::Deleted => "deleted",
            State::Vss => "vss",
        }
    }

    /// The segment added to `artifact`.
    pub fn artifact_suffix(self) -> &'static str {
        match self {
            State::Live => "",
            State::Deleted => ":deleted",
            State::Vss => ":vss",
        }
    }

    pub fn of(deleted: bool, snapshot: bool) -> State {
        if deleted {
            State::Deleted
        } else if snapshot {
            State::Vss
        } else {
            State::Live
        }
    }
}

/// One timeline row: the fourteen event columns and the tail.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Row {
    /// Fixed-width UTC text, or empty.
    pub timestamp: String,
    pub computer: String,
    /// `etc:<area>`, with `:deleted` or `:vss`.
    pub artifact: String,
    /// Always 0.
    pub event_id: u64,
    pub state: State,
    /// The account the item concerns.
    pub user: String,
    pub area: String,
    /// The path from the root: `etc/passwd`.
    pub path: String,
    pub key: String,
    /// `account`, `sudo_rule`, `directive`...
    pub item_type: String,
    /// What the timestamp is: `modified`, `changed`, `created`, `shadow_last_change`,
    /// `dpkg_info_list`, or empty.
    pub time_source: String,
    /// The file's size.
    pub size: u64,
    /// The value, then ` | line=N | file_modified=... | file_changed=... | file_created=...`.
    pub detail: String,
    /// `<mount>/<path on the mount>`, the item's name first when several were given.
    pub source_file: String,
    pub tail: Tail,
}

/// Quotes a text field the way masstin does: always in double quotes, inner quotes doubled,
/// line breaks replaced by spaces.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\"\""),
            '\r' | '\n' => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The header line.
pub fn header_line() -> String {
    let mut all: Vec<&str> = HEADERS.to_vec();
    all.extend_from_slice(&TAIL);
    all.join(",")
}

impl Row {
    /// The CSV line: text fields quoted, the numbers bare, an empty tail bare (`,,,,,`).
    pub fn csv_line(&self) -> String {
        let head = format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            quote(&self.timestamp),
            quote(&self.computer),
            quote(&self.artifact),
            self.event_id,
            quote(self.state.text()),
            quote(&self.user),
            quote(&self.area),
            quote(&self.path),
            quote(&self.key),
            quote(&self.item_type),
            quote(&self.time_source),
            self.size,
            quote(&self.detail),
            quote(&self.source_file)
        );
        if self.tail == Tail::default() {
            return format!("{head},,,,,");
        }
        let score = self.tail.score.map(|s| s.to_string()).unwrap_or_default();
        format!("{head},{},{score},{},,", quote(&self.tail.hunt), quote(&self.tail.why))
    }

    /// The row as one JSON object.
    pub fn json(&self) -> String {
        let mut m = serde_json::Map::new();
        m.insert("timestamp".into(), self.timestamp.clone().into());
        m.insert("computer".into(), self.computer.clone().into());
        m.insert("artifact".into(), self.artifact.clone().into());
        m.insert("event_id".into(), self.event_id.into());
        m.insert("state".into(), self.state.text().into());
        m.insert("user".into(), self.user.clone().into());
        m.insert("area".into(), self.area.clone().into());
        m.insert("path".into(), self.path.clone().into());
        m.insert("key".into(), self.key.clone().into());
        m.insert("item_type".into(), self.item_type.clone().into());
        m.insert("time_source".into(), self.time_source.clone().into());
        m.insert("size".into(), self.size.into());
        m.insert("detail".into(), self.detail.clone().into());
        m.insert("source_file".into(), self.source_file.clone().into());
        m.insert("hunt".into(), self.tail.hunt.clone().into());
        m.insert("hunt_score".into(), self.tail.score.map(serde_json::Value::from).unwrap_or(serde_json::Value::Null));
        m.insert("hunt_why".into(), self.tail.why.clone().into());
        serde_json::Value::Object(m).to_string()
    }
}

/// Sorts by time then by every column and drops exact duplicates. Returns how many were
/// dropped.
pub fn finish(rows: &mut Vec<Row>) -> usize {
    let before = rows.len();
    rows.sort();
    rows.dedup();
    let dropped = before - rows.len();
    if dropped > 0 {
        crate::diag::info(code::ROWS_DUPLICATES, format!("{dropped} duplicate row(s) collapsed"));
    }
    let untimed = rows.iter().filter(|r| r.timestamp.is_empty()).count();
    if untimed > 0 {
        crate::diag::info(code::ROWS_NO_TIME, format!("{untimed} row(s)"));
    }
    if rows.is_empty() {
        crate::diag::warn(code::ROWS_EMPTY, "no rows");
    }
    crate::diag::info(code::ROWS_SORTED, format!("{} rows", rows.len()));
    dropped
}

/// Writes the CSV: header, then one line per row.
pub fn write_csv(mut w: impl Write, rows: &[Row]) -> std::io::Result<()> {
    writeln!(w, "{}", header_line())?;
    for r in rows {
        writeln!(w, "{}", r.csv_line())?;
    }
    w.flush()
}

/// Writes JSON lines: one object per row.
pub fn write_json(mut w: impl Write, rows: &[Row]) -> std::io::Result<()> {
    for r in rows {
        writeln!(w, "{}", r.json())?;
    }
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> Row {
        Row {
            timestamp: "2026-11-03T10:00:00.000000Z".into(),
            computer: "LNX".into(),
            artifact: "etc:accounts".into(),
            event_id: 0,
            state: State::Live,
            user: "toor".into(),
            area: "accounts".into(),
            path: "etc/passwd".into(),
            key: "toor".into(),
            item_type: "account".into(),
            time_source: "modified".into(),
            size: 1200,
            detail: "uid=0 \"x\"\nnext".into(),
            source_file: "folder/etc/passwd".into(),
            tail: Tail::default(),
        }
    }

    #[test]
    fn header_has_nineteen_columns_in_masstin_order() {
        let h = header_line();
        assert_eq!(h.split(',').count(), 19);
        assert!(h.starts_with("timestamp,computer,artifact,event_id,state,user,area"));
        assert!(h.ends_with("hunt,hunt_score,hunt_why,verdict,notes"));
    }

    #[test]
    fn csv_lines_quote_and_tail() {
        let r = row();
        let line = r.csv_line();
        assert!(line.ends_with("\"folder/etc/passwd\",,,,,"), "{line}");
        assert!(line.contains("\"uid=0 \"\"x\"\" next\""));
        assert!(line.contains(",0,\"live\","));
        assert!(line.contains(",1200,"));
        let mut hit = r.clone();
        hit.tail = Tail { hunt: "significant".into(), score: Some(39), why: "rule LNX-UID0-ACCOUNT (high): w".into() };
        let line = hit.csv_line();
        assert!(line.ends_with(",\"significant\",39,\"rule LNX-UID0-ACCOUNT (high): w\",,"), "{line}");
        let mut hab = r;
        hab.tail = Tail { hunt: "habitual".into(), score: None, why: "w".into() };
        assert!(hab.csv_line().ends_with(",\"habitual\",,\"w\",,"));
    }

    #[test]
    fn json_lines() {
        let mut r = row();
        r.tail = Tail { hunt: "candidate".into(), score: Some(21), why: "x".into() };
        let v: serde_json::Value = serde_json::from_str(&r.json()).unwrap();
        assert_eq!(v["area"], "accounts");
        assert_eq!(v["hunt_score"], 21);
        assert_eq!(v["state"], "live");
        let mut buf = Vec::new();
        write_json(&mut buf, &[row()]).unwrap();
        let v: serde_json::Value = serde_json::from_str(String::from_utf8(buf).unwrap().trim()).unwrap();
        assert!(v["hunt_score"].is_null());
    }

    #[test]
    fn states() {
        assert_eq!(State::of(true, true), State::Deleted);
        assert_eq!(State::of(false, true), State::Vss);
        assert_eq!(State::of(false, false), State::Live);
        assert_eq!(State::Deleted.artifact_suffix(), ":deleted");
        assert_eq!(State::Vss.text(), "vss");
        assert_eq!(State::Live.artifact_suffix(), "");
    }

    #[test]
    fn finish_sorts_and_dedups() {
        crate::diag::set_quiet(true);
        let a = row();
        let mut b = row();
        b.timestamp = "2025-01-01T00:00:00.000000Z".into();
        let mut c = row();
        c.timestamp.clear();
        let mut rows = vec![a.clone(), b.clone(), a, c];
        assert_eq!(finish(&mut rows), 1);
        assert_eq!(rows.len(), 3);
        assert!(rows[0].timestamp.is_empty());
        assert_eq!(rows[1].timestamp, b.timestamp);
        assert!(crate::diag::has(code::ROWS_DUPLICATES));
        assert!(crate::diag::has(code::ROWS_NO_TIME));
        let mut none: Vec<Row> = Vec::new();
        finish(&mut none);
        assert!(crate::diag::has(code::ROWS_EMPTY));
        let mut buf = Vec::new();
        write_csv(&mut buf, &rows).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap().lines().count(), 4);
        crate::diag::drain();
    }
}
