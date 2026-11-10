//! The output folder: `timeline.csv`, one text dump per root and area, `files.txt`,
//! `roots.txt`, and with --json `timeline.jsonl`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use crate::run::{Outcome, ParsedFile};
use crate::timeline;

pub mod code {
    crate::codes! {
        OUT_DIR_FAILED = 500, "the output folder could not be created; check the path and the permissions";
        OUT_TIMELINE_FAILED = 501, "timeline.csv could not be written (disk full, permissions, a program holding the file)";
        OUT_JSON_FAILED = 502, "timeline.jsonl could not be written; the CSV was";
        OUT_DUMP_FAILED = 503, "a text dump could not be written; the timeline still holds its rows";
        OUT_INVENTORY_FAILED = 504, "files.txt or roots.txt could not be written; the timeline was";
        OUT_WRITTEN = 505, "the outputs were written; the message gives the folder, the rows and the dumps (shown with -v)";
        OUT_DUMP_NAME = 506, "two roots would give the same dump name; the root folder was added to tell them apart (shown with -vv)";
        OUT_NO_DUMPS = 507, "--no-dumps: only the timeline, files.txt and roots.txt were written";
        OUT_OVERWRITE = 508, "the output folder already held an etcdump timeline; it was replaced (shown with -v)";
    }
}

/// Creates the folder.
pub fn prepare_dir(dir: &Path) -> crate::diag::Result<()> {
    if dir.join("timeline.csv").exists() {
        crate::diag::info(code::OUT_OVERWRITE, dir.display().to_string());
    }
    std::fs::create_dir_all(dir).map_err(|e| crate::diag::fail(code::OUT_DIR_FAILED, format!("{}: {e}", dir.display())))
}

/// A name safe on every file system: letters, digits, dot, dash, underscore.
pub fn safe(s: &str) -> String {
    let t: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).collect();
    let t = t.trim_matches('_').to_string();
    if t.is_empty() {
        "root".into()
    } else {
        t
    }
}

/// The dump file of a file: `<item>_<mount>[_<root>]_<area>.txt`.
pub fn dump_name(f: &ParsedFile, with_item: bool) -> String {
    let root = if f.cf.root == "/" { String::new() } else { format!("_{}", safe(&f.cf.root)) };
    let item = if with_item { format!("{}_", safe(&f.cf.item)) } else { String::new() };
    format!("{item}{}{root}_{}.txt", safe(&f.cf.mount_label), f.cf.area)
}

/// The text of one dump: every file of one root and area, live first then deleted.
pub fn dump_text(files: &[&ParsedFile]) -> String {
    let mut s = String::new();
    if let Some(f) = files.first() {
        s.push_str(&format!("# etcdump {} · area {} · {} {}{}\n# {}\n\n", crate::VERSION, f.cf.area, f.cf.item, f.cf.mount_label, if f.cf.root == "/" { String::new() } else { f.cf.root.clone() }, crate::discover::AREAS.iter().find(|(a, _)| *a == f.cf.area).map(|a| a.1).unwrap_or("")));
    }
    let mut deleted_header = false;
    for f in files {
        if f.cf.deleted.is_some() && !deleted_header {
            s.push_str("[DELETED AND PREVIOUS VERSIONS]\n\n");
            deleted_header = true;
        }
        let t = &f.cf.entry.times;
        let mut head = format!("== {}  ({}, {} bytes", f.cf.rel, f.report.state.text(), f.report.size);
        if let Some(id) = &f.cf.deleted {
            head.push_str(&format!(", id {id}"));
        }
        for (n, v) in [("modified", t.modified), ("changed", t.changed), ("created", t.created)] {
            if let Some(v) = v {
                head.push_str(&format!(", {n} {}", v.to_rfc3339_micros()));
            }
        }
        if f.report.status != "ok" {
            head.push_str(&format!(", {}", f.report.status));
        }
        head.push_str(")\n");
        s.push_str(&head);
        for (it, tail) in &f.items {
            let line = if it.line > 0 { format!("[{:>4}] ", it.line) } else { "       ".to_string() };
            let mark = if tail.hunt.is_empty() { String::new() } else { format!("    <<< {} {}", tail.hunt, tail.why.split(':').next().unwrap_or("")) };
            s.push_str(&format!("  {line}{} = {}{mark}\n", it.key, it.value));
        }
        s.push('\n');
    }
    s
}

/// files.txt: one line per configuration file.
pub fn inventory_text(out: &Outcome) -> String {
    let mut s = String::from("# source\tarea\tparser\tstate\tsize\tmodified\tstatus\titems\trows\thits\n");
    for f in &out.files {
        let r = &f.report;
        s.push_str(&format!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n", r.source, r.area, r.parser, r.state.text(), r.size, r.modified, r.status, r.items, r.rows, r.hits));
    }
    s
}

/// roots.txt: one line per input with its computer and Linux roots.
pub fn roots_text(out: &Outcome) -> String {
    let mut s = String::from("# item\tcomputer\troots\n");
    for (label, computer, roots) in &out.items_read {
        s.push_str(&format!("{label}\t{computer}\t{}\n", roots.join(", ")));
    }
    s
}

/// Writes everything; the timeline failing is an error, the rest warnings.
pub fn write(dir: &Path, out: &Outcome, json: bool, dumps: bool) -> crate::diag::Result<usize> {
    prepare_dir(dir)?;
    let csv = dir.join("timeline.csv");
    let f = std::fs::File::create(&csv).map_err(|e| crate::diag::fail(code::OUT_TIMELINE_FAILED, format!("{}: {e}", csv.display())))?;
    timeline::write_csv(std::io::BufWriter::new(f), &out.rows).map_err(|e| crate::diag::fail(code::OUT_TIMELINE_FAILED, format!("{}: {e}", csv.display())))?;
    if json {
        let p = dir.join("timeline.jsonl");
        let r = std::fs::File::create(&p).and_then(|f| timeline::write_json(std::io::BufWriter::new(f), &out.rows));
        if let Err(e) = r {
            crate::diag::warn(code::OUT_JSON_FAILED, format!("{}: {e}", p.display()));
        }
    }
    for (name, text) in [("files.txt", inventory_text(out)), ("roots.txt", roots_text(out))] {
        if let Err(e) = std::fs::write(dir.join(name), text) {
            crate::diag::warn(code::OUT_INVENTORY_FAILED, format!("{name}: {e}"));
        }
    }
    let mut written = 0usize;
    if dumps {
        let with_item = out.items_read.len() > 1;
        let mut groups: BTreeMap<String, Vec<&ParsedFile>> = BTreeMap::new();
        for f in &out.files {
            groups.entry(dump_name(f, with_item)).or_default().push(f);
        }
        for (name, mut files) in groups {
            files.sort_by(|a, b| (a.cf.deleted.is_some(), &a.cf.rel, &a.cf.deleted).cmp(&(b.cf.deleted.is_some(), &b.cf.rel, &b.cf.deleted)));
            let p = dir.join(&name);
            match std::fs::File::create(&p).and_then(|mut f| f.write_all(dump_text(&files).as_bytes())) {
                Ok(()) => written += 1,
                Err(e) => {
                    crate::diag::warn(code::OUT_DUMP_FAILED, format!("{}: {e}", p.display()));
                }
            }
        }
    } else {
        crate::diag::info(code::OUT_NO_DUMPS, dir.display().to_string());
    }
    crate::diag::info(code::OUT_WRITTEN, format!("{}: {} row(s), {written} dump(s)", dir.display(), out.rows.len()));
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_names() {
        assert_eq!(safe("partition_0"), "partition_0");
        assert_eq!(safe("/[root]"), "root");
        assert_eq!(safe("a b/c"), "a_b_c");
        assert_eq!(safe("///"), "root");
    }

    #[test]
    fn prepare_and_write_fail_cleanly() {
        crate::diag::set_quiet(true);
        let dir = std::env::temp_dir().join(format!("etcdump_out_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out = Outcome::default();
        assert_eq!(write(&dir, &out, true, true).unwrap(), 0);
        assert!(dir.join("timeline.csv").exists() && dir.join("timeline.jsonl").exists() && dir.join("files.txt").exists() && dir.join("roots.txt").exists());
        assert!(crate::diag::has(code::OUT_WRITTEN));
        write(&dir, &out, false, false).unwrap();
        assert!(crate::diag::has(code::OUT_OVERWRITE));
        assert!(crate::diag::has(code::OUT_NO_DUMPS));
        // A file where the folder should be.
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, "x").unwrap();
        assert!(write(&blocker.join("sub"), &out, false, false).is_err());
        assert!(crate::diag::has(code::OUT_DIR_FAILED));
        let _ = std::fs::remove_dir_all(&dir);
        crate::diag::drain();
    }
}
