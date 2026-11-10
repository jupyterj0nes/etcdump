//! The run: inputs → Linux roots → configuration files → items → rules → rows.
//!
//! Each input is opened on its own thread (an evidencefs `Evidence` is not `Send`, so the
//! thread that opens it lists and reads its files); the bytes come back to the caller,
//! which parses them and runs the rules on a rayon pool. Rows are sorted and every
//! diagnostic is absorbed in input and file order, so the output is the same byte for byte
//! whatever the thread count.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rayon::prelude::*;

use crate::discover::{self, ConfigFile, FindOptions};
use crate::filter::Filter;
use crate::parse::{self, Ctx, Item};
use crate::rules::{self, RuleSet, Tail};
use crate::timeline::{self, Row, State};

pub mod code {
    crate::codes! {
        RUN_STARTED = 0, "the run started; the message gives the inputs and the thread count (shown with -v)";
        RUN_DONE = 1, "the run finished; the message gives the roots, files, items and rows (shown with -v)";
        CLI_NO_INPUT = 2, "no -d or -f was given: name at least one evidence item (a folder, a triage package, an archive or a disk image)";
        CLI_NO_OUTPUT = 3, "no -o was given: name the output folder (it is created when missing)";
        CLI_EXPLAIN_UNKNOWN = 4, "--explain names no etcdump code; --codes lists them all";
        RUN_INPUT_MISSING = 5, "an input path does not exist; it is skipped and the run goes on with the others";
        RUN_NO_ROOT_ANYWHERE = 6, "no input held a Linux root: there is nothing to read (hivedump reads Windows registry hives)";
        RUN_THREADS = 7, "the worker pool size: --threads, or every core when it is 0 (shown with -v)";
        RUN_FILE_UNREADABLE = 8, "a configuration file could not be read; it is in files.txt as unreadable and gives no rows";
        RUN_FILE_TOO_LARGE = 9, "a configuration file is larger than --max-file-bytes; it is one file item in the timeline and not parsed";
        RUN_DELETED_READ = 10, "a deleted configuration file or a previous version was read back from the file system; its rows carry state deleted";
        RUN_DELETED_EMPTY = 11, "a deleted configuration file is described by the metadata but nothing can be read back; it is in files.txt with no rows";
        RUN_HUNT = 12, "rules were run over every item; the message gives the significant, candidate and habitual rows (shown with -v)";
        RUN_LIST_RULES = 13, "--list-rules printed the rules that would run (built-in and --rules), then exited";
        RUN_LIST_AREAS = 14, "--list-areas printed the configuration areas etcdump reads, then exited";
        RUN_MEASURE = 15, "--measure: instead of a timeline, the rules were measured on the inputs taken as clean reference evidence; rarity.tsv and reference.tsv were written";
        RUN_ITEM_DONE = 16, "an input was read; the message gives its roots and configuration files (shown with -v)";
    }
}

/// What a run does.
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub inputs: Vec<PathBuf>,
    pub hostname: Option<String>,
    pub no_deleted: bool,
    pub no_vss: bool,
    pub max_file_bytes: u64,
    pub max_items: usize,
    pub rules: Vec<PathBuf>,
    pub no_builtin_rules: bool,
    pub reference: Vec<PathBuf>,
    pub no_hunt: bool,
    pub filter: Filter,
    pub threads: usize,
}

/// One configuration file as read.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub cf: ConfigFile,
    pub computer: String,
    /// Several inputs: the item name goes first in source_file.
    pub item_prefix: bool,
    pub bytes: Option<Vec<u8>>,
    pub too_large: bool,
    pub dpkg_times: BTreeMap<String, evidencefs::time::Timestamp>,
}

/// What one input gave.
#[derive(Debug, Default)]
pub struct ItemRead {
    pub label: String,
    pub computer: String,
    pub roots: Vec<String>,
    pub files: Vec<Loaded>,
    pub diags: Vec<crate::diag::Diagnostic>,
}

/// What one file gave, for files.txt and the summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileReport {
    pub item: String,
    pub computer: String,
    pub source: String,
    pub rel: String,
    pub area: &'static str,
    pub parser: &'static str,
    pub state: State,
    pub size: u64,
    pub modified: String,
    pub status: &'static str,
    pub items: usize,
    pub rows: usize,
    pub hits: usize,
}

/// One parsed file: its items with their tails, ready for the dumps.
#[derive(Clone, Debug)]
pub struct ParsedFile {
    pub report: FileReport,
    pub cf: ConfigFile,
    pub items: Vec<(Item, Tail)>,
}

/// What a run gave.
#[derive(Debug, Default)]
pub struct Outcome {
    pub rows: Vec<Row>,
    pub files: Vec<ParsedFile>,
    pub items_read: Vec<(String, String, Vec<String>)>,
}

fn ts(t: Option<evidencefs::time::Timestamp>) -> String {
    t.map(|t| t.to_rfc3339_micros()).unwrap_or_default()
}

/// The item label of a path: its file or folder name.
pub fn label_of(p: &std::path::Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| p.display().to_string())
}

/// Opens one input and reads its configuration files (on the calling thread).
pub fn read_item(path: &std::path::Path, opts: &Options, item_prefix: bool) -> ItemRead {
    let label = label_of(path);
    let mut out = ItemRead { label: label.clone(), ..Default::default() };
    if !path.exists() {
        crate::diag::warn(code::RUN_INPUT_MISSING, path.display().to_string());
        out.diags = crate::diag::drain();
        return out;
    }
    let ev = match discover::open(path, !opts.no_vss) {
        Ok(ev) => ev,
        Err(_) => {
            out.diags = crate::diag::drain();
            return out;
        }
    };
    out.computer = discover::computer(&ev, opts.hostname.as_deref(), &label);
    let fopts = FindOptions { deleted: !opts.no_deleted, snapshots: !opts.no_vss, areas: opts.filter.areas.clone(), ..Default::default() };
    let roots = discover::roots(&ev);
    let files = discover::find_in(&ev, &label, &roots, &fopts);
    let mut dpkg_cache: BTreeMap<(usize, String), BTreeMap<String, evidencefs::time::Timestamp>> = BTreeMap::new();
    out.roots = roots.iter().map(|(m, r)| format!("{}{}", ev.mounts[*m].label, if r == "/" { String::new() } else { r.clone() })).collect();
    for cf in files {
        let m = &ev.mounts[cf.mount];
        let size = cf.entry.size;
        let (bytes, too_large) = if cf.entry.link_target.is_some() {
            (Some(Vec::new()), false)
        } else if size > opts.max_file_bytes {
            crate::diag::warn(code::RUN_FILE_TOO_LARGE, format!("{}: {size} bytes", cf.source()));
            (None, true)
        } else {
            match m.fs.read(&cf.path, None, opts.max_file_bytes) {
                Ok(b) => {
                    if cf.deleted.is_some() {
                        crate::diag::info(code::RUN_DELETED_READ, cf.source());
                    }
                    (Some(b), false)
                }
                Err(e) => {
                    if cf.deleted.is_some() {
                        crate::diag::info(code::RUN_DELETED_EMPTY, format!("{}: {e}", cf.source()));
                    } else {
                        crate::diag::warn(code::RUN_FILE_UNREADABLE, format!("{}: {e}", cf.source()));
                    }
                    (None, false)
                }
            }
        };
        crate::diag::surface_crates();
        let dpkg_times = if cf.parser == parse::Parser::DpkgStatus { dpkg_cache.entry((cf.mount, cf.root.clone())).or_insert_with(|| discover::dpkg_times(&ev, cf.mount, &cf.root)).clone() } else { BTreeMap::new() };
        out.files.push(Loaded { cf, computer: out.computer.clone(), item_prefix, bytes, too_large, dpkg_times });
    }
    crate::diag::info(code::RUN_ITEM_DONE, format!("{label}: {} root(s), {} file(s)", out.roots.len(), out.files.len()));
    out.diags = crate::diag::drain();
    out
}

/// Parses one loaded file and runs the rules: its rows and its report.
pub fn process(l: &Loaded, set: &RuleSet, opts: &Options) -> (Vec<Row>, ParsedFile) {
    let cf = &l.cf;
    let state = State::of(cf.deleted.is_some(), cf.snapshot);
    let source = if l.item_prefix { format!("{}:{}", cf.item, cf.source()) } else { cf.source() };
    let times = &cf.entry.times;
    let (file_time, file_source) = match (times.modified, times.changed, times.created) {
        (Some(t), _, _) => (Some(t), "modified"),
        (None, Some(t), _) => (Some(t), "changed"),
        (None, None, Some(t)) => (Some(t), "created"),
        _ => (None, ""),
    };
    let mut report = FileReport { item: cf.item.clone(), computer: l.computer.clone(), source: source.clone(), rel: cf.rel.clone(), area: cf.area, parser: cf.parser.name(), state, size: cf.entry.size, modified: ts(times.modified), status: "ok", items: 0, rows: 0, hits: 0 };
    let parsed = match (&l.bytes, l.too_large) {
        (_, true) => {
            report.status = "too_large";
            parse::Parsed { items: vec![Item::new(cf.entry.name.clone(), format!("size={} not parsed (over --max-file-bytes)", cf.entry.size), "file", 0)], ..Default::default() }
        }
        (None, false) => {
            report.status = if cf.deleted.is_some() { "deleted_unreadable" } else { "unreadable" };
            return (Vec::new(), ParsedFile { report, cf: cf.clone(), items: Vec::new() });
        }
        (Some(b), false) => {
            let ctx = Ctx { file_name: cf.entry.name.clone(), link_target: cf.entry.link_target.clone(), size: cf.entry.size, dpkg_times: l.dpkg_times.clone(), max_items: opts.max_items };
            parse::parse(cf.parser, b, &ctx)
        }
    };
    if parsed.items.iter().any(|i| i.time.is_some()) {
        crate::diag::record(timeline::code::ROWS_ITEM_TIME, crate::diag::Severity::Info, cf.rel.clone());
    }
    let owner = cf.owner();
    let artifact = format!("etc:{}{}", cf.area, state.artifact_suffix());
    let extra = {
        let mut e = String::new();
        for (name, t) in [("file_modified", times.modified), ("file_changed", times.changed), ("file_created", times.created)] {
            if let Some(t) = t {
                e.push_str(&format!(" | {name}={}", t.to_rfc3339_micros()));
            }
        }
        if let Some(id) = &cf.deleted {
            e.push_str(&format!(" | deleted_id={id}"));
            if let Some(d) = cf.entry.deleted_at {
                e.push_str(&format!(" | deleted_at={}", d.to_rfc3339_micros()));
            }
        }
        e
    };
    let mut rows = Vec::new();
    let mut items = Vec::new();
    for it in parsed.items {
        let tail = if opts.no_hunt { Tail::default() } else { rules::judge(&set.hits(cf.area, &cf.rel, &it)) };
        if !tail.hunt.is_empty() && tail.hunt != "habitual" {
            report.hits += 1;
        }
        let (t, tsrc) = match it.time {
            Some((t, s)) => (Some(t), s),
            None => (file_time, file_source),
        };
        let user = if !it.user.is_empty() { it.user.clone() } else { owner.clone() };
        let line = if it.line > 0 { format!(" | line={}", it.line) } else { String::new() };
        rows.push(Row {
            timestamp: ts(t),
            computer: l.computer.clone(),
            artifact: artifact.clone(),
            event_id: 0,
            state,
            user,
            area: cf.area.to_string(),
            path: cf.rel.clone(),
            key: it.key.clone(),
            item_type: it.kind.to_string(),
            time_source: tsrc.to_string(),
            size: cf.entry.size,
            detail: format!("{}{line}{extra}", it.value),
            source_file: source.clone(),
            tail: tail.clone(),
        });
        items.push((it, tail));
    }
    report.items = items.len();
    report.rows = rows.len();
    (rows, ParsedFile { report, cf: cf.clone(), items })
}

/// Runs everything; `progress(done, total, what)` is called as files are parsed.
pub fn run(opts: &Options, progress: &(dyn Fn(usize, usize, &str) + Sync)) -> crate::diag::Result<Outcome> {
    let threads = if opts.threads == 0 { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) } else { opts.threads };
    crate::diag::info(code::RUN_THREADS, format!("{threads}"));
    crate::diag::info(code::RUN_STARTED, format!("{} input(s), {threads} thread(s)", opts.inputs.len()));
    let set = if opts.no_hunt {
        crate::diag::info(rules::code::RULES_DISABLED, "--no-hunt");
        RuleSet::default()
    } else {
        RuleSet::load(!opts.no_builtin_rules, &opts.rules, &opts.reference)
    };
    let prefix = opts.inputs.len() > 1;
    progress(0, opts.inputs.len().max(1), "opening the evidence");
    // One thread per input, at most `threads` at a time; results kept in input order.
    let mut reads: Vec<ItemRead> = Vec::new();
    for chunk in opts.inputs.chunks(threads.max(1)) {
        let got: Vec<ItemRead> = std::thread::scope(|s| {
            let handles: Vec<_> = chunk.iter().map(|p| s.spawn(move || read_item(p, opts, prefix))).collect();
            handles
                .into_iter()
                .zip(chunk)
                .map(|(h, p)| {
                    h.join().unwrap_or_else(|_| {
                        crate::diag::error(discover::code::DISC_ITEM_THREAD_FAILED, p.display().to_string());
                        ItemRead { label: label_of(p), ..Default::default() }
                    })
                })
                .collect()
        });
        reads.extend(got);
    }
    let mut outcome = Outcome::default();
    let mut loaded: Vec<Loaded> = Vec::new();
    for r in reads {
        crate::diag::absorb(r.diags);
        outcome.items_read.push((r.label, r.computer, r.roots));
        loaded.extend(r.files);
    }
    if outcome.items_read.iter().all(|(_, _, roots)| roots.is_empty()) {
        crate::diag::warn(code::RUN_NO_ROOT_ANYWHERE, format!("{} input(s)", opts.inputs.len()));
    }
    let total = loaded.len();
    let done = std::sync::atomic::AtomicUsize::new(0);
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().map_err(|e| crate::diag::fail(code::RUN_THREADS, e.to_string()))?;
    let results: Vec<(Vec<Row>, ParsedFile, Vec<crate::diag::Diagnostic>)> = pool.install(|| {
        loaded
            .par_iter()
            .map(|l| {
                let (rows, pf) = process(l, &set, opts);
                let d = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                progress(d, total.max(1), &l.cf.rel);
                (rows, pf, crate::diag::drain())
            })
            .collect()
    });
    for (rows, pf, diags) in results {
        crate::diag::absorb(diags);
        outcome.rows.extend(rows);
        outcome.files.push(pf);
    }
    opts.filter.apply(&mut outcome.rows);
    timeline::finish(&mut outcome.rows);
    if !opts.no_hunt {
        let count = |h: &str| outcome.rows.iter().filter(|r| r.tail.hunt == h).count();
        crate::diag::info(code::RUN_HUNT, format!("{} significant, {} candidate, {} habitual", count("significant"), count("candidate"), count("habitual")));
    }
    crate::diag::info(code::RUN_DONE, format!("{} root(s), {} file(s), {} row(s)", outcome.items_read.iter().map(|i| i.2.len()).sum::<usize>(), outcome.files.len(), outcome.rows.len()));
    Ok(outcome)
}

impl Outcome {
    /// The summary printed with --summary.
    pub fn summary_text(&self) -> String {
        let mut s = String::new();
        for (label, computer, roots) in &self.items_read {
            s.push_str(&format!("{label}: computer {computer}, {} Linux root(s){}\n", roots.len(), if roots.is_empty() { String::new() } else { format!(" ({})", roots.join(", ")) }));
        }
        let mut per_area: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();
        for f in &self.files {
            let e = per_area.entry(f.report.area).or_default();
            e.0 += 1;
            e.1 += f.report.rows;
            e.2 += f.report.hits;
        }
        s.push_str("area          files    rows   hits\n");
        for (area, _) in discover::AREAS {
            if let Some((f, r, h)) = per_area.get(area) {
                s.push_str(&format!("{area:<12} {f:>6} {r:>7} {h:>6}\n"));
            }
        }
        let deleted = self.files.iter().filter(|f| f.report.state == State::Deleted).count();
        let unreadable = self.files.iter().filter(|f| f.report.status != "ok").count();
        s.push_str(&format!("{} file(s), {deleted} deleted or previous version(s), {unreadable} not parsed, {} row(s)\n", self.files.len(), self.rows.len()));
        let mut top: Vec<&Row> = self.rows.iter().filter(|r| matches!(r.tail.hunt.as_str(), "significant" | "candidate")).collect();
        top.sort_by(|a, b| (b.tail.hunt == "significant").cmp(&(a.tail.hunt == "significant")).then(b.tail.score.cmp(&a.tail.score)).then(a.timestamp.cmp(&b.timestamp)));
        if !top.is_empty() {
            s.push_str("first to read:\n");
            for r in top.iter().take(10) {
                let rule = r.tail.why.split(':').next().unwrap_or("");
                s.push_str(&format!("  {} {:>3} {} {} {} = {} ({rule})\n", r.tail.hunt, r.tail.score.map(|x| x.to_string()).unwrap_or_default(), r.timestamp, r.path, r.key, r.detail.split(" | ").next().unwrap_or("")));
            }
        }
        s
    }
}
