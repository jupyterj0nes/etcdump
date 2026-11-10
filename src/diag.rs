//! Diagnostics: stable codes, the sink that collects them, and the error type.
//!
//! Every failure, skip or decision the analyst may need to trace carries a code
//! `ED###_NAME`. Each module declares its codes with the `codes!` macro in a `pub mod code`
//! block, inside its area's range; [`catalog`] gathers them for `--codes` and `--explain`,
//! and a test checks that no number is used twice.
//!
//! | Range   | Area |
//! |---------|------|
//! | 000-099 | command line, run |
//! | 100-199 | finding Linux roots and configuration files inside the evidence |
//! | 200-349 | parsing each kind of configuration file |
//! | 350-449 | rules, hunt state and score |
//! | 450-499 | the timeline rows |
//! | 500-599 | text dumps, inventory and the other outputs |
//! | 600-649 | filters (grep, area, since, until) |
//! | 650-699 | measuring rule rarity on reference evidence |
//!
//! The codes of the crate underneath, `EF###` (evidencefs), are shown as they are:
//! etcdump drains its sink after each step and prints them with the same rules (errors and
//! warnings always, infos with `-v`).
//!
//! Diagnostics are recorded in a per-thread sink: a worker records while it reads one
//! file, drains the sink when the file is done and hands the list back, and the main
//! thread absorbs the lists in file order, so a run prints the same whatever the thread
//! count.

use std::cell::RefCell;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// A stable diagnostic code: `ED` + three digits + a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Code {
    pub id: u16,
    pub name: &'static str,
    /// What it means and what to do about it.
    pub help: &'static str,
}

impl Code {
    /// `ED###_NAME`.
    pub fn tag(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ED{:03}_{}", self.id, self.name)
    }
}

/// Declares a module's codes and its `CODES` list.
#[macro_export]
macro_rules! codes {
    ($( $konst:ident = $id:literal, $help:literal; )*) => {
        $( #[doc = $help] pub const $konst: $crate::diag::Code = $crate::diag::Code { id: $id, name: stringify!($konst), help: $help }; )*
        /// Every code of this module.
        pub const CODES: &[$crate::diag::Code] = &[$($konst),*];
    };
}

/// How bad a diagnostic is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// A decision or a count; nothing was lost.
    Info,
    /// The work went on without something.
    Warning,
    /// Something could not be done at all.
    Error,
}

impl Severity {
    /// `INFO`, `WARN`, `ERROR`.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Error => "ERROR",
        }
    }
}

/// One recorded diagnostic, from etcdump or from evidencefs (its tag then starts with `EF`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// `ED###_NAME` or `EF###_NAME`.
    pub tag: String,
    pub severity: Severity,
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity.label(), self.tag, self.message)
    }
}

/// A failure with its code. Displays as `ED###_NAME: message`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: Code,
    pub msg: String,
}

impl Error {
    pub fn new(code: Code, msg: impl Into<String>) -> Self {
        Error { code, msg: msg.into() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.msg)
    }
}

impl std::error::Error for Error {}

/// The crate's result.
pub type Result<T> = std::result::Result<T, Error>;

thread_local! {
    static SINK: RefCell<Vec<Diagnostic>> = const { RefCell::new(Vec::new()) };
}
static QUIET: AtomicBool = AtomicBool::new(false);
static VERBOSITY: AtomicU8 = AtomicU8::new(0);

/// Nothing on stderr (the sink still collects everything).
pub fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// 0: errors and warnings; 1: infos too; 2: everything, decisions included.
pub fn set_verbosity(v: u8) {
    VERBOSITY.store(v.min(2), Ordering::Relaxed);
}

pub fn verbosity() -> u8 {
    VERBOSITY.load(Ordering::Relaxed)
}

fn echo(d: &Diagnostic) {
    if is_quiet() {
        return;
    }
    if d.severity != Severity::Info || verbosity() >= 1 {
        eprintln!("{d}");
    }
}

/// Records a diagnostic of etcdump's own.
pub fn record(code: Code, severity: Severity, message: impl Into<String>) -> Diagnostic {
    let d = Diagnostic { tag: code.tag(), severity, message: message.into() };
    echo(&d);
    SINK.with(|s| s.borrow_mut().push(d.clone()));
    d
}

pub fn info(code: Code, message: impl Into<String>) -> Diagnostic {
    record(code, Severity::Info, message)
}

pub fn warn(code: Code, message: impl Into<String>) -> Diagnostic {
    record(code, Severity::Warning, message)
}

pub fn error(code: Code, message: impl Into<String>) -> Diagnostic {
    record(code, Severity::Error, message)
}

/// Builds an error and records it.
pub fn fail(code: Code, msg: impl Into<String>) -> Error {
    let e = Error::new(code, msg);
    error(code, e.msg.clone());
    e
}

/// Records a diagnostic that came from evidencefs, with its own tag.
pub fn record_foreign(tag: String, severity: Severity, message: String) {
    let d = Diagnostic { tag, severity, message };
    echo(&d);
    SINK.with(|s| s.borrow_mut().push(d));
}

/// Moves everything evidencefs recorded on this thread into etcdump's sink, with its tags
/// as they are.
pub fn surface_crates() {
    for d in evidencefs::diag::drain() {
        let sev = match d.severity {
            evidencefs::Severity::Info => Severity::Info,
            evidencefs::Severity::Warning => Severity::Warning,
            evidencefs::Severity::Error => Severity::Error,
        };
        record_foreign(d.code.tag(), sev, d.message);
    }
}

/// Removes and returns everything recorded on this thread.
pub fn drain() -> Vec<Diagnostic> {
    SINK.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// A copy of everything recorded on this thread.
pub fn snapshot() -> Vec<Diagnostic> {
    SINK.with(|s| s.borrow().clone())
}

/// Puts diagnostics drained on another thread into this one's sink, in order, without
/// echoing them again (the worker already did).
pub fn absorb(list: Vec<Diagnostic>) {
    SINK.with(|s| s.borrow_mut().extend(list));
}

/// Has this thread recorded the code?
pub fn has(code: Code) -> bool {
    let tag = code.tag();
    SINK.with(|s| s.borrow().iter().any(|d| d.tag == tag))
}

/// Has this thread recorded a diagnostic whose tag starts with `prefix` (`EF4`, `ED2`)?
pub fn has_tag_prefix(prefix: &str) -> bool {
    SINK.with(|s| s.borrow().iter().any(|d| d.tag.starts_with(prefix)))
}

/// How many of the code this thread recorded.
pub fn count(code: Code) -> usize {
    let tag = code.tag();
    SINK.with(|s| s.borrow().iter().filter(|d| d.tag == tag).count())
}

/// Every code of the crate, in number order.
pub fn catalog() -> Vec<Code> {
    let mut all: Vec<Code> = Vec::new();
    all.extend_from_slice(crate::run::code::CODES);
    all.extend_from_slice(crate::discover::code::CODES);
    all.extend_from_slice(crate::parse::code::CODES);
    all.extend_from_slice(crate::rules::code::CODES);
    all.extend_from_slice(crate::timeline::code::CODES);
    all.extend_from_slice(crate::output::code::CODES);
    all.extend_from_slice(crate::filter::code::CODES);
    all.extend_from_slice(crate::measure::code::CODES);
    all.sort_by_key(|c| c.id);
    all
}

/// The code with this number, tag or name.
pub fn lookup(what: &str) -> Option<Code> {
    let w = what.trim();
    let num: Option<u16> = w.strip_prefix("ED").or_else(|| w.strip_prefix("ed")).map(|rest| rest.split('_').next().unwrap_or(rest)).unwrap_or(w).parse().ok();
    catalog().into_iter().find(|c| Some(c.id) == num || c.name.eq_ignore_ascii_case(w) || c.tag().eq_ignore_ascii_case(w))
}

/// A Markdown table of every code, for `docs/codes.md` and `--codes`.
pub fn codes_markdown() -> String {
    let mut s = String::from("# Diagnostic codes\n\nEvery code etcdump can print, with what it means and what to do about it. The ranges are in `src/diag.rs`. Codes starting with `EF` come from [evidencefs](https://github.com/jupyterj0nes/evidencefs); they are printed as that crate records them and explained in its own `docs/codes.md`.\n\n| Code | Meaning |\n|---|---|\n");
    for c in catalog() {
        s.push_str(&format!("| `{c}` | {} |\n", c.help.replace('|', "\\|")));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_in_range() {
        let all = catalog();
        assert!(all.len() > 120, "many codes ({})", all.len());
        let mut seen = std::collections::HashSet::new();
        for c in &all {
            assert!(c.id < 700, "{c} out of range");
            assert!(seen.insert(c.id), "code {} used twice", c.id);
            assert!(c.help.len() > 25, "{c}: help too short");
            assert!(c.name.chars().all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_'), "{c}: name");
        }
        let ranges: [(&[Code], std::ops::Range<u16>); 8] = [
            (crate::run::code::CODES, 0..100),
            (crate::discover::code::CODES, 100..200),
            (crate::parse::code::CODES, 200..350),
            (crate::rules::code::CODES, 350..450),
            (crate::timeline::code::CODES, 450..500),
            (crate::output::code::CODES, 500..600),
            (crate::filter::code::CODES, 600..650),
            (crate::measure::code::CODES, 650..700),
        ];
        for (codes, range) in ranges {
            for c in codes {
                assert!(range.contains(&c.id), "{c} outside {range:?}");
            }
        }
    }

    #[test]
    fn display_lookup_and_markdown() {
        let c = Code { id: 7, name: "X_Y", help: "something to say about it, long enough" };
        assert_eq!(c.to_string(), "ED007_X_Y");
        let first = catalog()[0];
        assert_eq!(lookup(&first.tag()), Some(first));
        assert_eq!(lookup(&first.id.to_string()), Some(first));
        assert_eq!(lookup(first.name), Some(first));
        assert_eq!(lookup(&format!("ED{:03}", first.id)), Some(first));
        assert_eq!(lookup(&format!("ed{:03}", first.id)), Some(first));
        assert_eq!(lookup("ED999"), None);
        assert_eq!(lookup("nonsense"), None);
        let md = codes_markdown();
        for c in catalog() {
            assert!(md.contains(&c.tag()));
        }
        assert!(md.contains("evidencefs"));
    }

    #[test]
    fn sink_per_thread_and_foreign_tags() {
        set_quiet(true);
        drain();
        let c = crate::run::code::RUN_STARTED;
        info(c, "a");
        warn(c, "b");
        let e = fail(c, "c");
        assert_eq!(e.to_string(), format!("{c}: c"));
        assert_eq!(count(c), 3);
        assert!(has(c));
        assert_eq!(std::thread::spawn(|| snapshot().len()).join().unwrap(), 0);
        record_foreign("EF001_X".into(), Severity::Warning, "foreign".into());
        assert!(has_tag_prefix("EF0"));
        assert!(!has_tag_prefix("DH"));
        let list = drain();
        assert_eq!(list.len(), 4);
        assert_eq!(list[0].severity, Severity::Info);
        assert_eq!(list[2].severity, Severity::Error);
        assert_eq!(list[3].to_string(), "[WARN] EF001_X: foreign");
        assert!(snapshot().is_empty());
        absorb(list);
        assert_eq!(snapshot().len(), 4);
        drain();
        evidencefs::diag::set_quiet(true);
        evidencefs::diag::info(evidencefs::source::code::IMAGE_NOT_FOUND, "y");
        surface_crates();
        let list = drain();
        assert_eq!(list.len(), 1);
        assert!(list[0].tag.starts_with("EF001"));
        assert_eq!(Severity::Error.label(), "ERROR");
        assert!(Severity::Error > Severity::Info);
        set_verbosity(9);
        assert_eq!(verbosity(), 2);
        set_verbosity(0);
    }
}
