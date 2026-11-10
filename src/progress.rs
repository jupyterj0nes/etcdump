//! Progress: a bar on a terminal, or plain lines for a program that runs etcdump.
//!
//! With `ETCDUMP_PROGRESS_PIPE=1` in the environment every update is one line on stderr,
//! `@@pb <pos>/<len> <message>`, at most a few per second (the last one always goes out),
//! so a parent process such as agentc00pr draws the progress itself; no terminal is
//! needed. Otherwise an indicatif bar is drawn, unless quiet.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressStyle};

/// The environment variable that switches to pipe lines.
pub const PIPE_ENV: &str = "ETCDUMP_PROGRESS_PIPE";

/// Minimum time between two pipe lines.
pub const PIPE_THROTTLE: Duration = Duration::from_millis(250);

pub enum Reporter {
    Silent,
    Bar(ProgressBar),
    Pipe(Mutex<PipeState>),
}

pub struct PipeState {
    last: Option<Instant>,
    last_total: usize,
}

impl Reporter {
    /// Picks the reporter from the environment and the quiet flag.
    pub fn new(quiet: bool) -> Reporter {
        if std::env::var_os(PIPE_ENV).is_some() {
            return Reporter::Pipe(Mutex::new(PipeState { last: None, last_total: 0 }));
        }
        if quiet {
            return Reporter::Silent;
        }
        let bar = ProgressBar::new(0);
        bar.set_style(ProgressStyle::with_template("{spinner} [{bar:30}] {pos}/{len} {msg}").expect("template").progress_chars("=> "));
        Reporter::Bar(bar)
    }

    /// `done` of `total`, working on `what`.
    pub fn set(&self, done: usize, total: usize, what: &str) {
        match self {
            Reporter::Silent => {}
            Reporter::Bar(b) => {
                if b.length() != Some(total as u64) {
                    b.set_length(total as u64);
                }
                b.set_position(done as u64);
                b.set_message(shorten(what, 60));
            }
            Reporter::Pipe(state) => {
                let mut s = state.lock().expect("pipe state");
                let now = Instant::now();
                let due = s.last.is_none_or(|l| now.duration_since(l) >= PIPE_THROTTLE) || done >= total || total != s.last_total;
                if due {
                    eprintln!("{}", pipe_line(done, total, what));
                    s.last = Some(now);
                    s.last_total = total;
                }
            }
        }
    }

    pub fn finish(&self) {
        match self {
            Reporter::Silent => {}
            Reporter::Bar(b) => b.finish_and_clear(),
            Reporter::Pipe(_) => eprintln!("@@pb"),
        }
    }
}

/// The pipe line for one update: `@@pb done/total message`.
pub fn pipe_line(done: usize, total: usize, what: &str) -> String {
    format!("@@pb {done}/{} {}", total.max(1), what.replace(['\r', '\n'], " "))
}

/// The tail of a long path, so a bar stays on one line.
pub fn shorten(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else {
        let tail: String = s.chars().skip(n - (max - 1)).collect();
        format!("…{tail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_lines_parse_the_way_agentc00pr_reads_them() {
        assert_eq!(pipe_line(3, 10, "SYSTEM"), "@@pb 3/10 SYSTEM");
        assert_eq!(pipe_line(0, 0, "x"), "@@pb 0/1 x");
        assert_eq!(pipe_line(1, 2, "two\nlines"), "@@pb 1/2 two lines");
        let line = pipe_line(7, 9, "sorting");
        let rest = line.strip_prefix("@@pb ").unwrap();
        let (pos, len) = rest.split_whitespace().next().unwrap().split_once('/').unwrap();
        assert_eq!((pos.parse::<u64>().unwrap(), len.parse::<u64>().unwrap()), (7, 9));
    }

    #[test]
    fn shortening_keeps_the_tail() {
        assert_eq!(shorten("abc", 10), "abc");
        assert_eq!(shorten("abcdefghijklmnop", 8), "…jklmnop");
    }

    #[test]
    fn reporters_do_not_panic() {
        Reporter::Silent.set(1, 2, "x");
        Reporter::Silent.finish();
        let p = Reporter::Pipe(Mutex::new(PipeState { last: None, last_total: 0 }));
        p.set(0, 3, "a");
        p.set(1, 3, "b");
        p.set(3, 3, "c");
        p.finish();
        let b = Reporter::Bar(ProgressBar::hidden());
        b.set(1, 5, "y");
        b.finish();
    }
}
