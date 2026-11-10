//! etcdump: the configuration of every Linux root, as text and as a timeline.
//!
//! The library behind the `etcdump` binary and behind agentc00pr's Linux configuration
//! panel. [`discover`] finds the Linux roots and their configuration files in any evidence
//! evidencefs opens; [`parse`] turns one file into items; [`rules`] judges each item and
//! fills the hunt tail; [`run::run`] does it all for a list of inputs; [`output`] writes the
//! folder; [`diag`] holds every code a message can carry.

#![forbid(unsafe_code)]

pub mod diag;
pub mod discover;
pub mod filter;
pub mod measure;
pub mod output;
pub mod parse;
pub mod progress;
pub mod rules;
pub mod run;
pub mod timeline;

#[cfg(test)]
mod tests_e2e;

/// The crate version, for the tool to print.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }

    /// docs/codes.md is the code table; ETCDUMP_WRITE_DOCS=1 rewrites it.
    #[test]
    fn codes_doc_is_current() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs").join("codes.md");
        let now = crate::diag::codes_markdown();
        if std::env::var_os("ETCDUMP_WRITE_DOCS").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &now).unwrap();
        }
        let on_disk = std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n");
        assert_eq!(on_disk.trim_end(), now.trim_end(), "docs/codes.md is stale: run `ETCDUMP_WRITE_DOCS=1 cargo test --release codes_doc`");
    }
}
