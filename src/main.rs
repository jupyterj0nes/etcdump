//! etcdump: the configuration of every Linux root, as text and as a timeline.

use std::path::PathBuf;

use clap::{CommandFactory, Parser};
use etcdump::run::{code, Options};

/// The exit codes, documented in `--help` and docs/CLI.md.
pub mod exit {
    /// Rows were written (or a listing, --codes, --explain, --measure succeeded).
    pub const OK: i32 = 0;
    /// Nothing to write: no Linux root, no configuration, or the filters excluded every row.
    pub const NO_ROWS: i32 = 1;
    /// The command line was wrong.
    pub const USAGE: i32 = 2;
    /// The output folder or the timeline could not be written.
    pub const OUTPUT: i32 = 3;
}

const LONG_ABOUT: &str = "\
etcdump finds every Linux root in the inputs (a folder that plays / because it holds \
etc/passwd or etc/hostname: a mounted or copied volume, a UAC, CyLR or KAPE-style triage \
package, a zip or tar archive, or a disk image E01/raw/VHD/VHDX/VMDK with ext4, XFS or LVM \
volumes inside) and reads the configuration an investigation looks at, area by area: \
accounts (passwd, group, the state of each shadow password and its scheme, never the hash), \
sudo, SSH (daemon and client configuration, authorized keys, known hosts of every user), \
network, mounts, cron and at, systemd units, drop-ins, timers and generators, init scripts \
and rc.local, system and per-user shell profiles, ld.so.preload, kernel modules, udev rules, \
PAM, APT/yum/dnf sources and APT hooks, XDG autostart, motd scripts, environment and \
/etc/default, firewall rules, logrotate scripts, web server sites and installed packages \
(dpkg, dated by their file lists). Deleted configuration files and previous versions the file \
system still describes (the ext4 journal) are read too, with state deleted. Every item is \
checked against persistence and hardening rules (built in, plus your YAML files with \
--rules); a hit fills the row's hunt columns: significant for a high rule, candidate for a \
medium or low one, habitual when a clean reference host holds the same item, and a score that \
is the rule's measured rarity.\n\n\
The output folder gets timeline.csv in the c00pr 19-column format (one row per item at its \
file's modification time, or the item's own time where it has one: a password's last change, \
a package's install), one text dump per root and area that any grep can read, files.txt (one \
line per configuration file) and roots.txt.\n\n\
Exit codes: 0 rows were written; 1 nothing to write (no Linux root, no configuration, or the \
filters excluded every row); 2 the command line was wrong; 3 the output folder or the timeline \
could not be written.\n\n\
Environment: ETCDUMP_PROGRESS_PIPE=1 makes the progress plain stderr lines \
`@@pb <done>/<total> <message>` for a program that runs etcdump as a child (agentc00pr).";

#[derive(Parser, Debug)]
#[command(name = "etcdump", version, about = "The configuration of every Linux root, as text and as a timeline.", long_about = LONG_ABOUT)]
pub struct Cli {
    /// Evidence to read, a folder: a mounted or copied volume, a triage package (UAC keeps the
    /// root under `[root]`, it is found by its etc/passwd), or any folder holding one or more
    /// Linux roots. Archives inside it are opened as mounts of their own, two levels deep.
    /// Repeat for several; each is read on its own thread and every row names its item first
    /// in source_file when more than one is given.
    #[arg(short = 'd', long = "dir", value_name = "FOLDER", help_heading = "Input")]
    pub dirs: Vec<PathBuf>,

    /// Evidence to read, a file: a disk image (E01 or its first segment, raw .dd/.raw/.img,
    /// split .001, VHD, VHDX, VMDK; every ext4, XFS and LVM volume inside is walked), a .zip
    /// (read in place) or a .tar/.tgz/.tar.gz (unpacked to a temporary folder). Repeat for
    /// several. A loose configuration file on its own holds no root and gives nothing: copy it
    /// under an etc/ folder and give that folder with -d.
    #[arg(short = 'f', long = "file", value_name = "FILE", help_heading = "Input")]
    pub files: Vec<PathBuf>,

    /// The computer name written in every row's `computer` column. Without it the name comes
    /// from the evidence (etc/hostname of the root, the triage package name), else from the
    /// input's file or folder name.
    #[arg(long, value_name = "NAME", help_heading = "Input")]
    pub hostname: Option<String>,

    /// Do not read deleted configuration files and previous versions. By default the deleted
    /// entries the file system still describes (the ext4 journal's copies of inodes and
    /// directory blocks, NTFS records) whose original path is a configuration file are read
    /// back and written with the `deleted` state and the `:deleted` artifact segment, so a
    /// sudoers line or a cron job removed after use is still seen.
    #[arg(long, help_heading = "Input")]
    pub no_deleted: bool,

    /// Do not read snapshot mounts (Volume Shadow Copies of an image, LVM snapshots). By
    /// default their configuration is read too, with the `vss` state.
    #[arg(long, help_heading = "Input")]
    pub no_vss: bool,

    /// Configuration files larger than this many bytes are listed as one file item and not
    /// parsed (a huge package database, a log someone named like a config). Default 32 MiB.
    #[arg(long, value_name = "BYTES", default_value_t = 32 << 20, help_heading = "Input")]
    pub max_file_bytes: u64,

    /// At most this many items are taken from one file; the rest of the file is not read and
    /// ED205 says so. 0 means no limit. Default 200000.
    #[arg(long, value_name = "N", default_value_t = 200_000, help_heading = "Input")]
    pub max_items: usize,

    /// More rules, as a YAML file or a folder of .yaml/.yml files, added to the built-in set
    /// (a rule with the name of a built-in one replaces it). Each rule names an area, a path
    /// glob, a key and a value wildcard, texts the value must or must not contain, a
    /// severity, a reason and a technique: `--list-rules` prints the built-in ones in that
    /// format. Repeat for several.
    #[arg(long, value_name = "PATH", help_heading = "Rules")]
    pub rules: Vec<PathBuf>,

    /// Do not run the built-in rules; only those of --rules. With neither, no row is judged.
    #[arg(long, help_heading = "Rules")]
    pub no_builtin_rules: bool,

    /// A reference list (the reference.tsv that --measure writes) of items a clean host of
    /// yours holds: rule hits on the very same items are habitual, not findings. Added to the
    /// built-in reference (stock RangeForge lab hosts). Repeat for several.
    #[arg(long, value_name = "FILE", help_heading = "Rules")]
    pub reference: Vec<PathBuf>,

    /// Do not run any rule: the hunt columns stay empty and the run is a little faster.
    #[arg(long, help_heading = "Rules")]
    pub no_hunt: bool,

    /// Print the rules that would run (built-in, plus --rules) as YAML, with their measured
    /// rarity, then exit.
    #[arg(long, help_heading = "Rules")]
    pub list_rules: bool,

    /// Measure the rules instead of writing a timeline: the inputs are taken as stock, clean
    /// hosts, every rule is run over every item, and rarity.tsv (per rule: hits, items,
    /// points) and reference.tsv (the items a rule fired on) are written into -o. Copy them
    /// into src/builtin/ to ship them, or give reference.tsv with --reference.
    #[arg(long, help_heading = "Rules")]
    pub measure: bool,

    /// The output folder, created if missing: timeline.csv (19 columns, UTF-8, RFC 4180,
    /// fixed-width UTC timestamps, sorted by time, duplicates collapsed), one
    /// `<mount>[_<root>]_<area>.txt` text dump per root and area (the item's name first when
    /// several inputs were given), files.txt (one line per configuration file: source, area,
    /// parser, state, size, modified, status, items, rows, rule hits), roots.txt, and with
    /// --json timeline.jsonl.
    #[arg(short = 'o', long = "output", value_name = "DIR", help_heading = "Output")]
    pub output: Option<PathBuf>,

    /// Also write timeline.jsonl: one JSON object per row with the same fields as the CSV and
    /// the hunt columns, for tools that prefer JSON lines.
    #[arg(long, help_heading = "Output")]
    pub json: bool,

    /// Do not write the text dumps; only timeline.csv, files.txt and roots.txt.
    #[arg(long, help_heading = "Output")]
    pub no_dumps: bool,

    /// Print a summary to standard output after the run: per input its computer and roots,
    /// per area the files, rows and rule hits, and the ten rows to read first.
    #[arg(long, help_heading = "Output")]
    pub summary: bool,

    /// Keep only the rows whose path, key or detail contains this text, ignoring case. Repeat
    /// for several texts: any of them matches. Applies to the timeline; the dumps keep every
    /// item so the context stays readable.
    #[arg(long, value_name = "TEXT", help_heading = "Filter")]
    pub grep: Vec<String>,

    /// Drop the rows whose path, key or detail contains this text, ignoring case. Repeat for
    /// several. Applied after --grep.
    #[arg(long = "grep-not", value_name = "TEXT", help_heading = "Filter")]
    pub grep_not: Vec<String>,

    /// Read only these areas, comma-separated or repeated: accounts, sudo, ssh, keys,
    /// network, mounts, cron, at, systemd, init, shell, preload, modules, udev, pam, sources,
    /// autostart, motd, environment, firewall, logrotate, web, packages (`--list-areas`
    /// explains each). Other files are not even read.
    #[arg(long, value_name = "AREA", help_heading = "Filter")]
    pub area: Vec<String>,

    /// Keep only rows at or after this UTC time: `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SS` or the
    /// full `YYYY-MM-DDTHH:MM:SS.ffffffZ`. Rows without a time are dropped when a bound is
    /// given.
    #[arg(long, value_name = "UTC", help_heading = "Filter")]
    pub since: Option<String>,

    /// Keep only rows before this UTC time (exclusive), same formats as --since.
    #[arg(long, value_name = "UTC", help_heading = "Filter")]
    pub until: Option<String>,

    /// Keep only the rows a rule made significant or candidate (not habitual, not unjudged):
    /// the findings alone.
    #[arg(long, help_heading = "Filter")]
    pub only_hunted: bool,

    /// Worker threads: inputs are opened in parallel up to this many, and files are parsed
    /// and judged on a pool of this size. 0 (the default) uses every core. The output is
    /// identical whatever the count.
    #[arg(long, value_name = "N", default_value_t = 0, help_heading = "Run")]
    pub threads: usize,

    /// More console detail: -v shows informational diagnostics (roots found, files, counts),
    /// -vv also every decision of etcdump and of evidencefs underneath. Errors and warnings
    /// always show.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, help_heading = "Run")]
    pub verbose: u8,

    /// Nothing on standard error: no progress bar, no diagnostics. The exit code still says
    /// how the run went and files.txt says what was read.
    #[arg(short = 'q', long, help_heading = "Run")]
    pub quiet: bool,

    /// List the configuration areas etcdump reads and what each holds, then exit.
    #[arg(long, help_heading = "Help")]
    pub list_areas: bool,

    /// List every diagnostic code etcdump can print (ED000 to ED699) with what it means and
    /// what to do about it, as a Markdown table, then exit. Codes starting with EF
    /// (evidencefs) are explained in that crate's docs/codes.md.
    #[arg(long, help_heading = "Help")]
    pub codes: bool,

    /// Explain one diagnostic code seen in a run, given as `ED210`, `ED210_NAME`, `210` or
    /// its bare name, then exit. Exit code 2 when the code does not exist.
    #[arg(long, value_name = "CODE", help_heading = "Help")]
    pub explain: Option<String>,

    /// Print the command-line reference (this help as Markdown, with the exit codes, the
    /// environment variables and examples), which is what docs/CLI.md holds, then exit.
    #[arg(long, help_heading = "Help")]
    pub cli_reference: bool,
}

/// docs/CLI.md: the help as Markdown.
pub fn cli_reference() -> String {
    let mut cmd = Cli::command();
    cmd.build();
    let help = cmd.render_long_help().to_string();
    let mut s = String::from("# Command line\n\nGenerated from `etcdump --help` by `ETCDUMP_WRITE_DOCS=1 cargo test --release --bin etcdump cli_reference`; a test fails when this file is stale.\n\n```text\n");
    s.push_str(help.trim_end());
    s.push_str("\n```\n\n## Exit codes\n\n| Code | Meaning |\n|-----:|---------|\n| 0 | Rows were written (or a listing, --codes, --explain or --measure succeeded) |\n| 1 | Nothing to write: no Linux root, no configuration, or the filters excluded every row |\n| 2 | The command line was wrong (no input, no output, a bad time or area, an unknown code to explain) |\n| 3 | The output folder or the timeline could not be written |\n\n## Environment\n\n| Variable | Effect |\n|----------|--------|\n| `ETCDUMP_PROGRESS_PIPE=1` | Progress as plain stderr lines `@@pb <done>/<total> <message>` (one per update, at most four a second, an empty `@@pb` at the end) for a parent program that draws the bar itself |\n\n## Examples\n\n```text\netcdump -d D:\\cases\\LNX01-triage -o D:\\cases\\LNX01-etc\netcdump -f uac-lnx01-linux-20261028.tar.gz -o out --summary\netcdump -f disk.E01 --hostname WEB01 --json -o out\netcdump -d triage --area sudo,ssh,keys,cron,systemd --only-hunted -o out\netcdump -d triage --rules D:\\rules\\linux --reference clean\\reference.tsv -o out\netcdump -d triage --grep /tmp/ --since 2026-11-01 -o out\netcdump -d clean-host-1 -d clean-host-2 --measure -o measured\netcdump --list-rules\netcdump --list-areas\netcdump --explain ED215\n```\n");
    s
}

fn main() {
    std::process::exit(real_main());
}

fn real_main() -> i32 {
    let cli = Cli::parse();
    etcdump::diag::set_quiet(cli.quiet);
    etcdump::diag::set_verbosity(cli.verbose);
    evidencefs::diag::set_quiet(true);
    if cli.cli_reference {
        print!("{}", cli_reference());
        return exit::OK;
    }
    if cli.codes {
        print!("{}", etcdump::diag::codes_markdown());
        return exit::OK;
    }
    if let Some(what) = &cli.explain {
        return match etcdump::diag::lookup(what) {
            Some(c) => {
                println!("{c}\n\n{}", c.help);
                exit::OK
            }
            None => {
                etcdump::diag::error(code::CLI_EXPLAIN_UNKNOWN, format!("'{what}' is not an etcdump code; see --codes"));
                exit::USAGE
            }
        };
    }
    if cli.list_areas {
        for (a, d) in etcdump::discover::AREAS {
            println!("{a:<12} {d}");
        }
        etcdump::diag::info(code::RUN_LIST_AREAS, "areas listed");
        return exit::OK;
    }
    if cli.list_rules {
        let set = etcdump::rules::RuleSet::load(!cli.no_builtin_rules, &cli.rules, &cli.reference);
        print!("{}", list_rules(&set));
        etcdump::diag::info(code::RUN_LIST_RULES, format!("{} rule(s)", set.rules.len()));
        return exit::OK;
    }
    let mut inputs = cli.dirs.clone();
    inputs.extend(cli.files.iter().cloned());
    if inputs.is_empty() {
        etcdump::diag::error(code::CLI_NO_INPUT, "give at least one -d FOLDER or -f FILE (--help explains them)");
        return exit::USAGE;
    }
    let Some(output) = cli.output.clone() else {
        etcdump::diag::error(code::CLI_NO_OUTPUT, "give the output folder with -o DIR");
        return exit::USAGE;
    };
    let filter = match etcdump::filter::Filter::new(&cli.grep, &cli.grep_not, &cli.area, cli.since.as_deref(), cli.until.as_deref(), cli.only_hunted) {
        Ok(f) => f,
        Err(_) => return exit::USAGE,
    };
    let opts = Options { inputs, hostname: cli.hostname.clone(), no_deleted: cli.no_deleted, no_vss: cli.no_vss, max_file_bytes: cli.max_file_bytes, max_items: cli.max_items, rules: cli.rules.clone(), no_builtin_rules: cli.no_builtin_rules, reference: cli.reference.clone(), no_hunt: cli.no_hunt, filter, threads: cli.threads };
    if cli.measure {
        etcdump::diag::info(code::RUN_MEASURE, output.display().to_string());
        return match etcdump::measure::measure(&opts).and_then(|t| etcdump::measure::write(&output, &t)) {
            Ok(()) => exit::OK,
            Err(e) if e.code == etcdump::measure::code::MEASURE_NO_ITEMS => exit::NO_ROWS,
            Err(_) => exit::OUTPUT,
        };
    }
    let reporter = etcdump::progress::Reporter::new(cli.quiet);
    let progress = |done: usize, total: usize, what: &str| reporter.set(done, total, what);
    let outcome = match etcdump::run::run(&opts, &progress) {
        Ok(o) => o,
        Err(_) => {
            reporter.finish();
            return exit::USAGE;
        }
    };
    reporter.finish();
    if let Err(e) = etcdump::output::write(&output, &outcome, cli.json, !cli.no_dumps) {
        let _ = e;
        return exit::OUTPUT;
    }
    if cli.summary {
        print!("{}", outcome.summary_text());
    }
    if outcome.rows.is_empty() {
        exit::NO_ROWS
    } else {
        exit::OK
    }
}

/// The rules as YAML with their rarity, for --list-rules.
fn list_rules(set: &etcdump::rules::RuleSet) -> String {
    let mut s = String::from("# etcdump rules (built-in and --rules); points = measured rarity on the clean reference\n");
    for r in &set.rules {
        let m = set.rarity.get(&r.name).map(|m| format!("{} points ({} of {} reference items)", m.points, m.hits, m.rows)).unwrap_or_else(|| "not measured".into());
        s.push_str(&format!("\n- name: {}\n  # {m}\n", r.name));
        let opt = |k: &str, v: &Option<String>, s: &mut String| {
            if let Some(v) = v {
                s.push_str(&format!("  {k}: {v:?}\n"));
            }
        };
        let list = |k: &str, v: &[String], s: &mut String| {
            if !v.is_empty() {
                s.push_str(&format!("  {k}: {v:?}\n"));
            }
        };
        opt("area", &r.area, &mut s);
        opt("path", &r.path, &mut s);
        list("not_path", &r.not_path, &mut s);
        opt("key", &r.key, &mut s);
        list("not_key", &r.not_key, &mut s);
        opt("value", &r.value, &mut s);
        list("data", &r.data, &mut s);
        list("and_data", &r.and_data, &mut s);
        list("not_data", &r.not_data, &mut s);
        s.push_str(&format!("  severity: {}\n  why: {:?}\n  technique: {}\n", r.level(), r.why, r.technique));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses() {
        Cli::command().debug_assert();
        let c = Cli::parse_from(["etcdump", "-d", "a", "-f", "b.tgz", "--hostname", "H", "-o", "out", "--json", "--summary", "--no-dumps", "--no-deleted", "--no-vss", "--max-file-bytes", "10", "--max-items", "5", "--rules", "r.yaml", "--no-builtin-rules", "--reference", "ref.tsv", "--no-hunt", "--grep", "x", "--grep-not", "y", "--area", "sudo,ssh", "--since", "2024-01-01", "--until", "2025-01-01", "--only-hunted", "--threads", "4", "-vv", "-q"]);
        assert_eq!(c.dirs, vec![PathBuf::from("a")]);
        assert_eq!(c.files, vec![PathBuf::from("b.tgz")]);
        assert_eq!(c.output, Some(PathBuf::from("out")));
        assert!(c.json && c.summary && c.no_dumps && c.no_deleted && c.no_vss && c.no_builtin_rules && c.no_hunt && c.only_hunted && c.quiet);
        assert_eq!((c.max_file_bytes, c.max_items, c.threads, c.verbose), (10, 5, 4, 2));
        assert_eq!(c.area, vec!["sudo,ssh"]);
        let d = Cli::parse_from(["etcdump", "--list-rules"]);
        assert!(d.list_rules && d.output.is_none());
        assert_eq!(d.max_file_bytes, 32 << 20);
        assert_eq!(d.max_items, 200_000);
    }

    #[test]
    fn list_rules_prints_every_rule() {
        etcdump::diag::set_quiet(true);
        let set = etcdump::rules::RuleSet::load(true, &[], &[]);
        let text = list_rules(&set);
        for r in &set.rules {
            assert!(text.contains(&format!("- name: {}", r.name)));
        }
        assert!(text.contains("points"));
    }

    /// docs/CLI.md is what --cli-reference prints; ETCDUMP_WRITE_DOCS=1 rewrites it.
    #[test]
    fn cli_reference_is_current() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs").join("CLI.md");
        let now = cli_reference().replace("\r\n", "\n");
        if std::env::var_os("ETCDUMP_WRITE_DOCS").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &now).unwrap();
        }
        let on_disk = std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n");
        assert_eq!(on_disk.trim_end(), now.trim_end(), "docs/CLI.md is not what --cli-reference prints: run `ETCDUMP_WRITE_DOCS=1 cargo test --release --bin etcdump cli_reference`");
    }

    /// Every visible option says what it does, what it takes and what it needs.
    #[test]
    fn every_option_is_explained() {
        for a in Cli::command().get_arguments().filter(|a| !a.is_hide_set() && !matches!(a.get_id().as_str(), "help" | "version")) {
            let help = a.get_long_help().or(a.get_help()).map(|s| s.to_string()).unwrap_or_default();
            assert!(help.len() >= 60, "--{}: help of {} chars is too short", a.get_long().unwrap_or(""), help.len());
            if a.get_action().takes_values() {
                assert!(a.get_value_names().is_some_and(|v| !v.is_empty()), "--{} takes a value but names none", a.get_long().unwrap_or(""));
            }
            assert!(a.get_help_heading().is_some(), "--{} is under no heading", a.get_long().unwrap_or(""));
        }
        let about = Cli::command().get_long_about().map(|s| s.to_string()).unwrap_or_default();
        assert!(about.contains("Exit codes"));
        assert!(about.contains("ETCDUMP_PROGRESS_PIPE"));
    }

    #[test]
    fn reference_mentions_every_option_and_the_codes() {
        let r = cli_reference();
        for a in Cli::command().get_arguments() {
            if let Some(l) = a.get_long() {
                assert!(r.contains(&format!("--{l}")), "--{l} missing from the reference");
            }
        }
        assert!(r.contains("## Exit codes") && r.contains("## Environment") && r.contains("## Examples"));
    }
}
