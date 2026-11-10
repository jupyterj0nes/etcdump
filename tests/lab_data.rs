//! Runs over the RangeForge lab evidence on the author's machine; each test is skipped
//! (passes with a note) when its evidence is not there.

use std::path::{Path, PathBuf};

use etcdump::run::{self, Options};

fn lab(p: &str) -> Option<PathBuf> {
    let path = PathBuf::from(p);
    if path.exists() {
        Some(path)
    } else {
        eprintln!("skipped: {p} not on this machine");
        None
    }
}

fn opts(inputs: Vec<PathBuf>, threads: usize) -> Options {
    Options { inputs, max_file_bytes: 32 << 20, max_items: 200_000, threads, ..Default::default() }
}

fn csv(o: &Options) -> (String, run::Outcome) {
    let out = run::run(o, &|_, _, _| {}).unwrap();
    let mut buf = Vec::new();
    etcdump::timeline::write_csv(&mut buf, &out.rows).unwrap();
    (String::from_utf8(buf).unwrap(), out)
}

const UAC: &str = "D:/evidence/mixed-intake/uac-leo-lnx01-linux-20261028203103.tar.gz";
const TRIAGE: &str = "D:/evidence/rangeforge-20261103/leo-lnx01-triage";
const TGZ: &str = "D:/evidence/mixed-intake/lnx01.tgz";
const EXT4: &str = "D:/evidence/mixed-intake/real_ext4.img";

#[test]
fn uac_collection_of_the_clean_host() {
    etcdump::diag::set_quiet(true);
    let Some(p) = lab(UAC) else { return };
    let (one, out) = csv(&opts(vec![p.clone()], 1));
    assert_eq!(out.items_read[0].1, "leo-lnx01");
    assert!(out.items_read[0].2[0].ends_with("[root]"), "{:?}", out.items_read);
    assert!(out.files.len() > 500, "{}", out.files.len());
    assert!(out.rows.len() > 5000, "{}", out.rows.len());
    for area in ["accounts", "sudo", "ssh", "cron", "systemd", "init", "shell", "pam", "sources", "udev", "modules"] {
        assert!(out.rows.iter().any(|r| r.area == area), "{area}");
    }
    // A clean host: nothing significant, the stock sudo rules and APT hooks are habitual.
    assert!(!out.rows.iter().any(|r| r.tail.hunt == "significant"), "{:?}", out.rows.iter().filter(|r| r.tail.hunt == "significant").map(|r| (&r.path, &r.key)).collect::<Vec<_>>());
    let cloud = out.rows.iter().find(|r| r.path == "etc/sudoers.d/90-cloud-init-users" && r.key == "ubuntu").unwrap();
    assert_eq!(cloud.tail.hunt, "habitual");
    assert!(out.rows.iter().any(|r| r.path.starts_with("etc/apt/apt.conf.d/") && r.tail.hunt == "habitual"));
    // The lab's deliberate weakness stays a finding: it is not in the shipped reference.
    let lead = out.rows.iter().find(|r| r.key == "%Leadership").unwrap();
    assert_eq!(lead.tail.hunt, "candidate");
    // shadow is not collected by UAC here; passwd is, and no hash leaks anyway.
    assert!(!out.rows.iter().any(|r| r.detail.contains("$6$") || r.detail.contains("$y$")));
    let (four, _) = csv(&opts(vec![p], 4));
    assert_eq!(one, four, "byte-identical across thread counts");
}

#[test]
fn triage_folder_of_the_same_host() {
    etcdump::diag::set_quiet(true);
    let Some(p) = lab(TRIAGE) else { return };
    let (a, out) = csv(&opts(vec![p.clone()], 2));
    assert_eq!(out.items_read[0].1, "leo-lnx01");
    assert!(out.rows.iter().any(|r| r.path == "etc/passwd"));
    assert!(out.rows.iter().any(|r| r.area == "cron"));
    assert!(!out.rows.iter().any(|r| r.detail.contains("accessed")));
    let (b, _) = csv(&opts(vec![p], 0));
    assert_eq!(a, b);
}

#[test]
fn raw_tarball_and_ext4_image() {
    etcdump::diag::set_quiet(true);
    if let Some(p) = lab(TGZ) {
        let (_, out) = csv(&opts(vec![p], 2));
        assert_eq!(out.items_read[0].1, "LEO-LNX01.leoncorp.test");
        assert!(out.rows.iter().any(|r| r.path == "etc/passwd" && r.key == "root"));
    }
    if let Some(p) = lab(EXT4) {
        let (a, out) = csv(&opts(vec![p.clone()], 2));
        assert!(!out.items_read.is_empty());
        assert!(out.items_read[0].2.iter().any(|r| r.starts_with("partition") || r.starts_with("whole")) || out.items_read[0].2.is_empty(), "{:?}", out.items_read);
        let (b, _) = csv(&opts(vec![p], 1));
        assert_eq!(a, b);
    }
}

#[test]
fn binary_end_to_end_with_pipe_progress() {
    let Some(p) = lab(UAC) else { return };
    let exe = Path::new(env!("CARGO_BIN_EXE_etcdump"));
    let out = std::env::temp_dir().join(format!("etcdump_lab_bin_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let r = std::process::Command::new(exe).arg("-f").arg(&p).arg("-o").arg(&out).arg("--summary").arg("--json").env("ETCDUMP_PROGRESS_PIPE", "1").output().unwrap();
    assert_eq!(r.status.code(), Some(0), "{}", String::from_utf8_lossy(&r.stderr));
    let err = String::from_utf8_lossy(&r.stderr);
    assert!(err.lines().any(|l| l.starts_with("@@pb ")), "{err}");
    let summary = String::from_utf8_lossy(&r.stdout);
    assert!(summary.contains("computer leo-lnx01"));
    assert!(out.join("timeline.csv").exists() && out.join("timeline.jsonl").exists() && out.join("files.txt").exists() && out.join("roots.txt").exists());
    let dumps: Vec<_> = std::fs::read_dir(&out).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().ends_with("_sudo.txt")).collect();
    assert_eq!(dumps.len(), 1);
    let _ = std::fs::remove_dir_all(&out);
}
