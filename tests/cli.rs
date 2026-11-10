//! The binary's command line over synthetic trees: exit codes, outputs, listings.

use std::path::{Path, PathBuf};
use std::process::Command;

fn exe() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_etcdump"))
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("etcdump_cli_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn put(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

fn tree(d: &Path) {
    put(d, "etc/hostname", "cli-host\n");
    put(d, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n");
    put(d, "etc/sudoers.d/x", "toor ALL=(ALL) NOPASSWD: ALL\n");
    put(d, "etc/crontab", "* * * * * root /tmp/.x\n");
}

#[test]
fn run_summary_and_exit_codes() {
    let d = scratch("run");
    tree(&d.join("ev"));
    let out = d.join("out");
    let r = Command::new(exe()).arg("-d").arg(d.join("ev")).arg("-o").arg(&out).arg("--summary").arg("-q").output().unwrap();
    assert_eq!(r.status.code(), Some(0));
    let s = String::from_utf8_lossy(&r.stdout);
    assert!(s.contains("computer cli-host"), "{s}");
    assert!(s.contains("first to read:"));
    let csv = std::fs::read_to_string(out.join("timeline.csv")).unwrap();
    assert!(csv.contains("\"significant\""));
    // --only-hunted keeps only the findings; a grep that matches nothing exits 1.
    let r = Command::new(exe()).arg("-d").arg(d.join("ev")).arg("-o").arg(d.join("o2")).arg("--grep").arg("zzzz").arg("-q").output().unwrap();
    assert_eq!(r.status.code(), Some(1));
    let r = Command::new(exe()).arg("-d").arg(d.join("ev")).arg("-o").arg(d.join("o3")).arg("--only-hunted").arg("--no-dumps").arg("-q").output().unwrap();
    assert_eq!(r.status.code(), Some(0));
    let hunted = std::fs::read_to_string(d.join("o3").join("timeline.csv")).unwrap();
    assert!(hunted.lines().skip(1).all(|l| l.contains("\"significant\"") || l.contains("\"candidate\"")));
    let dumps = std::fs::read_dir(d.join("o3")).unwrap().filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n.ends_with(".txt") && n != "files.txt" && n != "roots.txt").count();
    assert_eq!(dumps, 0, "--no-dumps");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn usage_errors() {
    let r = Command::new(exe()).arg("-o").arg("x").arg("-q").output().unwrap();
    assert_eq!(r.status.code(), Some(2), "no input");
    let r = Command::new(exe()).arg("-d").arg(".").arg("-q").output().unwrap();
    assert_eq!(r.status.code(), Some(2), "no output");
    let r = Command::new(exe()).arg("-d").arg(".").arg("-o").arg("x").arg("--since").arg("yesterday").arg("-q").output().unwrap();
    assert_eq!(r.status.code(), Some(2), "bad time");
    let r = Command::new(exe()).arg("-d").arg(".").arg("-o").arg("x").arg("--area").arg("bogus").arg("-q").output().unwrap();
    assert_eq!(r.status.code(), Some(2), "bad area");
    let r = Command::new(exe()).arg("--explain").arg("ED999").arg("-q").output().unwrap();
    assert_eq!(r.status.code(), Some(2));
}

#[test]
fn listings_codes_and_reference() {
    let r = Command::new(exe()).arg("--codes").output().unwrap();
    assert!(String::from_utf8_lossy(&r.stdout).contains("ED215_PARSE_SHADOW_HASH_WITHHELD"));
    let r = Command::new(exe()).arg("--explain").arg("215").output().unwrap();
    assert_eq!(r.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&r.stdout).contains("no hash is written"));
    let r = Command::new(exe()).arg("--list-areas").output().unwrap();
    let s = String::from_utf8_lossy(&r.stdout);
    assert!(s.contains("accounts") && s.contains("packages"));
    let r = Command::new(exe()).arg("--list-rules").output().unwrap();
    let s = String::from_utf8_lossy(&r.stdout);
    assert!(s.contains("- name: LNX-UID0-ACCOUNT") && s.contains("points ("));
    let r = Command::new(exe()).arg("--cli-reference").output().unwrap();
    assert!(String::from_utf8_lossy(&r.stdout).contains("## Exit codes"));
}

#[test]
fn nothing_to_read_exits_one_and_measure_writes_tables() {
    let d = scratch("nothing");
    put(&d.join("ev"), "readme.txt", "x");
    let r = Command::new(exe()).arg("-d").arg(d.join("ev")).arg("-o").arg(d.join("out")).arg("-q").output().unwrap();
    assert_eq!(r.status.code(), Some(1));
    assert!(d.join("out").join("timeline.csv").exists(), "the header-only timeline is still written");
    let r = Command::new(exe()).arg("-d").arg(d.join("ev")).arg("--measure").arg("-o").arg(d.join("m0")).arg("-q").output().unwrap();
    assert_eq!(r.status.code(), Some(1));
    tree(&d.join("clean"));
    let r = Command::new(exe()).arg("-d").arg(d.join("clean")).arg("--measure").arg("-o").arg(d.join("m")).arg("-q").output().unwrap();
    assert_eq!(r.status.code(), Some(0));
    let rarity = std::fs::read_to_string(d.join("m").join("rarity.tsv")).unwrap();
    assert!(rarity.contains("LNX-UID0-ACCOUNT\t1\t"));
    assert!(d.join("m").join("reference.tsv").exists());
    let _ = std::fs::remove_dir_all(&d);
}
