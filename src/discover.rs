//! Finding Linux roots and their configuration files inside the evidence.
//!
//! The evidence is opened with evidencefs (folders, triage packages, zips, tars, raw/E01/
//! VHD/VMDK images with ext4, XFS and LVM, shadow copies when there are any). Every folder
//! that plays `/` (it holds `etc/passwd` or `etc/hostname`) is a root; under each root
//! only the folders configuration lives in are walked, never the whole volume, and each
//! file is given its area and parser by [`classify`]. Deleted files and previous versions
//! that the file system still describes (`/$DELETED`, the ext4 journal) are classified the
//! same way by their original path.

use std::collections::BTreeMap;
use std::path::Path;

use evidencefs::fs::{Entry, EntryKind, WalkOptions, WalkStep};
use evidencefs::time::Timestamp;
use evidencefs::{Evidence, OpenOptions};

use crate::parse::Parser;

pub mod code {
    crate::codes! {
        DISC_OPENED = 100, "an evidence item was opened; the message gives its kind and mounts (shown with -v)";
        DISC_OPEN_FAILED = 101, "an evidence item could not be opened (not an image, archive or folder evidencefs reads; damaged; missing); it is skipped and the run goes on with the others";
        DISC_NO_ROOT = 102, "no Linux root (a folder holding etc/passwd or etc/hostname) was found in an item; it gives no configuration";
        DISC_ROOT = 103, "a Linux root was found; the message gives the mount and the folder that plays / (shown with -v)";
        DISC_FILE = 104, "a configuration file was found and given its area and parser (shown with -vv)";
        DISC_WALK_LIMIT = 105, "a walk under a root stopped at its limit (entries or depth); some configuration may be missing; the message names the folder";
        DISC_READ_FAILED = 106, "a configuration file could not be read from the evidence (damaged extents, a decompression error); it is listed in the inventory as unreadable";
        DISC_TOO_LARGE = 107, "a configuration file is larger than --max-file-bytes; it is listed as one file item and not parsed";
        DISC_DELETED_SCAN = 108, "the deleted entries of a mount were listed (ext4 journal, NTFS $MFT); the message gives how many fall under a root's configuration folders";
        DISC_DELETED_UNREADABLE = 109, "a deleted configuration file is described by the metadata but its content cannot be read back; it is listed with no items";
        DISC_DELETED_SKIPPED = 110, "--no-deleted: the deleted entries and previous versions of the mounts were not looked at";
        DISC_SNAPSHOT = 111, "a mount is a snapshot (a Volume Shadow Copy, an LVM snapshot); its rows carry state vss";
        DISC_DPKG_LISTS = 112, "the file lists under var/lib/dpkg/info were read for their times (one per installed package) to date the package rows";
        DISC_HOSTNAME = 113, "the computer name was taken from the evidence (etc/hostname, the triage package name) (shown with -v)";
        DISC_HOSTNAME_FROM_NAME = 114, "the computer name was taken from the item's file or folder name: no --hostname and nothing in the evidence names the host";
        DISC_WINDOWS_ONLY = 115, "an item holds a Windows root and no Linux one: etcdump reads Linux configuration (hivedump reads Windows hives)";
        DISC_LINK = 116, "a configuration file is a symbolic link; it is listed with its target and not followed (shown with -vv)";
        DISC_USER_HOME = 117, "a home folder was found under a root (home/<user>, root); its dotfiles, SSH files and autostart entries are read (shown with -vv)";
        DISC_UNKNOWN_FILE = 118, "a file under a configuration folder has no area etcdump knows (a backup, an editor swap file); it is skipped (shown with -vv)";
        DISC_SKIPPED_BACKUP = 119, "a backup or editor copy (passwd-, shadow-, *.bak, *.dpkg-old, *~, .swp) was read as its own file: backups keep the state before the last change";
        DISC_ITEM_THREAD_FAILED = 120, "the worker reading one evidence item stopped unexpectedly; that item gives nothing and the others go on";
        DISC_NESTED = 121, "an archive inside the item was opened as a mount of its own (shown with -v)";
        DISC_ARCHIVE_TIMES = 122, "a tar was unpacked to a temporary folder to be read: its files keep the modification time the archive stores, their creation, change and access times (the moment of unpacking) are left out so two runs give the same rows";
        DISC_FOLDER_ATIME = 123, "the access times of a host folder are left out: reading the files changes them, they are the collector's or this run's, not the suspect's (shown with -vv)";
    }
}

/// The areas, in the order the dumps and the summary list them.
pub const AREAS: &[(&str, &str)] = &[
    ("accounts", "passwd, group, shadow (state only), gshadow, login.defs"),
    ("sudo", "sudoers and sudoers.d"),
    ("ssh", "sshd_config, ssh_config and their .d folders, per-user ssh config"),
    ("keys", "authorized_keys and known_hosts of every user"),
    ("network", "hosts, resolv.conf, nsswitch.conf, hostname, interfaces, netplan, NetworkManager, hosts.allow/deny"),
    ("mounts", "fstab, crypttab, exports"),
    ("cron", "crontab, cron.d, cron.hourly/daily/weekly/monthly, anacrontab, user crontabs"),
    ("at", "at job spool"),
    ("systemd", "system and user units, drop-ins, timers, generators"),
    ("init", "init.d, rc.local, rc?.d links, inittab, upstart"),
    ("shell", "system and per-user shell profiles and rc files"),
    ("preload", "ld.so.preload, ld.so.conf and ld.so.conf.d"),
    ("modules", "modules, modules-load.d, modprobe.d"),
    ("udev", "udev rules under etc"),
    ("pam", "pam.d and security/pam_env.conf"),
    ("sources", "APT sources and apt.conf.d hooks, yum and dnf repositories"),
    ("autostart", "XDG autostart entries, system and per user"),
    ("motd", "motd, update-motd.d, issue"),
    ("environment", "environment, /etc/default, os-release, sysctl"),
    ("firewall", "iptables, nftables, ufw and firewalld saved rules"),
    ("logrotate", "logrotate.conf and logrotate.d"),
    ("web", "Apache and nginx site configuration"),
    ("packages", "dpkg status (with install times) and RPM databases"),
];

/// Is this a known area name?
pub fn is_area(name: &str) -> bool {
    AREAS.iter().any(|(a, _)| a.eq_ignore_ascii_case(name))
}

fn glob(p: &str, t: &str) -> bool {
    evidencefs::fs::glob_match(p, t)
}

/// The area and parser of a root-relative path (`etc/passwd`, `home/bob/.ssh/authorized_keys`),
/// or `None` when the file is not configuration etcdump reads.
pub fn classify(rel: &str) -> Option<(&'static str, Parser)> {
    let rel = rel.trim_start_matches('/');
    let name = rel.rsplit('/').next().unwrap_or(rel);
    // Backups keep the state before a change: read them like the file they copy.
    let base = name.trim_end_matches('-').trim_end_matches('~');
    let base = base.strip_suffix(".bak").or_else(|| base.strip_suffix(".dpkg-old")).or_else(|| base.strip_suffix(".dpkg-dist")).or_else(|| base.strip_suffix(".orig")).unwrap_or(base);
    if name.ends_with(".swp") || name.ends_with(".swx") {
        return None;
    }
    let dir = rel.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    let alt = if dir.is_empty() { base.to_string() } else { format!("{dir}/{base}") };
    let r = alt.as_str();
    let user_home = r.starts_with("home/") || r.starts_with("root/");
    let in_home = |suffix: &str| (glob(&format!("home/*/{suffix}"), r)) || glob(&format!("root/{suffix}"), r);
    let table: &[(&str, &str, Parser)] = &[
        ("etc/passwd", "accounts", Parser::Passwd),
        ("etc/group", "accounts", Parser::Group),
        ("etc/shadow", "accounts", Parser::Shadow),
        ("etc/gshadow", "accounts", Parser::Gshadow),
        ("etc/login.defs", "accounts", Parser::KvSpace),
        ("etc/sudoers", "sudo", Parser::Sudoers),
        ("etc/sudoers.d/*", "sudo", Parser::Sudoers),
        ("etc/ssh/sshd_config", "ssh", Parser::SshConfig),
        ("etc/ssh/sshd_config.d/*", "ssh", Parser::SshConfig),
        ("etc/ssh/ssh_config", "ssh", Parser::SshConfig),
        ("etc/ssh/ssh_config.d/*", "ssh", Parser::SshConfig),
        ("etc/ssh/authorized_keys/*", "keys", Parser::AuthorizedKeys),
        ("etc/ssh/ssh_known_hosts", "keys", Parser::KnownHosts),
        ("etc/hosts", "network", Parser::Hosts),
        ("etc/hosts.allow", "network", Parser::Lines),
        ("etc/hosts.deny", "network", Parser::Lines),
        ("etc/resolv.conf", "network", Parser::KvSpace),
        ("etc/nsswitch.conf", "network", Parser::KvColon),
        ("etc/hostname", "network", Parser::Lines),
        ("etc/network/interfaces", "network", Parser::Lines),
        ("etc/network/interfaces.d/*", "network", Parser::Lines),
        ("etc/netplan/*", "network", Parser::Lines),
        ("etc/NetworkManager/system-connections/*", "network", Parser::Ini),
        ("etc/sysconfig/network-scripts/ifcfg-*", "network", Parser::KvEq),
        ("etc/wpa_supplicant/*.conf", "network", Parser::Lines),
        ("etc/fstab", "mounts", Parser::Fstab),
        ("etc/crypttab", "mounts", Parser::Crypttab),
        ("etc/exports", "mounts", Parser::Exports),
        ("etc/crontab", "cron", Parser::CronSystem),
        ("etc/anacrontab", "cron", Parser::Lines),
        ("etc/cron.d/*", "cron", Parser::CronSystem),
        ("etc/cron.hourly/*", "cron", Parser::Script),
        ("etc/cron.daily/*", "cron", Parser::Script),
        ("etc/cron.weekly/*", "cron", Parser::Script),
        ("etc/cron.monthly/*", "cron", Parser::Script),
        ("etc/cron.allow", "cron", Parser::Lines),
        ("etc/cron.deny", "cron", Parser::Lines),
        ("var/spool/cron/crontabs/*", "cron", Parser::CronUser),
        ("var/spool/cron/tabs/*", "cron", Parser::CronUser),
        ("var/spool/cron/atjobs/*", "at", Parser::AtJob),
        ("var/spool/at/*", "at", Parser::AtJob),
        ("etc/at.allow", "at", Parser::Lines),
        ("etc/at.deny", "at", Parser::Lines),
        ("etc/systemd/system-generators/*", "systemd", Parser::FileOnly),
        ("usr/lib/systemd/system-generators/*", "systemd", Parser::FileOnly),
        ("lib/systemd/system-generators/*", "systemd", Parser::FileOnly),
        ("etc/systemd/*.conf", "systemd", Parser::Ini),
        ("etc/rc.local", "init", Parser::Script),
        ("etc/rc.d/rc.local", "init", Parser::Script),
        ("etc/init.d/*", "init", Parser::Script),
        ("etc/rc.d/init.d/*", "init", Parser::Script),
        ("etc/rc?.d/*", "init", Parser::Script),
        ("etc/rc.d/rc?.d/*", "init", Parser::Script),
        ("etc/inittab", "init", Parser::Lines),
        ("etc/init/*.conf", "init", Parser::Script),
        ("etc/profile", "shell", Parser::Script),
        ("etc/profile.d/*", "shell", Parser::Script),
        ("etc/bash.bashrc", "shell", Parser::Script),
        ("etc/bashrc", "shell", Parser::Script),
        ("etc/bash.bash_logout", "shell", Parser::Script),
        ("etc/zshrc", "shell", Parser::Script),
        ("etc/zsh/*", "shell", Parser::Script),
        ("etc/zprofile", "shell", Parser::Script),
        ("etc/csh.cshrc", "shell", Parser::Script),
        ("etc/csh.login", "shell", Parser::Script),
        ("etc/fish/config.fish", "shell", Parser::Script),
        ("etc/ld.so.preload", "preload", Parser::Lines),
        ("etc/ld.so.conf", "preload", Parser::Lines),
        ("etc/ld.so.conf.d/*", "preload", Parser::Lines),
        ("etc/modules", "modules", Parser::Lines),
        ("etc/modules-load.d/*", "modules", Parser::Lines),
        ("etc/modprobe.d/*", "modules", Parser::Lines),
        ("etc/udev/rules.d/*", "udev", Parser::Lines),
        ("etc/pam.d/*", "pam", Parser::Pam),
        ("etc/pam.conf", "pam", Parser::Pam),
        ("etc/security/pam_env.conf", "pam", Parser::Lines),
        ("etc/apt/sources.list", "sources", Parser::AptSources),
        ("etc/apt/sources.list.d/*.list", "sources", Parser::AptSources),
        ("etc/apt/sources.list.d/*.sources", "sources", Parser::AptDeb822),
        ("etc/apt/apt.conf", "sources", Parser::AptConf),
        ("etc/apt/apt.conf.d/*", "sources", Parser::AptConf),
        ("etc/yum.repos.d/*", "sources", Parser::Ini),
        ("etc/yum.conf", "sources", Parser::Ini),
        ("etc/dnf/dnf.conf", "sources", Parser::Ini),
        ("etc/zypp/repos.d/*", "sources", Parser::Ini),
        ("etc/xdg/autostart/*", "autostart", Parser::Ini),
        ("etc/motd", "motd", Parser::Lines),
        ("etc/update-motd.d/*", "motd", Parser::Script),
        ("etc/issue", "motd", Parser::Lines),
        ("etc/issue.net", "motd", Parser::Lines),
        ("etc/environment", "environment", Parser::KvEq),
        ("etc/default/*", "environment", Parser::KvEq),
        ("etc/os-release", "environment", Parser::KvEq),
        ("usr/lib/os-release", "environment", Parser::KvEq),
        ("etc/sysctl.conf", "environment", Parser::KvEq),
        ("etc/sysctl.d/*", "environment", Parser::KvEq),
        ("etc/iptables/*", "firewall", Parser::Lines),
        ("etc/sysconfig/iptables", "firewall", Parser::Lines),
        ("etc/sysconfig/ip6tables", "firewall", Parser::Lines),
        ("etc/nftables.conf", "firewall", Parser::Lines),
        ("etc/ufw/*.rules", "firewall", Parser::Lines),
        ("etc/ufw/ufw.conf", "firewall", Parser::KvEq),
        ("etc/firewalld/zones/*", "firewall", Parser::Lines),
        ("etc/logrotate.conf", "logrotate", Parser::Logrotate),
        ("etc/logrotate.d/*", "logrotate", Parser::Logrotate),
        ("etc/apache2/sites-enabled/*", "web", Parser::Lines),
        ("etc/apache2/apache2.conf", "web", Parser::Lines),
        ("etc/httpd/conf/httpd.conf", "web", Parser::Lines),
        ("etc/httpd/conf.d/*", "web", Parser::Lines),
        ("etc/nginx/nginx.conf", "web", Parser::Lines),
        ("etc/nginx/sites-enabled/*", "web", Parser::Lines),
        ("etc/nginx/conf.d/*", "web", Parser::Lines),
        ("var/lib/dpkg/status", "packages", Parser::DpkgStatus),
        ("var/lib/rpm/rpmdb.sqlite", "packages", Parser::RpmDb),
        ("var/lib/rpm/Packages", "packages", Parser::RpmDb),
        ("usr/lib/sysimage/rpm/rpmdb.sqlite", "packages", Parser::RpmDb),
    ];
    for (pat, area, parser) in table {
        if glob(pat, r) {
            return Some((area, *parser));
        }
    }
    // systemd units and drop-ins anywhere under the unit folders.
    for base in ["etc/systemd/system/", "etc/systemd/user/", "lib/systemd/system/", "usr/lib/systemd/system/", "run/systemd/system/"] {
        if let Some(rest) = r.strip_prefix(base) {
            return unit_file(rest);
        }
    }
    if user_home {
        if let Some(rest) = r.split_once("/.config/systemd/user/").map(|(_, b)| b) {
            return unit_file(rest);
        }
        let shell_files = [".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".cshrc", ".tcshrc", ".config/fish/config.fish", ".xinitrc", ".xprofile", ".xsession"];
        for f in shell_files {
            if in_home(f) {
                return Some(("shell", Parser::Script));
            }
        }
        if in_home(".ssh/authorized_keys") || in_home(".ssh/authorized_keys2") {
            return Some(("keys", Parser::AuthorizedKeys));
        }
        if in_home(".ssh/known_hosts") {
            return Some(("keys", Parser::KnownHosts));
        }
        if in_home(".ssh/config") {
            return Some(("ssh", Parser::SshConfig));
        }
        if in_home(".config/autostart/*") {
            return Some(("autostart", Parser::Ini));
        }
        if in_home(".pam_environment") {
            return Some(("pam", Parser::Lines));
        }
    }
    // Authorized keys of service accounts whose home is elsewhere (var/www, opt/app).
    if r.ends_with("/.ssh/authorized_keys") || r.ends_with("/.ssh/authorized_keys2") {
        return Some(("keys", Parser::AuthorizedKeys));
    }
    None
}

fn unit_file(rest: &str) -> Option<(&'static str, Parser)> {
    let name = rest.rsplit('/').next().unwrap_or(rest);
    if rest.contains(".d/") && name.ends_with(".conf") {
        return Some(("systemd", Parser::Unit));
    }
    let units = [".service", ".timer", ".socket", ".path", ".mount", ".automount", ".target", ".slice", ".scope", ".swap", ".device"];
    if units.iter().any(|u| name.ends_with(u)) {
        return Some(("systemd", Parser::Unit));
    }
    None
}

/// The folders walked under each root, with their depth.
pub const WALK_DIRS: &[(&str, usize)] = &[("etc", 6), ("var/spool/cron", 3), ("var/spool/at", 2), ("lib/systemd/system", 3), ("usr/lib/systemd/system", 3), ("lib/systemd/system-generators", 1), ("usr/lib/systemd/system-generators", 1), ("run/systemd/system", 3), ("var/lib/dpkg", 1), ("var/lib/rpm", 1), ("usr/lib/sysimage/rpm", 1), ("root", 4), ("var/www", 3)];

/// One configuration file found in the evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigFile {
    /// The evidence item's label (its file or folder name).
    pub item: String,
    /// The mount index in the item's evidence.
    pub mount: usize,
    /// The mount label (`folder`, `partition_0`, `zip`...).
    pub mount_label: String,
    /// The folder that plays `/` on that mount (`/` for an image, `/[root]` in UAC).
    pub root: String,
    /// The path from the root: `etc/passwd`.
    pub rel: String,
    /// The path on the mount (for a deleted file: its `/$DELETED/...` path).
    pub path: String,
    pub area: &'static str,
    pub parser: Parser,
    pub entry: Entry,
    /// The id of the deleted entry or previous version (`1234`, `1234.v2`), when deleted.
    pub deleted: Option<String>,
    /// The mount is a snapshot.
    pub snapshot: bool,
}

impl ConfigFile {
    /// `mount.source_path(path)`: `folder/etc/passwd`, `partition_0/$DELETED/12/etc/shadow`.
    pub fn source(&self) -> String {
        format!("{}{}", self.mount_label, if self.path.starts_with('/') { self.path.clone() } else { format!("/{}", self.path) })
    }

    /// The account a file belongs to by its place: `home/<user>/...`, `root/...`, a user
    /// crontab's name.
    pub fn owner(&self) -> String {
        let r = self.rel.as_str();
        if let Some(rest) = r.strip_prefix("home/") {
            return rest.split('/').next().unwrap_or("").to_string();
        }
        if r.starts_with("root/") {
            return "root".into();
        }
        if self.parser == crate::parse::Parser::CronUser {
            return self.entry.name.clone();
        }
        String::new()
    }
}

/// What to look at.
#[derive(Clone, Debug)]
pub struct FindOptions {
    pub deleted: bool,
    pub snapshots: bool,
    /// Only these areas (empty: all).
    pub areas: Vec<String>,
    /// Entries a walk visits before it stops.
    pub max_entries: usize,
}

impl Default for FindOptions {
    fn default() -> Self {
        FindOptions { deleted: true, snapshots: true, areas: Vec::new(), max_entries: 200_000 }
    }
}

/// Opens an evidence item the way etcdump reads it.
pub fn open(path: &Path, snapshots: bool) -> crate::diag::Result<Evidence> {
    let opts = OpenOptions { snapshots, ..OpenOptions::default() };
    let r = Evidence::open(path, &opts);
    crate::diag::surface_crates();
    match r {
        Ok(ev) => {
            crate::diag::info(code::DISC_OPENED, ev.describe());
            for m in &ev.mounts {
                if matches!(m.source, evidencefs::MountSource::Nested { .. }) {
                    crate::diag::info(code::DISC_NESTED, m.label.clone());
                }
            }
            Ok(ev)
        }
        Err(e) => Err(crate::diag::fail(code::DISC_OPEN_FAILED, format!("{}: {e}", path.display()))),
    }
}

/// The computer name of an item.
pub fn computer(ev: &Evidence, given: Option<&str>, item: &str) -> String {
    if let Some(h) = given {
        return h.to_string();
    }
    let h = ev.hostname();
    crate::diag::surface_crates();
    match h {
        Some(h) => {
            crate::diag::info(code::DISC_HOSTNAME, h.clone());
            h
        }
        None => {
            crate::diag::warn(code::DISC_HOSTNAME_FROM_NAME, item.to_string());
            item.to_string()
        }
    }
}

/// The Linux roots of every mount: `(mount index, root folder)`.
pub fn roots(ev: &Evidence) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, m) in ev.mounts.iter().enumerate() {
        for r in &m.roots.linux {
            crate::diag::info(code::DISC_ROOT, format!("{}: {r}", m.label));
            out.push((i, evidencefs::fs::normalize(r)));
        }
    }
    if out.is_empty() {
        if ev.mounts.iter().any(|m| !m.roots.windows.is_empty()) {
            crate::diag::warn(code::DISC_WINDOWS_ONLY, ev.path.display().to_string());
        } else {
            crate::diag::warn(code::DISC_NO_ROOT, ev.path.display().to_string());
        }
    }
    out
}

fn rel_of(root: &str, path: &str) -> Option<String> {
    let root = root.trim_end_matches('/');
    let rest = if root.is_empty() { Some(path) } else { path.strip_prefix(root) }?;
    if !rest.is_empty() && !rest.starts_with('/') {
        return None;
    }
    Some(rest.trim_start_matches('/').to_string())
}

fn wanted(area: &str, opts: &FindOptions) -> bool {
    opts.areas.is_empty() || opts.areas.iter().any(|a| a.eq_ignore_ascii_case(area))
}

/// Every configuration file under every root of the evidence, sorted by mount, root and
/// path, deleted entries after the live ones.
pub fn find(ev: &Evidence, item: &str, opts: &FindOptions) -> Vec<ConfigFile> {
    find_in(ev, item, &roots(ev), opts)
}

/// [`find`] over roots already located.
pub fn find_in(ev: &Evidence, item: &str, roots: &[(usize, String)], opts: &FindOptions) -> Vec<ConfigFile> {
    let mut out = Vec::new();
    for (mi, root) in roots {
        let m = &ev.mounts[*mi];
        let snapshot = m.is_snapshot();
        if snapshot {
            if !opts.snapshots {
                continue;
            }
            crate::diag::info(code::DISC_SNAPSHOT, m.label.clone());
        }
        // A tar unpacked to a temporary folder: only the modification time comes from the
        // archive; a host folder: its access times move as it is read.
        let unpacked = m.fs.kind() == evidencefs::FsKind::Folder && !matches!(m.source, evidencefs::MountSource::Folder(_));
        if unpacked {
            crate::diag::info(code::DISC_ARCHIVE_TIMES, m.label.clone());
        } else if m.fs.kind() == evidencefs::FsKind::Folder {
            crate::diag::record(code::DISC_FOLDER_ATIME, crate::diag::Severity::Info, m.label.clone());
        }
        let fix_times = |e: &Entry| -> Entry {
            let mut e = e.clone();
            if m.fs.kind() == evidencefs::FsKind::Folder {
                e.times.accessed = None;
            }
            if unpacked {
                e.times.created = None;
                e.times.changed = None;
            }
            e
        };
        let mut dirs: Vec<(String, usize)> = WALK_DIRS.iter().map(|(d, depth)| (evidencefs::fs::join(root, d), *depth)).collect();
        if let Ok(homes) = m.fs.read_dir(&evidencefs::fs::join(root, "home")) {
            for h in homes.into_iter().filter(|h| h.is_dir()) {
                crate::diag::record(code::DISC_USER_HOME, crate::diag::Severity::Info, h.path.clone());
                dirs.push((h.path.clone(), 5));
            }
        }
        for (dir, depth) in dirs {
            if !m.fs.exists(&dir) {
                continue;
            }
            let wopts = WalkOptions { max_depth: depth, max_files: opts.max_entries, skip_dirs: vec![".cache".into(), "node_modules".into(), "Trash".into(), ".git".into(), "proc".into()] };
            let stats = evidencefs::fs::walk(m.fs.as_ref(), &dir, &wopts, &mut |e: &Entry| {
                if e.kind == EntryKind::Dir {
                    return WalkStep::Continue;
                }
                let Some(rel) = rel_of(root, &e.path) else { return WalkStep::Continue };
                match classify(&rel) {
                    Some((area, parser)) if wanted(area, opts) => {
                        crate::diag::record(code::DISC_FILE, crate::diag::Severity::Info, format!("{} {rel} ({area}, {})", m.label, parser.name()));
                        if e.link_target.is_some() {
                            crate::diag::record(code::DISC_LINK, crate::diag::Severity::Info, rel.clone());
                        }
                        let name = &e.name;
                        if name.ends_with('-') || name.ends_with('~') || name.ends_with(".bak") || name.contains(".dpkg-") || name.ends_with(".orig") {
                            crate::diag::info(code::DISC_SKIPPED_BACKUP, rel.clone());
                        }
                        out.push(ConfigFile { item: item.to_string(), mount: *mi, mount_label: m.label.clone(), root: root.clone(), rel, path: e.path.clone(), area, parser, entry: fix_times(e), deleted: None, snapshot });
                    }
                    Some(_) => {}
                    None => {
                        crate::diag::record(code::DISC_UNKNOWN_FILE, crate::diag::Severity::Info, rel);
                    }
                }
                WalkStep::Continue
            });
            crate::diag::surface_crates();
            if stats.truncated {
                crate::diag::warn(code::DISC_WALK_LIMIT, format!("{} {dir}", m.label));
            }
        }
    }
    if opts.deleted {
        let mut seen_mounts = std::collections::BTreeSet::new();
        for (mi, root) in roots {
            if !seen_mounts.insert(*mi) {
                continue;
            }
            let m = &ev.mounts[*mi];
            if !m.fs.supports_deleted() || (m.is_snapshot() && !opts.snapshots) {
                continue;
            }
            let list = ev.deleted(*mi, None);
            crate::diag::surface_crates();
            let Ok(list) = list else { continue };
            let mut n = 0usize;
            for e in list {
                if e.kind == EntryKind::Dir {
                    continue;
                }
                let Some((id, original)) = evidencefs::fs::parse_deleted(&e.path) else { continue };
                let Some(rel) = roots.iter().filter(|(i, _)| i == mi).find_map(|(_, r)| rel_of(r, &original)) else { continue };
                if let Some((area, parser)) = classify(&rel) {
                    if !wanted(area, opts) {
                        continue;
                    }
                    n += 1;
                    out.push(ConfigFile { item: item.to_string(), mount: *mi, mount_label: m.label.clone(), root: root.clone(), rel, path: e.path.clone(), area, parser, entry: e.clone(), deleted: Some(id), snapshot: m.is_snapshot() });
                }
            }
            crate::diag::info(code::DISC_DELETED_SCAN, format!("{}: {n} configuration file(s)", m.label));
        }
    } else {
        crate::diag::info(code::DISC_DELETED_SKIPPED, item.to_string());
    }
    out.sort_by(|a, b| (a.mount, &a.root, a.deleted.is_some(), &a.rel, &a.deleted).cmp(&(b.mount, &b.root, b.deleted.is_some(), &b.rel, &b.deleted)));
    out.dedup_by(|a, b| a.mount == b.mount && a.path == b.path);
    out
}

/// The times of `var/lib/dpkg/info/*.list` under a root: package (and `package:arch`) to
/// the list's modification time.
pub fn dpkg_times(ev: &Evidence, mount: usize, root: &str) -> BTreeMap<String, Timestamp> {
    let mut out = BTreeMap::new();
    let dir = evidencefs::fs::join(root, "var/lib/dpkg/info");
    if let Ok(list) = ev.mounts[mount].fs.read_dir(&dir) {
        for e in list {
            if let Some(stem) = e.name.strip_suffix(".list") {
                if let Some(t) = e.times.modified.or(e.times.changed) {
                    out.insert(stem.to_string(), t);
                }
            }
        }
        crate::diag::info(code::DISC_DPKG_LISTS, format!("{} list(s)", out.len()));
    }
    crate::diag::surface_crates();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_system_files() {
        assert_eq!(classify("etc/passwd"), Some(("accounts", Parser::Passwd)));
        assert_eq!(classify("/etc/shadow"), Some(("accounts", Parser::Shadow)));
        assert_eq!(classify("etc/shadow-"), Some(("accounts", Parser::Shadow)));
        assert_eq!(classify("etc/passwd.bak"), Some(("accounts", Parser::Passwd)));
        assert_eq!(classify("etc/sudoers.d/90-cloud-init-users"), Some(("sudo", Parser::Sudoers)));
        assert_eq!(classify("etc/ssh/sshd_config.d/50-cloudimg-settings.conf"), Some(("ssh", Parser::SshConfig)));
        assert_eq!(classify("etc/cron.d/e2scrub_all"), Some(("cron", Parser::CronSystem)));
        assert_eq!(classify("etc/cron.daily/apt-compat"), Some(("cron", Parser::Script)));
        assert_eq!(classify("var/spool/cron/crontabs/bob"), Some(("cron", Parser::CronUser)));
        assert_eq!(classify("var/spool/cron/atjobs/a0001"), Some(("at", Parser::AtJob)));
        assert_eq!(classify("etc/ld.so.preload"), Some(("preload", Parser::Lines)));
        assert_eq!(classify("etc/pam.d/common-auth"), Some(("pam", Parser::Pam)));
        assert_eq!(classify("etc/apt/sources.list.d/ubuntu.sources"), Some(("sources", Parser::AptDeb822)));
        assert_eq!(classify("etc/apt/sources.list.d/x.list"), Some(("sources", Parser::AptSources)));
        assert_eq!(classify("etc/apt/apt.conf.d/20auto-upgrades"), Some(("sources", Parser::AptConf)));
        assert_eq!(classify("etc/yum.repos.d/epel.repo"), Some(("sources", Parser::Ini)));
        assert_eq!(classify("var/lib/dpkg/status"), Some(("packages", Parser::DpkgStatus)));
        assert_eq!(classify("var/lib/rpm/rpmdb.sqlite"), Some(("packages", Parser::RpmDb)));
        assert_eq!(classify("etc/update-motd.d/50-motd-news"), Some(("motd", Parser::Script)));
        assert_eq!(classify("etc/rc2.d/S01ssh"), Some(("init", Parser::Script)));
        assert_eq!(classify("etc/nginx/sites-enabled/default"), Some(("web", Parser::Lines)));
        assert_eq!(classify("etc/default/grub"), Some(("environment", Parser::KvEq)));
        assert_eq!(classify("etc/NetworkManager/system-connections/wifi.nmconnection"), Some(("network", Parser::Ini)));
        assert_eq!(classify("etc/iptables/rules.v4"), Some(("firewall", Parser::Lines)));
        assert_eq!(classify("etc/logrotate.d/rsyslog"), Some(("logrotate", Parser::Logrotate)));
        assert_eq!(classify("etc/xdg/autostart/x.desktop"), Some(("autostart", Parser::Ini)));
        assert_eq!(classify("etc/systemd/system-generators/g"), Some(("systemd", Parser::FileOnly)));
        assert_eq!(classify("etc/systemd/journald.conf"), Some(("systemd", Parser::Ini)));
        assert_eq!(classify("etc/random.txt"), None);
        assert_eq!(classify("etc/.passwd.swp"), None);
    }

    #[test]
    fn classify_units_and_dropins() {
        assert_eq!(classify("etc/systemd/system/backdoor.service"), Some(("systemd", Parser::Unit)));
        assert_eq!(classify("etc/systemd/system/multi-user.target.wants/ssh.service"), Some(("systemd", Parser::Unit)));
        assert_eq!(classify("lib/systemd/system/cron.service"), Some(("systemd", Parser::Unit)));
        assert_eq!(classify("usr/lib/systemd/system/x.timer"), Some(("systemd", Parser::Unit)));
        assert_eq!(classify("etc/systemd/system/ssh.service.d/override.conf"), Some(("systemd", Parser::Unit)));
        assert_eq!(classify("etc/systemd/system/README"), None);
        assert_eq!(classify("home/bob/.config/systemd/user/x.service"), Some(("systemd", Parser::Unit)));
    }

    #[test]
    fn classify_home_files() {
        assert_eq!(classify("home/bob/.bashrc"), Some(("shell", Parser::Script)));
        assert_eq!(classify("root/.profile"), Some(("shell", Parser::Script)));
        assert_eq!(classify("home/bob/.config/fish/config.fish"), Some(("shell", Parser::Script)));
        assert_eq!(classify("home/bob/.ssh/authorized_keys"), Some(("keys", Parser::AuthorizedKeys)));
        assert_eq!(classify("root/.ssh/authorized_keys2"), Some(("keys", Parser::AuthorizedKeys)));
        assert_eq!(classify("home/bob/.ssh/known_hosts"), Some(("keys", Parser::KnownHosts)));
        assert_eq!(classify("home/bob/.ssh/config"), Some(("ssh", Parser::SshConfig)));
        assert_eq!(classify("home/bob/.config/autostart/upd.desktop"), Some(("autostart", Parser::Ini)));
        assert_eq!(classify("var/www/.ssh/authorized_keys"), Some(("keys", Parser::AuthorizedKeys)));
        assert_eq!(classify("home/bob/notes.txt"), None);
        assert_eq!(classify("home/bob/.ssh/id_ed25519"), None, "private keys are never read");
    }

    #[test]
    fn areas_are_known() {
        assert!(AREAS.len() >= 20);
        for (a, d) in AREAS {
            assert!(is_area(a));
            assert!(d.len() > 5);
        }
        assert!(is_area("SUDO"));
        assert!(!is_area("bogus"));
    }

    #[test]
    fn relative_paths() {
        assert_eq!(rel_of("/", "/etc/passwd").as_deref(), Some("etc/passwd"));
        assert_eq!(rel_of("/[root]", "/[root]/etc/passwd").as_deref(), Some("etc/passwd"));
        assert_eq!(rel_of("/a", "/ab/etc"), None);
        assert_eq!(rel_of("/a", "/b/etc"), None);
    }

    #[test]
    fn owners_by_place() {
        let e = Entry::new("/home/bob/.bashrc", EntryKind::File);
        let cf = ConfigFile { item: "i".into(), mount: 0, mount_label: "folder".into(), root: "/".into(), rel: "home/bob/.bashrc".into(), path: "/home/bob/.bashrc".into(), area: "shell", parser: Parser::Script, entry: e.clone(), deleted: None, snapshot: false };
        assert_eq!(cf.owner(), "bob");
        assert_eq!(cf.source(), "folder/home/bob/.bashrc");
        let mut root = cf.clone();
        root.rel = "root/.profile".into();
        assert_eq!(root.owner(), "root");
        let mut cron = cf.clone();
        cron.rel = "var/spool/cron/crontabs/eve".into();
        cron.parser = Parser::CronUser;
        cron.entry = Entry::new("/var/spool/cron/crontabs/eve", EntryKind::File);
        assert_eq!(cron.owner(), "eve");
        let mut sys = cf;
        sys.rel = "etc/passwd".into();
        sys.parser = Parser::Passwd;
        assert_eq!(sys.owner(), "");
    }
}
