//! Tree walking without git: the control plane hands us two checkouts.
//!
//! The checkouts contain hostile PR content and the planner runs outside the
//! VM, so the walker never follows symlinks (a link to `/dev/zero` or to a
//! host secret must not be read) and caps the size of files it loads.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

/// Files larger than this are not loaded; they are fingerprinted by size and
/// treated as unparsable if they are Rust sources.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Directories never descended into.
const SKIP_DIRS: &[&str] = &[".git", "target"];

/// One entry of a tree, keyed by its `/`-separated path relative to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Entry {
    File(Vec<u8>),
    /// Too large to load; only the length is known.
    Oversized(u64),
    /// A symlink, represented by its target (never followed).
    Link(String),
}

impl Entry {
    pub(crate) fn contents(&self) -> Option<&[u8]> {
        match self {
            Entry::File(b) => Some(b),
            _ => None,
        }
    }
}

/// Recursively lists every regular file and symlink under `root`.
pub(crate) fn walk(root: &Path) -> io::Result<BTreeMap<String, Entry>> {
    let mut out = BTreeMap::new();
    if root.exists() {
        walk_into(root, "", &mut out)?;
    }
    Ok(out)
}

fn walk_into(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Entry>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let meta = fs::symlink_metadata(entry.path())?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            let target = fs::read_link(entry.path())?;
            out.insert(rel, Entry::Link(target.to_string_lossy().into_owned()));
        } else if ft.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk_into(&entry.path(), &rel, out)?;
            }
        } else if ft.is_file() {
            let e = if meta.len() > MAX_FILE_BYTES {
                Entry::Oversized(meta.len())
            } else {
                Entry::File(fs::read(entry.path())?)
            };
            out.insert(rel, e);
        }
        // Sockets, fifos and devices are ignored: they cannot be part of a
        // git checkout and reading them could block.
    }
    Ok(())
}

/// Paths (relative, `/`-separated, sorted) that differ between two trees:
/// added, removed or modified. `.git/` and `target/` are ignored.
pub fn changed_files(base: &Path, head: &Path) -> io::Result<Vec<String>> {
    let (b, h) = (walk(base)?, walk(head)?);
    Ok(diff(&b, &h))
}

pub(crate) fn diff(base: &BTreeMap<String, Entry>, head: &BTreeMap<String, Entry>) -> Vec<String> {
    let mut changed: Vec<String> = base
        .iter()
        .filter(|(k, v)| head.get(*k) != Some(v))
        .map(|(k, _)| k.clone())
        .chain(head.keys().filter(|k| !base.contains_key(*k)).cloned())
        .collect();
    changed.sort();
    changed.dedup();
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    #[test]
    fn reports_added_removed_and_modified() {
        let (b, h) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        write(b.path(), "same.txt", "x");
        write(h.path(), "same.txt", "x");
        write(b.path(), "src/mod.rs", "a");
        write(h.path(), "src/mod.rs", "b");
        write(b.path(), "gone.rs", "");
        write(h.path(), "new/file.rs", "");
        write(h.path(), "target/debug/junk", "ignored");
        write(h.path(), ".git/HEAD", "ignored");
        let got = changed_files(b.path(), h.path()).unwrap();
        assert_eq!(got, vec!["gone.rs", "new/file.rs", "src/mod.rs"]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_compared_not_followed() {
        let (b, h) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        std::os::unix::fs::symlink("/dev/zero", h.path().join("evil")).unwrap();
        let got = changed_files(b.path(), h.path()).unwrap();
        assert_eq!(got, vec!["evil"]);
    }
}
