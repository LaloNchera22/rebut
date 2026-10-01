//! On-disk cache of warm Firecracker snapshots.
//!
//! A snapshot is a VM booted from the standard rootfs with the guest agent
//! already listening on vsock and the repo's dependencies fetched (and
//! optionally prebuilt) into a cargo cache drive. It is keyed by
//! `(repo, Cargo.lock digest, toolchain)`: any change to the lockfile or the
//! toolchain needs a new snapshot.
//!
//! The index is a single `index.json` in the cache directory, rewritten
//! atomically (temp file + rename) on every change.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rebut_core::Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const INDEX_FILE: &str = "index.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotKey {
    /// Canonical repository URL.
    pub repo: String,
    /// SHA-256 of the repository's `Cargo.lock`.
    pub cargo_lock: Digest,
    /// Toolchain identifier, e.g. `1.80.0-x86_64-unknown-linux-gnu`.
    pub toolchain: String,
}

impl SnapshotKey {
    /// Stable identifier, also used as the entry's directory name.
    pub fn id(&self) -> String {
        Digest::of_parts(&[
            b"rebut/snapshot-key/v1",
            self.repo.as_bytes(),
            &self.cargo_lock.0,
            self.toolchain.as_bytes(),
        ])
        .to_hex()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Firecracker VM state file (`snapshot_path` of `/snapshot/load`).
    pub vmstate: PathBuf,
    /// Guest memory file (`mem_backend.backend_path`).
    pub memory: PathBuf,
    /// Read-only ext4 image with the warm `CARGO_HOME` (and target cache),
    /// attached at the path it had when the snapshot was taken.
    pub cache_drive: Option<PathBuf>,
    /// Digest over the digests of all the files above; part of the
    /// execution's `environment` digest.
    pub digest: Digest,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Index {
    entries: BTreeMap<String, Record>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    key: SnapshotKey,
    entry: SnapshotEntry,
}

pub struct SnapshotCache {
    dir: PathBuf,
    index: Mutex<Index>,
}

impl SnapshotCache {
    /// Opens (or creates) the cache rooted at `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(INDEX_FILE);
        let index = if path.exists() {
            serde_json::from_slice(&std::fs::read(&path)?)?
        } else {
            Index::default()
        };
        Ok(SnapshotCache {
            dir,
            index: Mutex::new(index),
        })
    }

    /// Suggested directory for the files of a new snapshot for `key`.
    pub fn entry_dir(&self, key: &SnapshotKey) -> PathBuf {
        self.dir.join(key.id())
    }

    /// Looks up a snapshot. Entries whose files have disappeared are ignored.
    pub fn get(&self, key: &SnapshotKey) -> Option<SnapshotEntry> {
        let index = self.index.lock().expect("snapshot index poisoned");
        let rec = index.entries.get(&key.id())?;
        let e = &rec.entry;
        let present = e.vmstate.is_file()
            && e.memory.is_file()
            && e.cache_drive.as_ref().map_or(true, |p| p.is_file());
        present.then(|| e.clone())
    }

    /// Registers snapshot files for `key`, hashing them, and persists the
    /// index. Replaces any previous entry for the same key.
    pub fn insert(
        &self,
        key: SnapshotKey,
        vmstate: PathBuf,
        memory: PathBuf,
        cache_drive: Option<PathBuf>,
    ) -> anyhow::Result<SnapshotEntry> {
        let mut parts = vec![digest_file(&vmstate)?, digest_file(&memory)?];
        if let Some(c) = &cache_drive {
            parts.push(digest_file(c)?);
        }
        let refs: Vec<&[u8]> = std::iter::once(&b"rebut/snapshot/v1"[..])
            .chain(parts.iter().map(|d| &d.0[..]))
            .collect();
        let entry = SnapshotEntry {
            vmstate,
            memory,
            cache_drive,
            digest: Digest::of_parts(&refs),
        };
        let mut index = self.index.lock().expect("snapshot index poisoned");
        index.entries.insert(
            key.id(),
            Record {
                key,
                entry: entry.clone(),
            },
        );
        self.persist(&index)?;
        Ok(entry)
    }

    /// Forgets the entry for `key` (files are left in place).
    pub fn remove(&self, key: &SnapshotKey) -> anyhow::Result<()> {
        let mut index = self.index.lock().expect("snapshot index poisoned");
        if index.entries.remove(&key.id()).is_some() {
            self.persist(&index)?;
        }
        Ok(())
    }

    fn persist(&self, index: &Index) -> anyhow::Result<()> {
        let tmp = self.dir.join(format!("{INDEX_FILE}.tmp"));
        std::fs::write(&tmp, serde_json::to_vec_pretty(index)?)?;
        std::fs::rename(&tmp, self.dir.join(INDEX_FILE))?;
        Ok(())
    }
}

/// Streaming SHA-256 of a file (images are too large to read at once).
pub fn digest_file(path: &Path) -> std::io::Result<Digest> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(Digest(h.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(lock: &[u8]) -> SnapshotKey {
        SnapshotKey {
            repo: "https://github.com/o/r".into(),
            cargo_lock: Digest::of(lock),
            toolchain: "1.80.0".into(),
        }
    }

    #[test]
    fn digest_file_matches_in_memory_digest() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        let data = vec![3u8; (1 << 20) + 17];
        std::fs::write(&p, &data).unwrap();
        assert_eq!(digest_file(&p).unwrap(), Digest::of(&data));
    }

    #[test]
    fn insert_get_persist_remove() {
        let d = tempfile::tempdir().unwrap();
        let cache = SnapshotCache::open(d.path().join("cache")).unwrap();
        let k = key(b"lock-v1");
        let dir = cache.entry_dir(&k);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vm"), b"state").unwrap();
        std::fs::write(dir.join("mem"), b"memory").unwrap();

        assert!(cache.get(&k).is_none());
        let e = cache
            .insert(k.clone(), dir.join("vm"), dir.join("mem"), None)
            .unwrap();
        assert_eq!(cache.get(&k), Some(e.clone()));
        // Different lockfile or toolchain: miss.
        assert!(cache.get(&key(b"lock-v2")).is_none());
        let mut other_tc = k.clone();
        other_tc.toolchain = "1.81.0".into();
        assert!(cache.get(&other_tc).is_none());

        // Survives reopening.
        let reopened = SnapshotCache::open(d.path().join("cache")).unwrap();
        assert_eq!(reopened.get(&k), Some(e.clone()));

        // Content change → different digest.
        std::fs::write(dir.join("mem"), b"memory2").unwrap();
        let e2 = reopened
            .insert(k.clone(), dir.join("vm"), dir.join("mem"), None)
            .unwrap();
        assert_ne!(e.digest, e2.digest);

        // Missing files are treated as a miss.
        std::fs::remove_file(dir.join("vm")).unwrap();
        assert!(reopened.get(&k).is_none());

        reopened.remove(&k).unwrap();
        let again = SnapshotCache::open(d.path().join("cache")).unwrap();
        assert!(again.index.lock().unwrap().entries.is_empty());
    }
}
