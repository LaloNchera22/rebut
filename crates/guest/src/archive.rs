//! Source tarballs (`.tar.gz`): deterministic packing on the host and
//! defensive unpacking in the guest.
//!
//! Unpacking treats the archive as hostile. Only regular files and
//! directories are accepted; absolute paths, `..` components, symlinks,
//! hardlinks and device nodes are rejected with an error (never silently
//! skipped), and the total unpacked size is bounded to stop gzip bombs.

use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use tar::{Archive, Builder, EntryType, Header};

/// Upper bound on the sum of file sizes in an unpacked source tree.
pub const MAX_UNPACKED_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Top-level directories never shipped into the VM.
const SKIPPED_ROOT_DIRS: &[&str] = &["target", ".git"];

#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("unsafe path in archive: {0:?}")]
    UnsafePath(PathBuf),
    #[error("unsupported entry type {kind:?} for {path:?}")]
    UnsupportedEntry { path: PathBuf, kind: EntryType },
    #[error("archive unpacks to more than {MAX_UNPACKED_SIZE} bytes")]
    TooLarge,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Validates an archive path: relative, and made only of normal components.
fn check_path(path: &Path) -> Result<(), ArchiveError> {
    let mut any = false;
    for c in path.components() {
        match c {
            Component::Normal(_) => any = true,
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ArchiveError::UnsafePath(path.to_path_buf()))
            }
        }
    }
    if any {
        Ok(())
    } else {
        Err(ArchiveError::UnsafePath(path.to_path_buf()))
    }
}

/// Unpacks a gzip-compressed tarball into `dest` (which must exist).
pub fn unpack_tarball(tar_gz: &[u8], dest: &Path) -> Result<(), ArchiveError> {
    let mut archive = Archive::new(GzDecoder::new(tar_gz));
    archive.set_preserve_permissions(true);
    archive.set_preserve_ownerships(false);
    archive.set_overwrite(true);
    let mut total: u64 = 0;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        check_path(&path)?;
        let kind = entry.header().entry_type();
        match kind {
            EntryType::Regular | EntryType::Continuous => {
                total = total.saturating_add(entry.size());
                if total > MAX_UNPACKED_SIZE {
                    return Err(ArchiveError::TooLarge);
                }
            }
            EntryType::Directory => {}
            // PAX/GNU metadata records are consumed by the `tar` crate itself.
            EntryType::XHeader | EntryType::XGlobalHeader => continue,
            EntryType::GNULongName | EntryType::GNULongLink => continue,
            _ => return Err(ArchiveError::UnsupportedEntry { path, kind }),
        }
        // `unpack_in` re-validates the path and refuses to write through
        // anything outside `dest`; it returns false if it skipped the entry.
        if !entry.unpack_in(dest)? {
            return Err(ArchiveError::UnsafePath(path));
        }
    }
    Ok(())
}

/// Reads a single regular file from a tarball, if present (e.g. `Cargo.lock`).
pub fn read_file(tar_gz: &[u8], wanted: &Path) -> Result<Option<Vec<u8>>, ArchiveError> {
    let mut archive = Archive::new(GzDecoder::new(tar_gz));
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let normalized: PathBuf = path
            .components()
            .filter(|c| !matches!(c, Component::CurDir))
            .collect();
        if normalized == wanted && entry.header().entry_type().is_file() {
            let mut buf = Vec::new();
            entry
                .by_ref()
                .take(MAX_UNPACKED_SIZE)
                .read_to_end(&mut buf)?;
            return Ok(Some(buf));
        }
    }
    Ok(None)
}

/// Packs `root` into a deterministic `.tar.gz`: entries sorted, mtimes and
/// ownership zeroed. Skips `target/` and `.git/` at the root and all symlinks
/// (which the guest would reject anyway).
pub fn pack_directory(root: &Path) -> Result<Vec<u8>, ArchiveError> {
    let enc = GzEncoder::new(Vec::new(), Compression::fast());
    let mut builder = Builder::new(enc);
    builder.mode(tar::HeaderMode::Deterministic);
    append_dir(&mut builder, root, Path::new(""))?;
    let mut enc = builder.into_inner()?;
    enc.flush()?;
    Ok(enc.finish()?)
}

fn append_dir<W: Write>(b: &mut Builder<W>, root: &Path, rel: &Path) -> Result<(), ArchiveError> {
    let mut entries: Vec<_> = fs::read_dir(root.join(rel))?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name();
        if rel.as_os_str().is_empty() && SKIPPED_ROOT_DIRS.iter().any(|s| name.as_os_str() == *s) {
            continue;
        }
        let rel_path = rel.join(&name);
        let ft = e.file_type()?;
        if ft.is_dir() {
            let mut h = Header::new_gnu();
            h.set_entry_type(EntryType::Directory);
            h.set_mode(0o755);
            h.set_size(0);
            h.set_mtime(0);
            b.append_data(&mut h, &rel_path, std::io::empty())?;
            append_dir(b, root, &rel_path)?;
        } else if ft.is_file() {
            b.append_path_with_name(e.path(), &rel_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_tar(build: impl FnOnce(&mut Builder<Vec<u8>>)) -> Vec<u8> {
        let mut b = Builder::new(Vec::new());
        build(&mut b);
        let tar = b.into_inner().unwrap();
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(&tar).unwrap();
        enc.finish().unwrap()
    }

    /// Writes a header with an arbitrary (possibly unsafe) path, bypassing
    /// the `tar` crate's own path validation on the builder side.
    fn file_with_raw_path(b: &mut Builder<Vec<u8>>, path: &str, data: &[u8]) {
        let mut h = Header::new_gnu();
        h.as_gnu_mut().unwrap().name[..path.len()].copy_from_slice(path.as_bytes());
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(EntryType::Regular);
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    #[test]
    fn roundtrip_skips_target_and_git() {
        let src = tempfile::tempdir().unwrap();
        fs::create_dir_all(src.path().join("src/nested")).unwrap();
        fs::create_dir_all(src.path().join("target/debug")).unwrap();
        fs::create_dir_all(src.path().join(".git")).unwrap();
        fs::write(src.path().join("Cargo.toml"), "[package]").unwrap();
        fs::write(src.path().join("src/nested/a.rs"), "fn a() {}").unwrap();
        fs::write(src.path().join("target/debug/junk"), "x").unwrap();
        fs::write(src.path().join(".git/HEAD"), "x").unwrap();

        let tgz = pack_directory(src.path()).unwrap();
        assert_eq!(tgz, pack_directory(src.path()).unwrap(), "deterministic");
        assert_eq!(
            read_file(&tgz, Path::new("Cargo.toml")).unwrap().unwrap(),
            b"[package]"
        );
        assert!(read_file(&tgz, Path::new("missing")).unwrap().is_none());

        let dst = tempfile::tempdir().unwrap();
        unpack_tarball(&tgz, dst.path()).unwrap();
        assert_eq!(
            fs::read_to_string(dst.path().join("src/nested/a.rs")).unwrap(),
            "fn a() {}"
        );
        assert!(!dst.path().join("target").exists());
        assert!(!dst.path().join(".git").exists());
    }

    #[test]
    fn rejects_parent_dir_components() {
        let tgz = raw_tar(|b| file_with_raw_path(b, "src/../../evil", b"x"));
        let dst = tempfile::tempdir().unwrap();
        let err = unpack_tarball(&tgz, dst.path()).unwrap_err();
        assert!(matches!(err, ArchiveError::UnsafePath(_)), "{err}");
        assert!(!dst.path().parent().unwrap().join("evil").exists());
    }

    #[test]
    fn rejects_absolute_paths() {
        let tgz = raw_tar(|b| file_with_raw_path(b, "/tmp/rebut-evil", b"x"));
        let dst = tempfile::tempdir().unwrap();
        let err = unpack_tarball(&tgz, dst.path()).unwrap_err();
        assert!(matches!(err, ArchiveError::UnsafePath(_)), "{err}");
    }

    #[test]
    fn rejects_symlinks() {
        let tgz = raw_tar(|b| {
            let mut h = Header::new_gnu();
            h.set_entry_type(EntryType::Symlink);
            h.set_size(0);
            b.append_link(&mut h, "link", "/etc").unwrap();
        });
        let dst = tempfile::tempdir().unwrap();
        let err = unpack_tarball(&tgz, dst.path()).unwrap_err();
        assert!(
            matches!(err, ArchiveError::UnsupportedEntry { .. }),
            "{err}"
        );
    }
}
