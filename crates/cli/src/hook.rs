//! `rebut hook install|uninstall`: a git pre-push hook that runs
//! `rebut verify` before your commits leave the machine.
//!
//! The hook is ours only if it carries [`MARKER`]; any other pre-push hook is
//! left alone unless the caller forces an overwrite.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context};

/// Line that identifies a hook written by `rebut hook install`.
pub const MARKER: &str = "# installed by `rebut hook install`";

/// The pre-push hook script for `base`.
pub fn script(base: &str) -> String {
    format!(
        "#!/bin/sh\n\
         {MARKER}; remove with `rebut hook uninstall`.\n\
         # Runs rebut's checks against {base} before every push. Skip once with\n\
         # `git push --no-verify`.\n\
         exec rebut verify --base {} --fail-on-findings\n",
        shell_quote(base)
    )
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./@+:".contains(&b))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// The hooks directory git uses for `repo` (honours `core.hooksPath` and
/// linked worktrees).
pub fn hooks_dir(repo: &Path) -> anyhow::Result<PathBuf> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--path-format=absolute", "--git-path", "hooks"])
        .output()
        .context("running git")?;
    if !out.status.success() {
        bail!(
            "{} is not a git repository: {}",
            repo.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(PathBuf::from(String::from_utf8(out.stdout)?.trim()))
}

fn is_ours(path: &Path) -> anyhow::Result<Option<bool>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s.contains(MARKER))),
        // Not UTF-8: certainly not ours.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => Ok(Some(false)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Writes `pre-push` into `hooks_dir`. Refuses to replace a hook that
/// `rebut` did not write unless `force`. Returns the hook's path.
pub fn install(hooks_dir: &Path, base: &str, force: bool) -> anyhow::Result<PathBuf> {
    let path = hooks_dir.join("pre-push");
    if is_ours(&path)? == Some(false) && !force {
        bail!(
            "{} already exists and was not installed by rebut; \
             pass --force to replace it",
            path.display()
        );
    }
    std::fs::create_dir_all(hooks_dir)
        .with_context(|| format!("creating {}", hooks_dir.display()))?;
    std::fs::write(&path, script(base)).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(path)
}

/// Removes `pre-push` from `hooks_dir` if `rebut` wrote it. Returns whether
/// a hook was removed; a hook that is not ours is an error.
pub fn uninstall(hooks_dir: &Path) -> anyhow::Result<bool> {
    let path = hooks_dir.join("pre-push");
    match is_ours(&path)? {
        None => Ok(false),
        Some(false) => bail!(
            "{} was not installed by rebut; leaving it alone",
            path.display()
        ),
        Some(true) => {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_writes_executable_hook() {
        let d = tempfile::tempdir().unwrap();
        let hooks = d.path().join("hooks");
        let path = install(&hooks, "main", false).unwrap();
        let s = std::fs::read_to_string(&path).unwrap();
        assert!(s.starts_with("#!/bin/sh\n"));
        assert!(s.contains(MARKER));
        assert!(s.contains("exec rebut verify --base main --fail-on-findings\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111);
        }
        // Reinstalling over our own hook is fine and updates the base.
        install(&hooks, "origin/develop", false).unwrap();
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("--base origin/develop "));
    }

    #[test]
    fn foreign_hook_needs_force_and_survives_uninstall() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("pre-push");
        std::fs::write(&path, "#!/bin/sh\nmake lint\n").unwrap();

        let err = install(d.path(), "main", false).unwrap_err();
        assert!(err.to_string().contains("--force"), "{err}");
        assert!(uninstall(d.path()).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "#!/bin/sh\nmake lint\n"
        );

        install(d.path(), "main", true).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains(MARKER));
    }

    #[test]
    fn uninstall_removes_only_ours() {
        let d = tempfile::tempdir().unwrap();
        assert!(!uninstall(d.path()).unwrap());
        let path = install(d.path(), "main", false).unwrap();
        assert!(uninstall(d.path()).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn base_is_shell_quoted() {
        assert!(script("main").contains("--base main "));
        assert!(script("a b").contains("--base 'a b' "));
        assert!(script("x';rm -rf /;'").contains(r"--base 'x'\'';rm -rf /;'\''' "));
    }

    #[test]
    fn hooks_dir_of_a_git_repo() {
        let d = tempfile::tempdir().unwrap();
        let ok = Command::new("git")
            .args(["init", "-q"])
            .arg(d.path())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("git unavailable; skipped");
            return;
        }
        let dir = hooks_dir(d.path()).unwrap();
        assert!(dir.ends_with(".git/hooks"), "{}", dir.display());
        assert!(hooks_dir(&d.path().join("missing")).is_err());
    }
}
