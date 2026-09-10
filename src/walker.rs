use anyhow::Result;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// Walk `root`, returning every regular file. When `respect_gitignore` is
/// true this honors `.gitignore`, `.ignore`, and a sieve-specific
/// `.sieveignore`, and always skips `.git/` internals (they're handled
/// separately by the history scanner).
pub fn walk(root: &Path, respect_gitignore: bool) -> Result<Vec<PathBuf>> {
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false) // do look inside dotfiles/dotdirs (secrets love .env)
        .git_ignore(respect_gitignore)
        .git_global(respect_gitignore)
        .git_exclude(respect_gitignore)
        .add_custom_ignore_filename(".sieveignore")
        .filter_entry(|e| e.file_name() != ".git");

    let mut out = Vec::new();
    for result in builder.build() {
        match result {
            Ok(entry) => {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    out.push(entry.into_path());
                }
            }
            Err(_) => continue, // unreadable entry (permissions, broken symlink, ...) — skip, don't abort the scan
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn walk_finds_files_and_skips_gitignored() {
        let dir = tempfile::tempdir().unwrap();
        // The `ignore` crate only honors .gitignore inside an actual git
        // repo (it walks up looking for `.git` to establish the root) — a
        // bare .gitignore with no .git is legitimately not activated. Every
        // real scan target has a .git dir, so the fixture needs one too.
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir.path())
            .status()
            .unwrap();
        fs::write(dir.path().join(".gitignore"), "ignored.txt\n").unwrap();
        fs::write(dir.path().join("keep.txt"), "hello").unwrap();
        fs::write(dir.path().join("ignored.txt"), "secret").unwrap();

        let files = walk(dir.path(), true).unwrap();
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"keep.txt".to_string()));
        assert!(names.contains(&".gitignore".to_string()));
        assert!(!names.contains(&"ignored.txt".to_string()));
    }

    #[test]
    fn walk_skips_git_internals() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".git").join("config"), "junk").unwrap();
        fs::write(dir.path().join("real.txt"), "hello").unwrap();

        let files = walk(dir.path(), true).unwrap();
        assert!(files
            .iter()
            .all(|p| !p.components().any(|c| c.as_os_str() == ".git")));
        assert!(files.iter().any(|p| p.file_name().unwrap() == "real.txt"));
    }
}
