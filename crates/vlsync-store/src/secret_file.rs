//! `--<secret>-file` options: a secret read from a mounted file instead of
//! an env var, which `docker inspect` and a rendered compose file would show.

use std::path::Path;

/// The file's contents less one trailing newline (`\n` or `\r\n`, as an
/// editor or `echo` leaves it). Errors name the flag and path, never the
/// contents.
pub fn read(flag: &str, path: &Path) -> anyhow::Result<String> {
    let mut s = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("--{flag} {}: {e}", path.display()))?;
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    anyhow::ensure!(!s.is_empty(), "--{flag} {} is empty", path.display());
    Ok(s)
}

/// `*plain = read(file)` when `file` is set; clap's `conflicts_with` keeps the
/// two from both being given.
pub fn resolve(flag: &str, file: &Option<std::path::PathBuf>, plain: &mut Option<String>) -> anyhow::Result<()> {
    if let Some(p) = file {
        *plain = Some(read(flag, p)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(contents: &[u8]) -> std::path::PathBuf {
        let p =
            std::env::temp_dir().join(format!("vlpds-secret-file-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn trims_one_trailing_newline() {
        for (raw, want) in [
            (&b"s3cret"[..], "s3cret"),
            (b"s3cret\n", "s3cret"),
            (b"s3cret\r\n", "s3cret"),
            (b"s3cret\n\n", "s3cret\n"),
            (b" s3cret \n", " s3cret "),
        ] {
            let p = tmp(raw);
            assert_eq!(read("x-file", &p).unwrap(), want, "{raw:?}");
            std::fs::remove_file(p).unwrap();
        }
    }

    #[test]
    fn empty_file_is_an_error() {
        for raw in [&b""[..], b"\n", b"\r\n"] {
            let p = tmp(raw);
            let e = read("jwt-secret-file", &p).unwrap_err().to_string();
            assert!(e.contains("--jwt-secret-file") && e.contains("is empty"), "{e}");
            std::fs::remove_file(p).unwrap();
        }
    }

    #[test]
    fn missing_file_names_flag_not_contents() {
        let p = std::env::temp_dir().join("vlpds-secret-file-does-not-exist");
        let e = read("admin-token-file", &p).unwrap_err().to_string();
        assert!(e.contains("--admin-token-file") && e.contains("vlpds-secret-file-does-not-exist"), "{e}");
    }

    #[test]
    fn resolve_overrides_plain_only_with_a_file() {
        let mut v = Some("from-env".to_string());
        resolve("x-file", &None, &mut v).unwrap();
        assert_eq!(v.as_deref(), Some("from-env"));
        let p = tmp(b"from-file\n");
        let mut v = None;
        resolve("x-file", &Some(p.clone()), &mut v).unwrap();
        assert_eq!(v.as_deref(), Some("from-file"));
        std::fs::remove_file(p).unwrap();
    }
}
