from pathlib import Path

main = Path('src/main.rs')
text = main.read_text()
old = '''fn load_or_create_token(path: &Path) -> Result<String> {
    if let Ok(token) = std::fs::read_to_string(path) {
        let token = token.trim();
        if token.len() >= 32 && !token.chars().any(char::is_whitespace) {
            return Ok(token.to_owned());
        }
        bail!("desktop daemon token file is malformed");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("token path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    std::fs::write(path, format!("{token}\\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    return Ok(token);
}
'''
new = '''fn load_or_create_token(path: &Path) -> Result<String> {
    const MAX_TOKEN_FILE_BYTES: u64 = 4096;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("desktop daemon token path must be a regular non-symlink file");
            }
            if metadata.len() == 0 || metadata.len() > MAX_TOKEN_FILE_BYTES {
                bail!("desktop daemon token file size is invalid");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if metadata.permissions().mode() & 0o077 != 0 {
                    bail!("desktop daemon token file must have owner-only permissions (0600)");
                }
            }
            let token = std::fs::read_to_string(path)?;
            let token = token.trim();
            if token.len() >= 32 && !token.chars().any(char::is_whitespace) {
                return Ok(token.to_owned());
            }
            bail!("desktop daemon token file is malformed");
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("token path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    {
        use std::io::Write as _;
        file.write_all(format!("{token}\\n").as_bytes())?;
        file.sync_all()?;
    }
    return Ok(token);
}
'''
if text.count(old) != 1:
    raise SystemExit(f'expected one load_or_create_token implementation, found {text.count(old)}')
main.write_text(text.replace(old, new, 1))

test = Path('tests/deploy_path_security.rs')
t = test.read_text()
insert = r'''

#[test]
fn rejects_existing_token_with_group_or_world_access() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_root("weak-token")?;
    let token_path = root.join("weak-token");
    fs::write(&token_path, format!("{}\n", "a".repeat(64)))?;
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o644))?;
    let address = unused_loopback()?;
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let output = Command::new(env!("CARGO_BIN_EXE_ll-desktop-daemon"))
        .env("HOME", &root)
        .env("USERPROFILE", &root)
        .env(
            "LL_DESKTOP_FLAGS_CONFIG",
            manifest_dir.join(".cli-flags.toml"),
        )
        .env("LL_DESKTOP_ADDR", address.to_string())
        .env("LL_DESKTOP_TOKEN_FILE", &token_path)
        .stdin(Stdio::null())
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();

    assert!(!output.status.success());
    assert!(stderr.contains("token"));
    assert!(stderr.contains("0600") || stderr.contains("owner-only") || stderr.contains("permission"));
    fs::remove_dir_all(root)?;
    return Ok(());
}

#[test]
fn rejects_symlink_token_path() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = temp_root("symlink-token")?;
    let target = root.join("real-token");
    let token_path = root.join("token-link");
    fs::write(&target, format!("{}\n", "b".repeat(64)))?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
    symlink(&target, &token_path)?;
    let address = unused_loopback()?;
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let output = Command::new(env!("CARGO_BIN_EXE_ll-desktop-daemon"))
        .env("HOME", &root)
        .env("USERPROFILE", &root)
        .env(
            "LL_DESKTOP_FLAGS_CONFIG",
            manifest_dir.join(".cli-flags.toml"),
        )
        .env("LL_DESKTOP_ADDR", address.to_string())
        .env("LL_DESKTOP_TOKEN_FILE", &token_path)
        .stdin(Stdio::null())
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();

    assert!(!output.status.success());
    assert!(stderr.contains("token"));
    assert!(stderr.contains("symlink") || stderr.contains("regular"));
    assert_eq!(fs::read_to_string(&target)?.trim(), "b".repeat(64));
    fs::remove_dir_all(root)?;
    return Ok(());
}
'''
if 'fn rejects_existing_token_with_group_or_world_access()' in t:
    raise SystemExit('token tests already present')
test.write_text(t + insert)
