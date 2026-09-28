use std::{
    error::Error,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn temp_root(case: &str) -> Result<PathBuf, Box<dyn Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ll-deploy-security-{case}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&root)?;
    return Ok(root);
}

fn unused_loopback() -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    return Ok(address);
}

fn start_daemon(root: &PathBuf, address: SocketAddr, token: &str) -> Result<Child, Box<dyn Error>> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let token_path = root.join("token");
    fs::write(&token_path, format!("{token}\n"))?;
    #[cfg(unix)]
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600))?;

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let child = Command::new(env!("CARGO_BIN_EXE_ll-desktop-daemon"))
        .env("HOME", root)
        .env("USERPROFILE", root)
        .env(
            "LL_DESKTOP_FLAGS_CONFIG",
            manifest_dir.join(".cli-flags.toml"),
        )
        .env("LL_DESKTOP_ADDR", address.to_string())
        .env("LL_DESKTOP_TOKEN_FILE", &token_path)
        .env("LL_WORKER_COMMAND", "lunatic")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    return Ok(child);
}

fn wait_until_listening(address: SocketAddr) -> Result<(), Box<dyn Error>> {
    for _ in 0..100 {
        if TcpStream::connect(address).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    return Err("desktop daemon did not start listening".into());
}

fn post_json(
    address: SocketAddr,
    token: &str,
    path: &str,
    body: &str,
) -> Result<String, Box<dyn Error>> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    return Ok(response);
}

#[cfg(unix)]
#[test]
fn deployment_refuses_symlinked_generation_directory() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let root = temp_root("symlink-directory")?;
    let tenant_root = root.join(".lunatic-lorry/deployments/tenant-a");
    let outside = root.join("outside");
    fs::create_dir_all(&tenant_root)?;
    fs::create_dir_all(&outside)?;
    symlink(&outside, tenant_root.join("deploy-a"))?;

    let address = unused_loopback()?;
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut daemon = start_daemon(&root, address, token)?;
    wait_until_listening(address)?;

    let body =
        r#"{"tenant_id":"tenant-a","deployment_id":"deploy-a","wasm_base64":"AGFzbQEAAAA="}"#;
    let response = post_json(address, token, "/v1/deploy", body)?;

    let _ = daemon.kill();
    let _ = daemon.wait();

    assert!(
        !response.starts_with("HTTP/1.1 200"),
        "deployment followed a symlinked generation directory: {response}"
    );
    assert!(
        !outside.join("module.wasm").exists(),
        "deployment escaped the configured artifact root through a symlink"
    );

    fs::remove_dir_all(root)?;
    return Ok(());
}

#[cfg(unix)]
#[test]
fn deployment_refuses_symlinked_module_file() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let root = temp_root("symlink-module")?;
    let deployment_root = root.join(".lunatic-lorry/deployments/tenant-a/deploy-a");
    let outside = root.join("outside-module.wasm");
    fs::create_dir_all(&deployment_root)?;
    fs::write(&outside, b"sentinel")?;
    symlink(&outside, deployment_root.join("module.wasm"))?;

    let address = unused_loopback()?;
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut daemon = start_daemon(&root, address, token)?;
    wait_until_listening(address)?;

    let body =
        r#"{"tenant_id":"tenant-a","deployment_id":"deploy-a","wasm_base64":"AGFzbQEAAAA="}"#;
    let response = post_json(address, token, "/v1/deploy", body)?;

    let _ = daemon.kill();
    let _ = daemon.wait();

    assert!(
        !response.starts_with("HTTP/1.1 200"),
        "deployment followed a symlinked module file: {response}"
    );
    assert_eq!(
        fs::read(&outside)?,
        b"sentinel",
        "deployment modified the symlink target outside its generation directory"
    );

    fs::remove_dir_all(root)?;
    return Ok(());
}
