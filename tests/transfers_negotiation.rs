use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct ChildCleanup {
    child: Option<Child>,
}

impl ChildCleanup {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }
}

impl Drop for ChildCleanup {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind free port");
    listener.local_addr().expect("local addr").port()
}

fn spawn_rcroc(bin: &str, args: &[&str]) -> Child {
    Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {:?} failed: {e}", args))
}

fn wait_status_with_timeout(child: &mut Child, timeout: Duration, name: &str) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("try_wait failed") {
            Some(status) => return status,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{name} timed out after {timeout:?}");
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{ts}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn locate_rcroc_bin() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_rcroc") {
        return PathBuf::from(path);
    }

    let current = std::env::current_exe().expect("resolve current test binary path");
    let mut debug_dir = current
        .parent()
        .expect("test binary has parent dir")
        .to_path_buf();
    if debug_dir.file_name().and_then(|n| n.to_str()) == Some("deps") {
        debug_dir = debug_dir
            .parent()
            .expect("deps has parent debug dir")
            .to_path_buf();
    }

    let bin_name = if cfg!(windows) { "rcroc.exe" } else { "rcroc" };
    let candidate = debug_dir.join(bin_name);
    assert!(
        candidate.exists(),
        "rcroc binary not found at {}",
        candidate.display()
    );
    candidate
}

#[test]
fn send_8_receive_2_does_not_hang_and_data_matches() {
    let bin = locate_rcroc_bin();
    let bin = bin.to_string_lossy().to_string();
    let relay_port = pick_free_port();
    let relay_addr = format!("127.0.0.1:{relay_port}");
    let relay_password = "pass";
    let secret = "1234-acorn-amber-anchor";

    let base = unique_temp_dir("rcroc-it-transfers");
    let send_dir = base.join("send");
    let recv_dir = base.join("recv");
    std::fs::create_dir_all(&send_dir).expect("create send dir");
    std::fs::create_dir_all(&recv_dir).expect("create recv dir");

    let source_file = send_dir.join("large.bin");
    let payload_len = 1024 * 1024 + 137;
    let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source_file, &payload).expect("write source file");

    let relay = spawn_rcroc(
        &bin,
        &[
            "relay",
            "--listen",
            &relay_addr,
            "--relay-password",
            relay_password,
        ],
    );
    let _relay_guard = ChildCleanup::new(relay);
    thread::sleep(Duration::from_millis(300));

    let recv_out = recv_dir.to_string_lossy().to_string();
    let mut receiver = spawn_rcroc(
        &bin,
        &[
            "receive",
            "--secret",
            secret,
            "--relay",
            &relay_addr,
            "--relay-password",
            relay_password,
            "--out",
            &recv_out,
            "--transfers",
            "2",
            "--resume",
        ],
    );
    thread::sleep(Duration::from_millis(400));

    let source_path = source_file.to_string_lossy().to_string();
    let mut sender = spawn_rcroc(
        &bin,
        &[
            "send",
            &source_path,
            "--secret",
            secret,
            "--relay",
            &relay_addr,
            "--relay-password",
            relay_password,
            "--transfers",
            "8",
        ],
    );

    let sender_status = wait_status_with_timeout(&mut sender, Duration::from_secs(40), "sender");
    assert!(sender_status.success(), "sender failed: {sender_status}");

    let receiver_status =
        wait_status_with_timeout(&mut receiver, Duration::from_secs(40), "receiver");
    assert!(receiver_status.success(), "receiver failed: {receiver_status}");

    let received_file = recv_dir.join("large.bin");
    assert!(received_file.exists(), "received file missing");

    let received = std::fs::read(&received_file).expect("read received file");
    assert_eq!(received, payload, "received file content mismatch");

    let _ = std::fs::remove_dir_all(base);
}
