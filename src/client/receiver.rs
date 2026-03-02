use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use indicatif::ProgressBar;
use tokio::{
    fs,
    io::{AsyncSeekExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
    time::{Duration, timeout},
};
use tracing::{info, warn};

use crate::{
    client::resume::ResumeState,
    discover,
    error::{RcrocError, Result},
    hash,
    models::{ChunkRange, FileRequest},
    net,
    protocol::{
        message::{
            EncryptedPacket, PlainMessage, recv_encrypted_packet, recv_plain_message,
            send_encrypted_packet, send_plain_message,
        },
        pake::{receiver_handshake, room_name_from_secret},
    },
    ui,
};

pub struct ReceiveConfig {
    pub secret: String,
    pub output_dir: PathBuf,
    pub relay_addr: String,
    pub relay_password: String,
    pub proxy: Option<String>,
    pub lan_discovery: bool,
    pub discover_timeout_secs: u64,
    pub resume: bool,
    pub max_transfers: usize,
}

struct ReceiveFileShared {
    file: Mutex<fs::File>,
    resume: Mutex<ResumeState>,
}

struct DataReceiverSpawn {
    relay_addr: String,
    relay_password: String,
    base_room: String,
    file_index: u32,
    transfers: usize,
    proxy: Option<String>,
    session_key: [u8; 32],
    shared: Arc<ReceiveFileShared>,
    progress: Option<Arc<ProgressBar>>,
}

struct DataRelayPath {
    connect_addr: String,
    proxy: Option<String>,
    request_addr: Option<String>,
}

pub async fn run_receive(cfg: ReceiveConfig) -> Result<()> {
    fs::create_dir_all(&cfg.output_dir).await?;

    let room = room_name_from_secret(&cfg.secret)?;
    let mut relay_candidates: Vec<(String, Option<String>)> = Vec::new();
    if cfg.lan_discovery
        && let Some(found) =
            discover::discover_relay(&room, Duration::from_secs(cfg.discover_timeout_secs)).await?
    {
        relay_candidates.push((found, None));
    }
    relay_candidates.push((cfg.relay_addr.clone(), cfg.proxy.clone()));
    dedup_relay_candidates(&mut relay_candidates);

    let mut connected = None;
    let mut last_err = None;
    for (addr, proxy) in relay_candidates {
        match connect_and_join(&addr, &cfg.relay_password, &room, proxy.as_deref()).await {
            Ok(stream) => {
                connected = Some((stream, addr));
                break;
            }
            Err(err) => {
                warn!(
                    "receiver failed to connect relay candidate {}: {}",
                    addr, err
                );
                last_err = Some(err);
            }
        }
    }

    let (mut control, relay_addr) = match connected {
        Some(v) => v,
        None => {
            return Err(last_err.unwrap_or_else(|| {
                RcrocError::Protocol("no reachable relay candidates".to_string())
            }));
        }
    };
    info!("receiver active relay path: {}", relay_addr);

    let session_key = receiver_handshake(&mut control, &cfg.secret).await?;

    let plan = match recv_encrypted_packet(&mut control, &session_key).await? {
        EncryptedPacket::Control(PlainMessage::TransferPlan(plan)) => plan,
        other => {
            return Err(RcrocError::UnexpectedMessage(format!(
                "expected TransferPlan, got {other:?}"
            )));
        }
    };

    if plan.chunk_size != crate::models::CHUNK_SIZE {
        return Err(RcrocError::Protocol(format!(
            "chunk size mismatch: sender={}, receiver={}",
            plan.chunk_size,
            crate::models::CHUNK_SIZE
        )));
    }
    let data_relay = select_data_relay_path(
        &relay_addr,
        cfg.proxy.clone(),
        &plan.sender_local_relay_addrs,
        cfg.lan_discovery,
    )
    .await;
    info!(
        "receiver data relay path: {}",
        data_relay
            .request_addr
            .as_deref()
            .unwrap_or(&data_relay.connect_addr)
    );

    for dir in &plan.empty_dirs {
        let safe = sanitize_relative_path(dir)?;
        let full = cfg.output_dir.join(safe);
        fs::create_dir_all(full).await?;
    }

    send_encrypted_packet(
        &mut control,
        &session_key,
        &EncryptedPacket::Control(PlainMessage::PlanAck),
    )
    .await?;

    let transfers = plan.transfers.max(1).min(cfg.max_transfers.max(1));

    for (index, file_meta) in plan.files.iter().enumerate() {
        let target_rel = sanitize_relative_path(&file_meta.relative_path)?;
        let target = cfg.output_dir.join(target_rel);

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut resume = ResumeState::load_or_init(&target, file_meta, cfg.resume).await?;
        let mut missing = resume.missing_ranges();
        if missing.is_empty() && target.exists() {
            let actual = hash::hash_file(target.clone(), plan.hash_algorithm).await?;
            if actual != file_meta.hash_hex {
                info!(
                    "file #{} hash mismatch on existing local file, forcing full retransfer: {}",
                    index, file_meta.relative_path
                );
                resume.reset_all();
                missing = resume.missing_ranges();
            }
        }
        info!(
            "file #{} {} size={} missing_ranges={} hash_algo={:?} transfers={}",
            index,
            file_meta.relative_path,
            file_meta.size,
            missing.len(),
            plan.hash_algorithm,
            transfers
        );

        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&target)
            .await?;
        file.set_len(file_meta.size).await?;

        let shared = Arc::new(ReceiveFileShared {
            file: Mutex::new(file),
            resume: Mutex::new(resume),
        });

        let progress = if missing.is_empty() {
            None
        } else {
            Some(Arc::new(ui::new_transfer_progress(
                format!("Receiving {}", file_meta.relative_path),
                missing_bytes(file_meta.size, &missing),
            )))
        };
        let workers = if missing.is_empty() {
            Vec::new()
        } else {
            spawn_data_receivers(DataReceiverSpawn {
                relay_addr: data_relay.connect_addr.clone(),
                relay_password: cfg.relay_password.clone(),
                base_room: room.clone(),
                file_index: index as u32,
                transfers,
                proxy: data_relay.proxy.clone(),
                session_key,
                shared: shared.clone(),
                progress: progress.clone(),
            })
            .await?
        };

        send_encrypted_packet(
            &mut control,
            &session_key,
            &EncryptedPacket::Control(PlainMessage::FileRequest(FileRequest {
                file_index: index as u32,
                missing_chunks: missing,
                transfers: Some(transfers),
                data_relay_addr: data_relay.request_addr.clone(),
            })),
        )
        .await?;

        match recv_encrypted_packet(&mut control, &session_key).await? {
            EncryptedPacket::Control(PlainMessage::FileDone { file_index })
                if file_index == index as u32 => {}
            other => {
                return Err(RcrocError::UnexpectedMessage(format!(
                    "expected FileDone for index {}, got {other:?}",
                    index
                )));
            }
        }

        for worker in workers {
            worker
                .await
                .map_err(|e| RcrocError::Protocol(format!("receiver worker join failed: {e}")))??;
        }
        if let Some(pb) = progress {
            pb.finish();
        }

        let actual_hash = hash::hash_file(target.clone(), plan.hash_algorithm).await?;
        let mut resume = shared.resume.lock().await;
        if actual_hash != file_meta.hash_hex {
            resume.reset_all();
            resume.persist().await?;
            return Err(RcrocError::Protocol(format!(
                "file hash mismatch after transfer: {} expected={} actual={}",
                file_meta.relative_path, file_meta.hash_hex, actual_hash
            )));
        }

        if resume.is_complete() {
            resume.complete_and_cleanup().await?;
        } else {
            resume.persist().await?;
        }

        info!("received/updated file #{} {}", index, target.display());
    }

    match recv_encrypted_packet(&mut control, &session_key).await? {
        EncryptedPacket::Control(PlainMessage::Finished) => {}
        other => {
            return Err(RcrocError::UnexpectedMessage(format!(
                "expected Finished, got {other:?}"
            )));
        }
    }

    send_encrypted_packet(
        &mut control,
        &session_key,
        &EncryptedPacket::Control(PlainMessage::Finished),
    )
    .await?;

    Ok(())
}

async fn spawn_data_receivers(
    params: DataReceiverSpawn,
) -> Result<Vec<tokio::task::JoinHandle<Result<()>>>> {
    let mut out = Vec::with_capacity(params.transfers);

    for worker_index in 0..params.transfers {
        let relay_addr = params.relay_addr.clone();
        let relay_password = params.relay_password.clone();
        let room = data_room(&params.base_room, params.file_index, worker_index);
        let proxy = params.proxy.clone();
        let shared = params.shared.clone();
        let session_key = params.session_key;
        let file_index = params.file_index;
        let progress = params.progress.clone();

        let h = tokio::spawn(async move {
            let mut stream =
                connect_and_join(&relay_addr, &relay_password, &room, proxy.as_deref()).await?;

            loop {
                let packet = match recv_encrypted_packet(&mut stream, &session_key).await {
                    Ok(v) => v,
                    Err(err) if is_stream_closed(&err) => break,
                    Err(err) => return Err(err),
                };

                match packet {
                    EncryptedPacket::Data {
                        file_index: incoming,
                        position,
                        data,
                        ..
                    } => {
                        if incoming != file_index {
                            return Err(RcrocError::Protocol(format!(
                                "data file index mismatch: got {incoming}, expected {file_index}"
                            )));
                        }
                        write_chunk(&shared, position, &data, progress.as_deref()).await?;
                    }
                    EncryptedPacket::Control(PlainMessage::Error { message }) => {
                        return Err(RcrocError::Protocol(message));
                    }
                    other => {
                        return Err(RcrocError::UnexpectedMessage(format!(
                            "unexpected data packet: {other:?}"
                        )));
                    }
                }
            }

            Ok(())
        });

        out.push(h);
    }

    Ok(out)
}

async fn write_chunk(
    shared: &Arc<ReceiveFileShared>,
    position: u64,
    data: &[u8],
    progress: Option<&ProgressBar>,
) -> Result<()> {
    {
        let mut file = shared.file.lock().await;
        file.seek(std::io::SeekFrom::Start(position)).await?;
        file.write_all(data).await?;
    }

    let chunk_index = (position / crate::models::CHUNK_SIZE as u64) as usize;
    let mut resume = shared.resume.lock().await;
    resume.mark_chunk(chunk_index).await?;
    if let Some(pb) = progress {
        pb.inc(data.len() as u64);
    }
    Ok(())
}

fn missing_bytes(size: u64, ranges: &[ChunkRange]) -> u64 {
    let mut total = 0u64;
    for range in ranges {
        for chunk in range.start..range.end {
            let pos = chunk * crate::models::CHUNK_SIZE as u64;
            if pos >= size {
                continue;
            }
            let remain = size - pos;
            total += remain.min(crate::models::CHUNK_SIZE as u64);
        }
    }
    total
}

fn sanitize_relative_path(path: &str) -> Result<PathBuf> {
    let src = Path::new(path);
    if src.is_absolute() {
        return Err(RcrocError::InvalidPath(format!(
            "absolute path not allowed: {path}"
        )));
    }

    let mut safe = PathBuf::new();
    for component in src.components() {
        match component {
            Component::Normal(v) => {
                let text = v.to_str().ok_or_else(|| {
                    RcrocError::InvalidPath(format!("invalid UTF-8 path: {path}"))
                })?;
                if text.contains(".ssh") || text.chars().any(|c| c.is_control()) {
                    return Err(RcrocError::InvalidPath(format!(
                        "unsafe path component: {text}"
                    )));
                }
                safe.push(text);
            }
            Component::CurDir => {}
            _ => {
                return Err(RcrocError::InvalidPath(format!(
                    "unsafe path component in {path}"
                )));
            }
        }
    }

    if safe.as_os_str().is_empty() {
        return Err(RcrocError::InvalidPath("empty relative path".to_string()));
    }

    Ok(safe)
}

fn is_stream_closed(err: &RcrocError) -> bool {
    match err {
        RcrocError::Io(ioe) => matches!(
            ioe.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
        ),
        _ => false,
    }
}

fn dedup_relay_candidates(candidates: &mut Vec<(String, Option<String>)>) {
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|v| seen.insert((v.0.clone(), v.1.clone())));
}

async fn select_data_relay_path(
    control_relay_addr: &str,
    control_proxy: Option<String>,
    sender_local_relay_addrs: &[String],
    lan_discovery: bool,
) -> DataRelayPath {
    if !lan_discovery || sender_local_relay_addrs.is_empty() {
        return DataRelayPath {
            connect_addr: control_relay_addr.to_string(),
            proxy: control_proxy,
            request_addr: None,
        };
    }

    for addr in sender_local_relay_addrs {
        if addr == control_relay_addr {
            continue;
        }

        if is_direct_relay_reachable(addr).await {
            return DataRelayPath {
                connect_addr: addr.clone(),
                proxy: None,
                request_addr: Some(addr.clone()),
            };
        }
    }

    DataRelayPath {
        connect_addr: control_relay_addr.to_string(),
        proxy: control_proxy,
        request_addr: None,
    }
}

async fn is_direct_relay_reachable(addr: &str) -> bool {
    matches!(
        timeout(Duration::from_millis(500), net::connect_target(addr, None)).await,
        Ok(Ok(_))
    )
}

async fn connect_and_join(
    relay_addr: &str,
    relay_password: &str,
    room: &str,
    proxy: Option<&str>,
) -> Result<TcpStream> {
    let mut stream = net::connect_target(relay_addr, proxy).await?;

    send_plain_message(
        &mut stream,
        &PlainMessage::JoinRoom {
            room: room.to_string(),
            relay_password: relay_password.to_string(),
        },
    )
    .await?;

    wait_for_room_ready(&mut stream).await?;
    Ok(stream)
}

async fn wait_for_room_ready(stream: &mut TcpStream) -> Result<()> {
    loop {
        match recv_plain_message(stream).await? {
            PlainMessage::JoinWaiting => {}
            PlainMessage::JoinOk => return Ok(()),
            PlainMessage::JoinError { message } => return Err(RcrocError::Protocol(message)),
            other => {
                return Err(RcrocError::UnexpectedMessage(format!(
                    "unexpected room response: {other:?}"
                )));
            }
        }
    }
}

fn data_room(base_room: &str, file_index: u32, worker_index: usize) -> String {
    format!("{base_room}-f{file_index}-t{worker_index}")
}
