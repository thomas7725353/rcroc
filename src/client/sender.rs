use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use globset::{Glob, GlobMatcher};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tracing::{info, warn};
use walkdir::WalkDir;

use crate::{
    discover,
    error::{RcrocError, Result},
    hash,
    models::{ChunkRange, FileMeta, HashAlgorithm, TransferPlan},
    net,
    protocol::{
        message::{
            EncryptedPacket, PlainMessage, recv_encrypted_packet, recv_plain_message,
            send_encrypted_packet, send_plain_message,
        },
        pake::{room_name_from_secret, sender_handshake},
    },
    relay,
};

pub struct SendConfig {
    pub paths: Vec<PathBuf>,
    pub secret: String,
    pub relay_addr: String,
    pub relay_password: String,
    pub no_compress: bool,
    pub transfers: usize,
    pub proxy: Option<String>,
    pub lan_discovery: bool,
    pub hash_algorithm: HashAlgorithm,
}

struct SenderFile {
    meta: FileMeta,
    source_path: PathBuf,
}

#[derive(Clone)]
struct ChunkJob {
    position: u64,
    length: usize,
}

#[derive(Clone)]
struct RelayCandidate {
    addr: String,
    proxy: Option<String>,
}

struct LocalRelayInfo {
    connect_addr: String,
    advertise_addr: String,
    _task: tokio::task::JoinHandle<()>,
}

struct TransferDispatch {
    relay: RelayCandidate,
    relay_password: String,
    base_room: String,
    file_index: u32,
    source_path: PathBuf,
    transfers: usize,
    session_key: [u8; 32],
    compress: bool,
}

pub async fn run_send(cfg: SendConfig) -> Result<()> {
    let transfers = cfg.transfers.max(1);
    let (plan, sender_files) =
        collect_transfer_plan(&cfg.paths, cfg.no_compress, transfers, cfg.hash_algorithm)?;
    if plan.files.is_empty() && plan.empty_dirs.is_empty() {
        return Err(RcrocError::InvalidPath(
            "no files or directories to send".to_string(),
        ));
    }

    let room = room_name_from_secret(&cfg.secret)?;

    let local_relay = if cfg.lan_discovery {
        match start_local_relay(&cfg.relay_password).await {
            Ok(v) => Some(v),
            Err(err) => {
                warn!("failed to start local relay for direct upgrade: {err}");
                None
            }
        }
    } else {
        None
    };

    let mut discovery_task = None;
    if cfg.lan_discovery {
        let advertise_addr = local_relay
            .as_ref()
            .map(|v| v.advertise_addr.clone())
            .unwrap_or_else(|| net::normalize_advertise_addr(&cfg.relay_addr));
        let (tx, handle) = discover::spawn_advertiser(room.clone(), advertise_addr);
        discovery_task = Some((tx, handle));
    }

    let mut relay_candidates = Vec::new();
    if let Some(local) = &local_relay {
        relay_candidates.push(RelayCandidate {
            addr: local.connect_addr.clone(),
            proxy: None,
        });
    }
    relay_candidates.push(RelayCandidate {
        addr: cfg.relay_addr.clone(),
        proxy: cfg.proxy.clone(),
    });

    dedup_candidates(&mut relay_candidates);

    let (mut control, active_relay) =
        connect_and_join_any(relay_candidates, &cfg.relay_password, &room).await?;
    info!("sender active relay path: {}", active_relay.addr);

    let session_key = sender_handshake(&mut control, &cfg.secret).await?;

    send_encrypted_packet(
        &mut control,
        &session_key,
        &EncryptedPacket::Control(PlainMessage::TransferPlan(plan.clone())),
    )
    .await?;

    match recv_encrypted_packet(&mut control, &session_key).await? {
        EncryptedPacket::Control(PlainMessage::PlanAck) => {}
        other => {
            return Err(RcrocError::UnexpectedMessage(format!(
                "expected PlanAck, got {other:?}"
            )));
        }
    }

    for (index, sender_file) in sender_files.iter().enumerate() {
        let request = match recv_encrypted_packet(&mut control, &session_key).await? {
            EncryptedPacket::Control(PlainMessage::FileRequest(req)) => req,
            other => {
                return Err(RcrocError::UnexpectedMessage(format!(
                    "expected FileRequest, got {other:?}"
                )));
            }
        };

        if request.file_index as usize != index {
            return Err(RcrocError::Protocol(format!(
                "file request index mismatch: got {}, expected {}",
                request.file_index, index
            )));
        }

        let negotiated_transfers = request.transfers.unwrap_or(transfers).max(1).min(transfers);
        let jobs = build_chunk_jobs(sender_file.meta.size, &request.missing_chunks)?;

        if jobs.is_empty() {
            info!(
                "file #{} already complete on receiver: {}",
                index, sender_file.meta.relative_path
            );
        } else {
            info!(
                "sending file #{} {} with {} chunk job(s) over {} transfer worker(s)",
                index,
                sender_file.meta.relative_path,
                jobs.len(),
                negotiated_transfers
            );
            let dispatch = TransferDispatch {
                relay: active_relay.clone(),
                relay_password: cfg.relay_password.clone(),
                base_room: room.clone(),
                file_index: request.file_index,
                source_path: sender_file.source_path.clone(),
                transfers: negotiated_transfers,
                session_key,
                compress: !cfg.no_compress,
            };
            transfer_file_chunks(dispatch, jobs).await?;
        }

        send_encrypted_packet(
            &mut control,
            &session_key,
            &EncryptedPacket::Control(PlainMessage::FileDone {
                file_index: request.file_index,
            }),
        )
        .await?;
    }

    send_encrypted_packet(
        &mut control,
        &session_key,
        &EncryptedPacket::Control(PlainMessage::Finished),
    )
    .await?;

    match recv_encrypted_packet(&mut control, &session_key).await? {
        EncryptedPacket::Control(PlainMessage::Finished) => {
            info!("transfer finished for {} file(s)", sender_files.len());
        }
        other => {
            return Err(RcrocError::UnexpectedMessage(format!(
                "expected Finished ack, got {other:?}"
            )));
        }
    }

    if let Some((tx, handle)) = discovery_task {
        let _ = tx.send(true);
        let _ = handle.await;
    }

    Ok(())
}

async fn transfer_file_chunks(dispatch: TransferDispatch, jobs: Vec<ChunkJob>) -> Result<()> {
    if jobs.is_empty() {
        return Ok(());
    }

    let mut per_worker = vec![Vec::<ChunkJob>::new(); dispatch.transfers];
    for (i, job) in jobs.into_iter().enumerate() {
        per_worker[i % dispatch.transfers].push(job);
    }

    let mut handles = Vec::with_capacity(dispatch.transfers);
    for (worker_index, worker_jobs) in per_worker.into_iter().enumerate() {
        let relay_addr = dispatch.relay.addr.clone();
        let relay_password = dispatch.relay_password.clone();
        let proxy = dispatch.relay.proxy.clone();
        let source_path = dispatch.source_path.clone();
        let worker_room = data_room(&dispatch.base_room, dispatch.file_index, worker_index);
        let key = dispatch.session_key;
        let use_compress = dispatch.compress;
        let file_index = dispatch.file_index;

        let handle = tokio::spawn(async move {
            let mut stream =
                connect_and_join(&relay_addr, &relay_password, &worker_room, proxy.as_deref())
                    .await?;

            let mut file = fs::File::open(&source_path).await?;
            for job in worker_jobs {
                file.seek(std::io::SeekFrom::Start(job.position)).await?;
                let mut buf = vec![0u8; job.length];
                file.read_exact(&mut buf).await?;

                send_encrypted_packet(
                    &mut stream,
                    &key,
                    &EncryptedPacket::Data {
                        file_index,
                        position: job.position,
                        data: buf,
                        compressed: use_compress,
                    },
                )
                .await?;
            }

            Ok::<(), RcrocError>(())
        });

        handles.push(handle);
    }

    for h in handles {
        h.await
            .map_err(|e| RcrocError::Protocol(format!("sender worker join failed: {e}")))??;
    }

    Ok(())
}

fn build_chunk_jobs(size: u64, ranges: &[ChunkRange]) -> Result<Vec<ChunkJob>> {
    let mut out = Vec::new();

    for range in ranges {
        if range.end < range.start {
            return Err(RcrocError::Protocol(format!(
                "invalid chunk range {}..{}",
                range.start, range.end
            )));
        }

        for chunk in range.start..range.end {
            let pos = chunk * crate::models::CHUNK_SIZE as u64;
            if pos >= size {
                continue;
            }

            let remain = size - pos;
            let len = remain.min(crate::models::CHUNK_SIZE as u64) as usize;
            out.push(ChunkJob {
                position: pos,
                length: len,
            });
        }
    }

    Ok(out)
}

fn collect_transfer_plan(
    paths: &[PathBuf],
    no_compress: bool,
    transfers: usize,
    hash_algorithm: HashAlgorithm,
) -> Result<(TransferPlan, Vec<SenderFile>)> {
    let mut files = Vec::new();
    let mut empty_dirs = Vec::new();
    let mut seen_paths = HashSet::new();

    for path in paths {
        if !path.exists() {
            return Err(RcrocError::InvalidPath(format!(
                "path not found: {}",
                path.display()
            )));
        }

        let root_name = path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| RcrocError::InvalidPath(format!("invalid path: {}", path.display())))?
            .to_string();

        if path.is_file() {
            let meta = file_meta(path, root_name.clone(), hash_algorithm)?;
            if !seen_paths.insert(meta.relative_path.clone()) {
                return Err(RcrocError::InvalidPath(format!(
                    "duplicate relative path: {}",
                    meta.relative_path
                )));
            }
            files.push(SenderFile {
                meta,
                source_path: path.to_path_buf(),
            });
            continue;
        }

        collect_directory_with_gitignore(
            path,
            &root_name,
            hash_algorithm,
            &mut seen_paths,
            &mut files,
            &mut empty_dirs,
        )?;
    }

    files.sort_by(|a, b| a.meta.relative_path.cmp(&b.meta.relative_path));
    empty_dirs.sort();

    let plan = TransferPlan {
        files: files.iter().map(|v| v.meta.clone()).collect(),
        empty_dirs,
        chunk_size: crate::models::CHUNK_SIZE,
        transfers,
        no_compress,
        hash_algorithm,
    };

    Ok((plan, files))
}

fn file_meta(
    path: &Path,
    relative_path: String,
    hash_algorithm: HashAlgorithm,
) -> Result<FileMeta> {
    let md = std::fs::metadata(path)?;
    let mod_time_unix = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|v| v.as_secs() as i64)
        .unwrap_or(0);

    Ok(FileMeta {
        relative_path,
        size: md.len(),
        mod_time_unix,
        hash_hex: hash::hash_file_blocking(path, hash_algorithm)?,
    })
}

fn collect_directory_with_gitignore(
    root_path: &Path,
    root_name: &str,
    hash_algorithm: HashAlgorithm,
    seen_paths: &mut HashSet<String>,
    files: &mut Vec<SenderFile>,
    empty_dirs: &mut Vec<String>,
) -> Result<()> {
    let gitignore = build_gitignore_matcher(root_path)?;

    let mut dirs: Vec<(PathBuf, String)> = Vec::new();
    let mut file_paths: Vec<PathBuf> = Vec::new();

    let walker = WalkDir::new(root_path)
        .into_iter()
        .filter_entry(|e| e.file_name() != OsStr::new(".git"));

    for entry in walker {
        let entry = entry.map_err(|e| RcrocError::InvalidPath(format!("walkdir error: {e}")))?;
        let current = entry.path();
        let is_dir = entry.file_type().is_dir();

        if current != root_path {
            let rel_for_match = current.strip_prefix(root_path).unwrap_or(current);
            if is_path_ignored_by_gitignore(&gitignore, rel_for_match, is_dir) {
                continue;
            }
        }

        let rel = if current == root_path {
            root_name.to_string()
        } else {
            let rest = current
                .strip_prefix(root_path)
                .map_err(|e| RcrocError::InvalidPath(format!("strip prefix failed: {e}")))?;
            let rest = to_slash_path(rest)?;
            format!("{root_name}/{rest}")
        };

        if is_dir {
            dirs.push((current.to_path_buf(), rel));
            continue;
        }

        if entry.file_type().is_file() {
            let meta = file_meta(current, rel, hash_algorithm)?;
            if !seen_paths.insert(meta.relative_path.clone()) {
                return Err(RcrocError::InvalidPath(format!(
                    "duplicate relative path: {}",
                    meta.relative_path
                )));
            }
            files.push(SenderFile {
                meta,
                source_path: current.to_path_buf(),
            });
            file_paths.push(current.to_path_buf());
        }
    }

    for (i, (dir_abs, rel)) in dirs.iter().enumerate() {
        let has_file_under = file_paths.iter().any(|p| p.starts_with(dir_abs));
        let has_child_dir = dirs
            .iter()
            .enumerate()
            .any(|(j, (other_dir, _))| i != j && other_dir.starts_with(dir_abs));

        if !has_file_under && !has_child_dir && seen_paths.insert(rel.clone()) {
            empty_dirs.push(rel.clone());
        }
    }

    Ok(())
}

#[derive(Clone)]
struct GitignoreRule {
    negated: bool,
    matcher: GlobMatcher,
}

fn build_gitignore_matcher(root_path: &Path) -> Result<Vec<GitignoreRule>> {
    let mut rules = Vec::new();

    let walker = WalkDir::new(root_path)
        .into_iter()
        .filter_entry(|e| e.file_name() != OsStr::new(".git"));

    for entry in walker {
        let entry = entry.map_err(|e| RcrocError::InvalidPath(format!("walkdir error: {e}")))?;
        if !entry.file_type().is_file() || entry.file_name() != OsStr::new(".gitignore") {
            continue;
        }

        let ignore_file = entry.path();
        let base_dir = ignore_file
            .parent()
            .ok_or_else(|| RcrocError::InvalidPath("invalid .gitignore parent".to_string()))?;
        let base_rel = base_dir
            .strip_prefix(root_path)
            .map_err(|e| RcrocError::InvalidPath(format!("strip prefix failed: {e}")))?;
        let base_rel = to_slash_path(base_rel)?;

        let file = File::open(ignore_file)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let raw = line?;
            rules.extend(parse_gitignore_rule_line(&raw, &base_rel)?);
        }
    }

    Ok(rules)
}

fn parse_gitignore_rule_line(raw: &str, base_rel: &str) -> Result<Vec<GitignoreRule>> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(Vec::new());
    }

    let (negated, mut pat) = if let Some(stripped) = line.strip_prefix('!') {
        (true, stripped.trim())
    } else {
        (false, line)
    };

    if pat.is_empty() {
        return Ok(Vec::new());
    }

    let directory_only = pat.ends_with('/');
    if directory_only {
        pat = pat.trim_end_matches('/');
    }
    pat = pat.trim_start_matches('/');
    if pat.is_empty() {
        return Ok(Vec::new());
    }

    let pat = pat.replace('\\', "/");
    let contains_slash = pat.contains('/');
    let mut patterns = Vec::new();

    if contains_slash {
        if base_rel.is_empty() {
            patterns.push(pat.clone());
        } else {
            patterns.push(format!("{base_rel}/{pat}"));
        }
    } else if base_rel.is_empty() {
        patterns.push(pat.clone());
        patterns.push(format!("**/{pat}"));
    } else {
        patterns.push(format!("{base_rel}/{pat}"));
        patterns.push(format!("{base_rel}/**/{pat}"));
    }

    if directory_only {
        let mut dir_patterns = Vec::new();
        for p in patterns {
            dir_patterns.push(p.clone());
            dir_patterns.push(format!("{p}/**"));
        }
        patterns = dir_patterns;
    }

    let mut rules = Vec::new();
    for p in patterns {
        let matcher = Glob::new(&p)
            .map_err(|e| RcrocError::InvalidPath(format!("invalid gitignore glob '{p}': {e}")))?
            .compile_matcher();
        rules.push(GitignoreRule { negated, matcher });
    }

    Ok(rules)
}

fn is_path_ignored_by_gitignore(rules: &[GitignoreRule], rel_path: &Path, _is_dir: bool) -> bool {
    let path = match to_slash_path(rel_path) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let mut ignored = false;
    for rule in rules {
        if rule.matcher.is_match(&path) {
            ignored = !rule.negated;
        }
    }
    ignored
}

fn to_slash_path(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| RcrocError::InvalidPath("invalid UTF-8 path".to_string()))?;
    Ok(text.replace('\\', "/"))
}

async fn start_local_relay(relay_password: &str) -> Result<LocalRelayInfo> {
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let port = listener.local_addr()?.port();
    let connect_addr = format!("127.0.0.1:{port}");
    let advertise_ip = net::local_ipv4_for_advertise().unwrap_or_else(|| "127.0.0.1".to_string());
    let advertise_addr = format!("{advertise_ip}:{port}");
    let relay_password = relay_password.to_string();

    let task = tokio::spawn(async move {
        if let Err(err) = relay::run_relay_on_listener(listener, &relay_password).await {
            warn!("local relay task exited with error: {err}");
        }
    });

    info!("local relay started for direct upgrade: {advertise_addr}");
    Ok(LocalRelayInfo {
        connect_addr,
        advertise_addr,
        _task: task,
    })
}

fn dedup_candidates(candidates: &mut Vec<RelayCandidate>) {
    let mut seen = HashSet::new();
    candidates.retain(|v| seen.insert((v.addr.clone(), v.proxy.clone())));
}

async fn connect_and_join_any(
    candidates: Vec<RelayCandidate>,
    relay_password: &str,
    room: &str,
) -> Result<(TcpStream, RelayCandidate)> {
    if candidates.is_empty() {
        return Err(RcrocError::Protocol("no relay candidates".to_string()));
    }

    if candidates.len() == 1 {
        let c = candidates[0].clone();
        let stream = connect_and_join(&c.addr, relay_password, room, c.proxy.as_deref()).await?;
        return Ok((stream, c));
    }

    let (tx, mut rx) = mpsc::channel::<(RelayCandidate, Result<TcpStream>)>(candidates.len());
    let mut handles = Vec::new();

    for candidate in candidates {
        let tx = tx.clone();
        let room = room.to_string();
        let relay_password = relay_password.to_string();
        let candidate_clone = candidate.clone();
        let handle = tokio::spawn(async move {
            let result = connect_and_join(
                &candidate_clone.addr,
                &relay_password,
                &room,
                candidate_clone.proxy.as_deref(),
            )
            .await;
            let _ = tx.send((candidate_clone, result)).await;
        });
        handles.push(handle);
    }
    drop(tx);

    let mut errors = Vec::new();
    while let Some((candidate, result)) = rx.recv().await {
        match result {
            Ok(stream) => {
                for h in handles {
                    h.abort();
                }
                return Ok((stream, candidate));
            }
            Err(err) => {
                errors.push(format!("{} via {}", err, candidate.addr));
            }
        }
    }

    Err(RcrocError::Protocol(format!(
        "all relay candidates failed: {}",
        errors.join("; ")
    )))
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
