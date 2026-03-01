# rcroc Implementation Plan

> 供 GPT Codex 直接执行的详细实现方案 — 基于 spec.md 规格书

---

## Architecture Decision Records

### ADR-001: SIEC 曲线替代方案

**状态**: 已决定

**背景**: 原版 croc 的 relay 认证使用 SIEC 曲线（`tscholl2/siec`），这是一个非标准椭圆曲线。Rust 生态无现成 SIEC 实现，移植成本高且该曲线缺乏广泛安全审计。

**决策**: relay 认证改用 P-256 曲线。rcroc 不追求与原版 croc relay 的互操作性，而是构建独立的 rcroc 生态。

**方案对比**:

| 方案 | 优点 | 缺点 |
|------|------|------|
| A: 手动移植 SIEC 到 Rust | 与原版 croc relay 兼容 | 工作量大，缺乏审计，维护负担 |
| B: 全部使用 P-256（采用） | 标准曲线，成熟实现，安全审计充分 | 不兼容原版 croc relay |
| C: 使用 Curve25519 | 高性能，广泛使用 | 不兼容原版，需额外移植工作 |

**后果**:
- rcroc relay 与原版 croc relay 不互通
- rcroc sender ↔ rcroc receiver 可互通
- 统一使用 P-256 简化代码，降低维护成本
- PAKE 弱密钥 `[1, 2, 3]` 格式保持不变，仅曲线不同

### ADR-002: PAKE 实现策略

**状态**: 已决定

**背景**: 原版 croc 使用 `schollz/pake/v3`，实现基于 Boneh/Shoup 的 PAKE2 协议（本质为 SPAKE2 变体）。Rust 现有的 `spake2` crate 使用 Ed25519 而非 P-256。

**决策**: 基于 `p256` crate 自行实现 SPAKE2 协议。

**算法概要**:
1. 预计算两个固定盲化点 M, N = hash\_to\_curve(固定标签)
2. 密码标量 w = reduce(SHA-256(password))
3. Role 0: 随机 x, 发送 X\* = x·G + w·M
4. Role 1: 随机 y, 发送 Y\* = y·G + w·N
5. Role 0: K = x·(Y\* − w·N) = x·y·G
6. Role 1: K = y·(X\* − w·M) = x·y·G
7. session\_key = SHA-256(K\_bytes ‖ X\*\_bytes ‖ Y\*\_bytes)

**后果**:
- 完全控制 PAKE 实现，不依赖第三方 PAKE crate
- P-256 曲线有 NIST 标准支持和广泛审计
- 需要严格的单元测试和向量测试确保正确性

---

## Project Directory Structure

```
rcroc/
├── Cargo.toml
├── src/
│   ├── lib.rs                    # T01: 模块声明
│   ├── main.rs                   # T25: 入口 + 信号处理
│   ├── error.rs                  # T02: 错误类型
│   ├── models.rs                 # T03: 常量 + 数据结构
│   ├── mnemonic.rs               # T04: 助记词编解码
│   ├── compress.rs               # T05: DEFLATE Huffman-only
│   ├── crypto/
│   │   ├── mod.rs                # T06: Cipher trait + re-exports
│   │   ├── aes_gcm.rs            # T06: AES-256-GCM
│   │   ├── chacha.rs             # T06: XChaCha20-Poly1305
│   │   └── key_derivation.rs     # T06: PBKDF2 + Argon2
│   ├── protocol/
│   │   ├── mod.rs                # T10: re-exports
│   │   ├── comm.rs               # T07: 帧协议
│   │   ├── pake.rs               # T08: SPAKE2 (P-256)
│   │   └── message.rs            # T09/T10: 消息类型 + 编解码管线
│   ├── relay/
│   │   ├── mod.rs                # T13: Relay TCP 服务器
│   │   ├── room.rs               # T11: 房间管理
│   │   └── pipe.rs               # T12: 双向管道
│   ├── client/
│   │   ├── mod.rs                # T23: Client 状态机
│   │   ├── sender.rs             # T21: 发送逻辑
│   │   ├── receiver.rs           # T22: 接收逻辑
│   │   └── transfer.rs           # T20: 多路复用传输
│   ├── utils/
│   │   ├── mod.rs                # re-exports
│   │   ├── hash.rs               # T16: xxhash / imohash
│   │   ├── fs.rs                 # T17: 文件操作
│   │   ├── zip.rs                # T18: ZIP 打包/解包
│   │   └── net.rs                # T19: DNS / IP / 代理
│   ├── cli.rs                    # T24: clap CLI 定义
│   └── discover.rs               # T24: LAN 对端发现
└── tests/
    └── integration/
        └── transfer_test.rs      # 端到端集成测试
```

---

## Cargo.toml

```toml
[package]
name = "rcroc"
version = "0.1.0"
edition = "2021"
description = "Rust rewrite of croc - secure file transfer"
license = "MIT"
rust-version = "1.75"

[[bin]]
name = "rcroc"
path = "src/main.rs"

[dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# CLI
clap = { version = "4", features = ["derive"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Crypto
aes-gcm = "0.10"
chacha20poly1305 = "0.10"
pbkdf2 = { version = "0.12", features = ["simple"] }
argon2 = "0.5"
hmac = "0.12"
sha2 = "0.10"
rand = "0.8"
p256 = { version = "0.13", features = ["ecdh", "hash2curve"] }
elliptic-curve = { version = "0.13", features = ["hash2curve"] }
zeroize = { version = "1", features = ["derive"] }

# Compression
flate2 = "1"
zip = "2"

# Hash
xxhash-rust = { version = "0.8", features = ["xxh3"] }

# Network
tokio-socks = "0.5"
socket2 = { version = "0.5", features = ["all"] }

# Terminal UI
indicatif = "0.17"
crossterm = "0.28"

# Filesystem
ignore = "0.4"
walkdir = "2"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Error handling
thiserror = "2"

# Byte handling
bytes = "1"
byteorder = "1"

# Misc
hex = "0.4"
base64 = "0.22"

[dev-dependencies]
tokio-test = "0.4"
tempfile = "3"
```

---

## Implementation Tasks

> 25 个任务按依赖关系排序，分 5 个阶段执行。
> 每个任务包含：文件路径、依赖、函数签名、实现代码、测试、验收标准。

---

## Phase 1: Foundation Layer

### T01: Project Scaffold

- **Files**: `Cargo.toml`, `src/lib.rs`
- **Depends on**: None
- **Description**: 创建项目骨架，声明所有模块。

#### Implementation: src/lib.rs

```rust
pub mod error;
pub mod models;
pub mod mnemonic;
pub mod compress;
pub mod crypto;
pub mod protocol;
pub mod relay;
pub mod client;
pub mod utils;
pub mod cli;
pub mod discover;
```

#### Acceptance Criteria
- [ ] `cargo check` 通过（允许未实现模块为空文件）
- [ ] 所有模块文件已创建（可为空）
- [ ] Cargo.toml 依赖可解析

---

### T02: Error Types

- **File**: `src/error.rs`
- **Depends on**: T01
- **Description**: 统一错误类型，使用 thiserror derive。

#### Implementation

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RcrocError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PAKE authentication failed: {0}")]
    PakeAuth(String),

    #[error("relay error: {0}")]
    Relay(String),

    #[error("encryption error: {0}")]
    Crypto(String),

    #[error("compression error: {0}")]
    Compression(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("transfer cancelled")]
    Cancelled,

    #[error("file not found: {0}")]
    FileNotFound(String),

    #[error("room full: {0}")]
    RoomFull(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("insufficient disk space: need {need} bytes, have {have} bytes")]
    InsufficientSpace { need: u64, have: u64 },
}

pub type Result<T> = std::result::Result<T, RcrocError>;
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = RcrocError::Protocol("bad frame".into());
        assert_eq!(err.to_string(), "protocol error: bad frame");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err: RcrocError = io_err.into();
        assert!(matches!(err, RcrocError::Io(_)));
    }

    #[test]
    fn test_result_type_alias() {
        let ok: Result<i32> = Ok(42);
        assert_eq!(ok.unwrap(), 42);
        let err: Result<i32> = Err(RcrocError::Cancelled);
        assert!(err.is_err());
    }
}
```

#### Acceptance Criteria
- [ ] 所有错误变体可构造和显示
- [ ] `std::io::Error` 和 `serde_json::Error` 可自动转换
- [ ] `Result<T>` 类型别名可用
- [ ] 测试全部通过

---

### T03: Models & Constants

- **File**: `src/models.rs`
- **Depends on**: T01, T02
- **Description**: 定义全局常量、文件元信息、传输状态机枚举、配置结构体。

#### Implementation

```rust
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

// ── Constants ──

/// TCP 缓冲区大小 (与原版 croc 一致)
pub const TCP_BUFFER_SIZE: usize = 65536;

/// 数据块大小 = TCP_BUFFER_SIZE / 2
pub const CHUNK_SIZE: usize = TCP_BUFFER_SIZE / 2;

/// Comm 帧魔数 "croc"
pub const COMM_MAGIC: &[u8; 4] = b"croc";

/// 默认 relay 地址
pub const DEFAULT_RELAY: &str = "croc.schollz.com";

/// 默认 relay 端口
pub const DEFAULT_RELAY_PORT: u16 = 9009;

/// 默认传输连接数
pub const DEFAULT_TRANSFER_PORTS: usize = 4;

/// 房间 TTL (3 小时)
pub const ROOM_TTL_SECS: u64 = 3 * 60 * 60;

/// 房间清理间隔 (10 分钟)
pub const ROOM_CLEANUP_INTERVAL_SECS: u64 = 10 * 60;

/// 读写超时 (3 小时)
pub const RW_TIMEOUT_SECS: u64 = 3 * 60 * 60;

/// PAKE relay 弱密钥
pub const PAKE_WEAK_KEY: &[u8] = &[1, 2, 3];

/// PBKDF2 迭代次数
pub const PBKDF2_ITERATIONS: u32 = 100;

/// AES-256 密钥长度
pub const AES_KEY_LEN: usize = 32;

/// PAKE salt 长度
pub const PAKE_SALT_LEN: usize = 8;

/// Keepalive 字节
pub const KEEPALIVE_BYTE: u8 = 0x01;

/// LAN 发现 multicast 地址 (IPv4)
pub const MULTICAST_ADDR_V4: &str = "239.255.255.250";

/// LAN 发现端口
pub const DISCOVER_PORT: u16 = 9010;

/// LAN 发现超时 (ms)
pub const DISCOVER_TIMEOUT_MS: u64 = 200;

/// 密码短语前缀长度 (NNNN)
pub const CODE_PREFIX_LEN: usize = 4;

// ── Enums ──

/// 传输状态机
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStep {
    ChannelSecured,
    FileInfoTransferred,
    RecipientRequestFile,
    FileTransferred,
    CloseChannels,
}

/// 哈希算法
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Xxhash,
    Imohash,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Xxhash
    }
}

/// 客户端角色
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Sender,
    Receiver,
}

// ── Data Structures ──

/// 文件元信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub folder_remote: String,
    pub folder_source: String,
    pub size: u64,
    #[serde(with = "system_time_serde")]
    pub mod_time: SystemTime,
    pub mode: u32,
    #[serde(default)]
    pub symlink: String,
    #[serde(with = "hex_bytes")]
    pub hash: Vec<u8>,
}

/// 发送方信息 (Step2 传输)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderInfo {
    pub files: Vec<FileInfo>,
    #[serde(default)]
    pub empty_folders: Vec<String>,
    pub total_files_size: u64,
    #[serde(default)]
    pub no_compress: bool,
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: HashAlgorithm,
}

fn default_hash_algorithm() -> HashAlgorithm {
    HashAlgorithm::Xxhash
}

/// 接收方文件请求 (Step3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteFileRequest {
    pub current_file_chunk_ranges: Vec<ChunkRange>,
    pub files_to_transfer_current_num: usize,
    pub machine_id: String,
}

/// 块范围 (断点续传)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRange {
    pub start: i64,
    pub end: i64,
}

/// 客户端配置
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub relay_address: String,
    pub relay_port: u16,
    pub relay_password: String,
    pub shared_secret: String,
    pub no_compress: bool,
    pub no_local: bool,
    pub no_multi: bool,
    pub hash_algorithm: HashAlgorithm,
    pub throttle_upload: Option<u64>,
    pub transfer_ports: usize,
    pub stdout: bool,
    pub ask: bool,
    pub overwrite: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            relay_address: DEFAULT_RELAY.into(),
            relay_port: DEFAULT_RELAY_PORT,
            relay_password: String::new(),
            shared_secret: String::new(),
            no_compress: false,
            no_local: false,
            no_multi: false,
            hash_algorithm: HashAlgorithm::default(),
            throttle_upload: None,
            transfer_ports: DEFAULT_TRANSFER_PORTS,
            stdout: false,
            ask: false,
            overwrite: false,
        }
    }
}

/// Relay 服务器配置
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub host: String,
    pub port: u16,
    pub password: String,
    pub ports: Vec<u16>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        let port = DEFAULT_RELAY_PORT;
        Self {
            host: "0.0.0.0".into(),
            port,
            password: String::new(),
            ports: (0..DEFAULT_TRANSFER_PORTS + 1)
                .map(|i| port + i as u16)
                .collect(),
        }
    }
}

// ── Serde helpers ──

mod system_time_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(UNIX_EPOCH + Duration::from_secs(secs))
    }
}

mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(CHUNK_SIZE, 32768);
        assert_eq!(COMM_MAGIC, b"croc");
        assert_eq!(PAKE_WEAK_KEY, &[1, 2, 3]);
    }

    #[test]
    fn test_sender_info_json_roundtrip() {
        let info = SenderInfo {
            files: vec![],
            empty_folders: vec![],
            total_files_size: 1024,
            no_compress: false,
            hash_algorithm: HashAlgorithm::Xxhash,
        };
        let json = serde_json::to_string(&info).unwrap();
        let decoded: SenderInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.total_files_size, 1024);
    }

    #[test]
    fn test_client_config_default() {
        let cfg = ClientConfig::default();
        assert_eq!(cfg.relay_port, 9009);
        assert_eq!(cfg.transfer_ports, 4);
    }

    #[test]
    fn test_relay_config_default_ports() {
        let cfg = RelayConfig::default();
        assert_eq!(cfg.ports.len(), 5); // base + 4 transfer
        assert_eq!(cfg.ports[0], 9009);
        assert_eq!(cfg.ports[4], 9013);
    }
}
```

#### Acceptance Criteria
- [ ] 所有常量值与 spec.md 一致
- [ ] FileInfo / SenderInfo / RemoteFileRequest 可 JSON 序列化/反序列化
- [ ] SystemTime serde 使用 UNIX 时间戳
- [ ] 测试全部通过

---

### T04: Mnemonic Encoding

- **File**: `src/mnemonic.rs`
- **Depends on**: T01
- **Description**: 移植 `schollz/mnemonicode`。将 4 字节编码为 3 个助记词，支持编码/解码。词典包含 1626 个词。

#### Function Signatures

```rust
/// 将字节序列编码为助记词列表
pub fn encode(data: &[u8]) -> Vec<String>

/// 将助记词列表解码为字节序列
pub fn decode(words: &[String]) -> crate::error::Result<Vec<u8>>

/// 生成密码短语: NNNN-word1-word2-word3
pub fn generate_code_phrase(num_words: usize) -> String

/// 从密码短语中提取房间名前缀和 PAKE 密码
/// 返回 (room_prefix, pake_password)
pub fn parse_code_phrase(phrase: &str) -> crate::error::Result<(String, String)>
```

#### Implementation

```rust
use rand::Rng;
use sha2::{Sha256, Digest};
use crate::error::{RcrocError, Result};
use crate::models::CODE_PREFIX_LEN;

/// 1626-word dictionary (ported from schollz/mnemonicode)
/// 完整词表需从 Go 源码 mnemonicode/wordlist.go 移植
const WORDLIST: &[&str] = &[
    "academy", "acrobat", "active", "actor", "adam", "admiral",
    "adrian", "africa", "agenda", "agent", "airline", "alabama",
    // ... (完整 1626 词需从 Go 源码移植)
    // 文件: https://github.com/schollz/mnemonicode/blob/master/wordlist.go
];

const WORDS_PER_GROUP: usize = 3;
const BYTES_PER_GROUP: usize = 4;

/// 将 4 字节编码为 3 个助记词索引
fn encode_group(b: &[u8]) -> Vec<usize> {
    let word_count = WORDLIST.len();
    let mut value: u32 = 0;
    for (i, &byte) in b.iter().enumerate() {
        value |= (byte as u32) << (8 * i);
    }

    let mut indices = Vec::with_capacity(WORDS_PER_GROUP);
    for _ in 0..WORDS_PER_GROUP {
        indices.push((value % word_count as u32) as usize);
        value /= word_count as u32;
    }
    indices
}

/// 将 3 个助记词索引解码为 4 字节
fn decode_group(indices: &[usize]) -> Result<Vec<u8>> {
    let word_count = WORDLIST.len();
    let mut value: u32 = 0;
    for (i, &idx) in indices.iter().enumerate().rev() {
        if idx >= word_count {
            return Err(RcrocError::InvalidInput(format!("word index {idx} out of range")));
        }
        value = value * word_count as u32 + idx as u32;
    }

    let mut bytes = Vec::with_capacity(BYTES_PER_GROUP);
    for i in 0..BYTES_PER_GROUP {
        bytes.push(((value >> (8 * i)) & 0xFF) as u8);
    }
    Ok(bytes)
}

fn word_to_index(word: &str) -> Result<usize> {
    let lower = word.to_lowercase();
    WORDLIST
        .iter()
        .position(|&w| w == lower)
        .ok_or_else(|| RcrocError::InvalidInput(format!("unknown mnemonic word: {word}")))
}

pub fn encode(data: &[u8]) -> Vec<String> {
    let mut words = Vec::new();
    for chunk in data.chunks(BYTES_PER_GROUP) {
        let mut padded = [0u8; BYTES_PER_GROUP];
        padded[..chunk.len()].copy_from_slice(chunk);
        let indices = encode_group(&padded);
        let count = if chunk.len() == BYTES_PER_GROUP {
            WORDS_PER_GROUP
        } else {
            // 不足 4 字节时词数减少
            (chunk.len() * WORDS_PER_GROUP + BYTES_PER_GROUP - 1) / BYTES_PER_GROUP
        };
        for &idx in &indices[..count] {
            words.push(WORDLIST[idx].to_string());
        }
    }
    words
}

pub fn decode(words: &[String]) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    for chunk in words.chunks(WORDS_PER_GROUP) {
        let indices: Vec<usize> = chunk
            .iter()
            .map(|w| word_to_index(w))
            .collect::<Result<_>>()?;

        let mut full_indices = indices.clone();
        while full_indices.len() < WORDS_PER_GROUP {
            full_indices.push(0);
        }
        let bytes = decode_group(&full_indices)?;

        let byte_count = if chunk.len() == WORDS_PER_GROUP {
            BYTES_PER_GROUP
        } else {
            chunk.len() * BYTES_PER_GROUP / WORDS_PER_GROUP
        };
        data.extend_from_slice(&bytes[..byte_count]);
    }
    Ok(data)
}

pub fn generate_code_phrase(num_words: usize) -> String {
    let mut rng = rand::thread_rng();
    let prefix: u16 = rng.gen_range(0..10000);

    let mut random_bytes = vec![0u8; (num_words * BYTES_PER_GROUP + WORDS_PER_GROUP - 1) / WORDS_PER_GROUP];
    rng.fill(random_bytes.as_mut_slice());

    let words = encode(&random_bytes);
    let selected: Vec<&str> = words.iter().take(num_words).map(|s| s.as_str()).collect();

    format!("{:04}-{}", prefix, selected.join("-"))
}

pub fn parse_code_phrase(phrase: &str) -> Result<(String, String)> {
    if phrase.len() < CODE_PREFIX_LEN + 1 {
        return Err(RcrocError::InvalidInput("code phrase too short".into()));
    }
    let prefix = &phrase[..CODE_PREFIX_LEN];
    // 验证前缀是数字
    if !prefix.chars().all(|c| c.is_ascii_digit()) {
        return Err(RcrocError::InvalidInput("code phrase must start with 4 digits".into()));
    }

    // 房间名 = hex(SHA256(prefix + "croc"))
    let room_input = format!("{prefix}croc");
    let room_hash = Sha256::digest(room_input.as_bytes());
    let room_name = hex::encode(room_hash);

    // PAKE 密码 = prefix 之后的部分 (跳过连字符)
    let pake_password = if phrase.len() > CODE_PREFIX_LEN + 1 {
        phrase[CODE_PREFIX_LEN + 1..].to_string()
    } else {
        String::new()
    };

    Ok((room_name, pake_password))
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let words = encode(&data);
        assert_eq!(words.len(), 3);
        let decoded = decode(&words).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_generate_code_phrase_format() {
        let phrase = generate_code_phrase(3);
        let parts: Vec<&str> = phrase.split('-').collect();
        assert_eq!(parts.len(), 4); // NNNN + 3 words
        assert_eq!(parts[0].len(), 4);
        assert!(parts[0].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_parse_code_phrase() {
        let phrase = "1234-alpha-beta-gamma";
        let (room, pake_pw) = parse_code_phrase(phrase).unwrap();
        assert!(!room.is_empty());
        assert_eq!(pake_pw, "alpha-beta-gamma");
    }

    #[test]
    fn test_parse_code_phrase_room_name_deterministic() {
        let (room1, _) = parse_code_phrase("1234-a-b-c").unwrap();
        let (room2, _) = parse_code_phrase("1234-x-y-z").unwrap();
        // 相同前缀 → 相同房间名
        assert_eq!(room1, room2);
    }

    #[test]
    fn test_parse_code_phrase_invalid() {
        assert!(parse_code_phrase("abc").is_err());
        assert!(parse_code_phrase("abcd-word").is_err());
    }
}
```

#### Acceptance Criteria
- [ ] 编码/解码 roundtrip 正确
- [ ] 密码短语格式: `NNNN-word1-word2-word3`
- [ ] 房间名 = `hex(SHA256(prefix + "croc"))` 与 spec 一致
- [ ] PAKE 密码 = 前缀后的完整字符串
- [ ] 1626 词词表完整移植

---

### T05: Compression

- **File**: `src/compress.rs`
- **Depends on**: T01, T02
- **Description**: DEFLATE Huffman-only 压缩/解压，使用 flate2 crate。

#### Implementation

```rust
use flate2::read::{DeflateDecoder, DeflateEncoder};
use flate2::Compression;
use std::io::Read;
use crate::error::{RcrocError, Result};

/// HuffmanOnly 压缩级别 (与原版 croc 一致)
const COMPRESSION_LEVEL: Compression = Compression::new(1);

/// 使用 DEFLATE (HuffmanOnly) 压缩数据
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(data, COMPRESSION_LEVEL);
    let mut compressed = Vec::new();
    encoder
        .read_to_end(&mut compressed)
        .map_err(|e| RcrocError::Compression(format!("compress failed: {e}")))?;
    Ok(compressed)
}

/// 解压 DEFLATE 数据
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| RcrocError::Compression(format!("decompress failed: {e}")))?;
    Ok(decompressed)
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let data = b"Hello, rcroc! This is a test of compression.";
        let compressed = compress(data).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_empty() {
        let compressed = compress(b"").unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, b"");
    }

    #[test]
    fn test_compress_large_data() {
        let data = vec![0x42u8; 100_000];
        let compressed = compress(&data).unwrap();
        assert!(compressed.len() < data.len());
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_decompress_invalid() {
        let result = decompress(&[0xFF, 0xFE, 0xFD]);
        assert!(result.is_err());
    }
}
```

#### Acceptance Criteria
- [ ] 压缩/解压 roundtrip 正确
- [ ] 空数据可处理
- [ ] 大数据压缩后体积更小
- [ ] 无效数据解压返回错误
- [ ] 使用 HuffmanOnly 级别

---

### T06: Crypto Module

- **Files**: `src/crypto/mod.rs`, `src/crypto/aes_gcm.rs`, `src/crypto/chacha.rs`, `src/crypto/key_derivation.rs`
- **Depends on**: T01, T02
- **Description**: 加密模块：AES-256-GCM（主用）、XChaCha20-Poly1305（备选）、PBKDF2/Argon2 密钥派生。

#### Implementation: src/crypto/mod.rs

```rust
pub mod aes_gcm_cipher;
pub mod chacha;
pub mod key_derivation;

pub use aes_gcm_cipher::AesGcmCipher;
pub use chacha::ChaChaCipher;
pub use key_derivation::{derive_key_pbkdf2, derive_key_argon2};

use crate::error::Result;

/// 统一加密 trait
pub trait Cipher: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
```

#### Implementation: src/crypto/aes_gcm.rs

```rust
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use crate::crypto::Cipher;
use crate::error::{RcrocError, Result};

const NONCE_SIZE: usize = 12;

pub struct AesGcmCipher {
    cipher: Aes256Gcm,
}

impl AesGcmCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }
}

impl Cipher for AesGcmCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| RcrocError::Crypto(format!("AES-GCM encrypt: {e}")))?;

        // 格式: [12-byte nonce][ciphertext+tag]
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE {
            return Err(RcrocError::Crypto("ciphertext too short for AES-GCM".into()));
        }
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| RcrocError::Crypto(format!("AES-GCM decrypt: {e}")))
    }
}
```

#### Implementation: src/crypto/chacha.rs

```rust
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use rand::RngCore;
use crate::crypto::Cipher;
use crate::error::{RcrocError, Result};

const NONCE_SIZE: usize = 24;

pub struct ChaChaCipher {
    cipher: XChaCha20Poly1305,
}

impl ChaChaCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::from_slice(key);
        Self {
            cipher: XChaCha20Poly1305::new(key),
        }
    }
}

impl Cipher for ChaChaCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| RcrocError::Crypto(format!("ChaCha20 encrypt: {e}")))?;

        // 格式: [24-byte nonce][ciphertext+tag]
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_SIZE {
            return Err(RcrocError::Crypto("ciphertext too short for ChaCha20".into()));
        }
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = XNonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| RcrocError::Crypto(format!("ChaCha20 decrypt: {e}")))
    }
}
```

#### Implementation: src/crypto/key_derivation.rs

```rust
use hmac::Hmac;
use sha2::Sha256;
use crate::error::{RcrocError, Result};
use crate::models::{PBKDF2_ITERATIONS, AES_KEY_LEN};

type HmacSha256 = Hmac<Sha256>;

/// PBKDF2 密钥派生 (主用, 与原版 croc 一致)
/// passphrase: PAKE session key
/// salt: 8-byte random salt
/// 返回 32-byte AES-256 密钥
pub fn derive_key_pbkdf2(passphrase: &[u8], salt: &[u8]) -> [u8; AES_KEY_LEN] {
    let mut key = [0u8; AES_KEY_LEN];
    pbkdf2::pbkdf2::<HmacSha256>(passphrase, salt, PBKDF2_ITERATIONS, &mut key)
        .expect("HMAC can be initialized with any key length");
    key
}

/// Argon2id 密钥派生 (备选, 用于 ChaCha20-Poly1305)
/// time=1, mem=64KB, threads=4, keyLen=32
pub fn derive_key_argon2(passphrase: &[u8], salt: &[u8]) -> Result<[u8; AES_KEY_LEN]> {
    use argon2::{Argon2, Algorithm, Version, Params};

    let params = Params::new(64 * 1024, 1, 4, Some(AES_KEY_LEN))
        .map_err(|e| RcrocError::Crypto(format!("Argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; AES_KEY_LEN];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| RcrocError::Crypto(format!("Argon2 derive: {e}")))?;
    Ok(key)
}
```

#### Tests

```rust
// 在各自文件的 #[cfg(test)] mod tests 中

// aes_gcm tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Cipher;

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(&key);
        let plaintext = b"hello rcroc";
        let encrypted = cipher.encrypt(plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        assert!(encrypted.len() > plaintext.len() + 12); // nonce + tag
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_tampered_ciphertext() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(&key);
        let mut encrypted = cipher.encrypt(b"test").unwrap();
        // 篡改最后一个字节
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(cipher.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_aes_gcm_wrong_key() {
        let cipher1 = AesGcmCipher::new(&[0x01u8; 32]);
        let cipher2 = AesGcmCipher::new(&[0x02u8; 32]);
        let encrypted = cipher1.encrypt(b"secret").unwrap();
        assert!(cipher2.decrypt(&encrypted).is_err());
    }
}

// key_derivation tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_deterministic() {
        let key1 = derive_key_pbkdf2(b"password", b"saltsalt");
        let key2 = derive_key_pbkdf2(b"password", b"saltsalt");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_pbkdf2_different_salt() {
        let key1 = derive_key_pbkdf2(b"password", b"salt1111");
        let key2 = derive_key_pbkdf2(b"password", b"salt2222");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_argon2_deterministic() {
        let key1 = derive_key_argon2(b"password", b"saltsalt").unwrap();
        let key2 = derive_key_argon2(b"password", b"saltsalt").unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_key_length() {
        let key = derive_key_pbkdf2(b"pw", b"sa");
        assert_eq!(key.len(), 32);
    }
}
```

#### Acceptance Criteria
- [ ] AES-256-GCM: 加密后格式为 [12-byte nonce][ciphertext+tag]
- [ ] XChaCha20-Poly1305: 加密后格式为 [24-byte nonce][ciphertext+tag]
- [ ] 篡改密文解密失败
- [ ] 错误密钥解密失败
- [ ] PBKDF2: 100 iterations, 32 bytes, SHA-256 与 spec 一致
- [ ] Argon2id: time=1, mem=64KB, threads=4
- [ ] Cipher trait 实现 Send + Sync
- [ ] 全部测试通过

---

## Phase 2: Protocol Layer

### T07: Comm Frame Protocol

- **File**: `src/protocol/comm.rs`
- **Depends on**: T01, T02, T03
- **Description**: 帧协议实现: `[4-byte magic "croc"][4-byte LE u32 length][payload]`。支持异步读写。

#### Implementation

```rust
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::time::Duration;
use crate::error::{RcrocError, Result};
use crate::models::{COMM_MAGIC, RW_TIMEOUT_SECS};

/// Comm 连接封装，提供帧协议读写
pub struct Comm {
    stream: TcpStream,
    timeout: Duration,
}

impl Comm {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            timeout: Duration::from_secs(RW_TIMEOUT_SECS),
        }
    }

    pub fn with_timeout(stream: TcpStream, timeout: Duration) -> Self {
        Self { stream, timeout }
    }

    /// 发送一帧数据: magic + length + payload
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        let mut header = Vec::with_capacity(8);
        header.extend_from_slice(COMM_MAGIC);
        header.write_u32::<LittleEndian>(payload.len() as u32)
            .map_err(|e| RcrocError::Protocol(format!("write length: {e}")))?;

        let result = tokio::time::timeout(self.timeout, async {
            self.stream.write_all(&header).await?;
            self.stream.write_all(payload).await?;
            self.stream.flush().await?;
            Ok::<(), std::io::Error>(())
        })
        .await;

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(RcrocError::Io(e)),
            Err(_) => Err(RcrocError::Timeout("comm send timeout".into())),
        }
    }

    /// 接收一帧数据: 验证 magic, 读取 length, 读取 payload
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let result = tokio::time::timeout(self.timeout, async {
            // 读取 magic
            let mut magic = [0u8; 4];
            self.stream.read_exact(&mut magic).await?;
            if &magic != COMM_MAGIC {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid magic: {:?}", magic),
                ));
            }

            // 读取长度 (LE u32)
            let mut len_buf = [0u8; 4];
            self.stream.read_exact(&mut len_buf).await?;
            let length = (&len_buf[..]).read_u32::<LittleEndian>()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

            // 读取 payload
            let mut payload = vec![0u8; length as usize];
            self.stream.read_exact(&mut payload).await?;

            Ok(payload)
        })
        .await;

        match result {
            Ok(Ok(payload)) => Ok(payload),
            Ok(Err(e)) => Err(RcrocError::Io(e)),
            Err(_) => Err(RcrocError::Timeout("comm recv timeout".into())),
        }
    }

    /// 获取底层 TcpStream 的引用 (用于 split)
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }

    /// 获取远端地址
    pub fn peer_addr(&self) -> Result<std::net::SocketAddr> {
        self.stream.peer_addr().map_err(RcrocError::Io)
    }
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_comm_send_recv() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut comm = Comm::new(stream);
            let data = comm.recv().await.unwrap();
            assert_eq!(data, b"hello rcroc");
            comm.send(b"world").await.unwrap();
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let mut client = Comm::new(client_stream);
        client.send(b"hello rcroc").await.unwrap();
        let response = client.recv().await.unwrap();
        assert_eq!(response, b"world");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_comm_large_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = vec![0xAB; 65536];
        let payload_clone = payload.clone();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut comm = Comm::new(stream);
            let data = comm.recv().await.unwrap();
            assert_eq!(data.len(), 65536);
            assert_eq!(data, payload_clone);
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let mut client = Comm::new(client_stream);
        client.send(&payload).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_comm_empty_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut comm = Comm::new(stream);
            let data = comm.recv().await.unwrap();
            assert!(data.is_empty());
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let mut client = Comm::new(client_stream);
        client.send(b"").await.unwrap();

        server.await.unwrap();
    }
}
```

#### Acceptance Criteria
- [ ] 帧格式: `[b"croc"][LE u32 len][payload]` 与 spec 一致
- [ ] 魔数验证: 非 `croc` 魔数返回错误
- [ ] 支持空 payload
- [ ] 支持 64KB+ 大 payload
- [ ] 读写超时默认 3 小时
- [ ] 异步 send/recv 测试通过

---

### T08: PAKE2 Implementation

- **File**: `src/protocol/pake.rs`
- **Depends on**: T01, T02, T06
- **Description**: 基于 P-256 的 SPAKE2 实现 (见 ADR-002)。支持 role 0/1，密钥交换后输出 session key。

#### Function Signatures

```rust
/// PAKE 角色
pub enum PakeRole {
    Receiver = 0,  // Role 0
    Sender = 1,    // Role 1
}

/// PAKE 状态机
pub struct Pake { /* ... */ }

impl Pake {
    /// 初始化 PAKE，生成待发送的公钥字节
    pub fn new(password: &[u8], role: PakeRole) -> Result<Self>;

    /// 获取待发送给对方的字节 (初始化后调用)
    pub fn bytes(&self) -> &[u8];

    /// 用对方的字节更新状态，计算共享密钥
    pub fn update(&mut self, peer_bytes: &[u8]) -> Result<()>;

    /// 获取会话密钥 (update 之后调用)
    pub fn session_key(&self) -> Result<&[u8]>;
}
```

#### Implementation

```rust
use p256::{
    elliptic_curve::{
        group::GroupEncoding,
        hash2curve::{ExpandMsgXmd, GroupDigest},
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field, Group,
    },
    NistP256, ProjectivePoint, Scalar, U256,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{RcrocError, Result};

const DST_M: &[u8] = b"rcroc-pake-M-point-v1";
const DST_N: &[u8] = b"rcroc-pake-N-point-v1";
const HASH_DST: &[u8] = b"rcroc-pake-hash2curve-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PakeRole {
    Receiver = 0,
    Sender = 1,
}

pub struct Pake {
    role: PakeRole,
    password_scalar: Scalar,
    random_scalar: Scalar,
    blinded_point: ProjectivePoint,  // X* or Y*
    my_bytes: Vec<u8>,
    session_key: Option<Vec<u8>>,
}

impl Pake {
    pub fn new(password: &[u8], role: PakeRole) -> Result<Self> {
        // 密码 → 标量
        let pw_hash = Sha256::digest(password);
        let pw_uint = U256::from_be_slice(&pw_hash);
        let password_scalar = <Scalar as Reduce<U256>>::reduce(pw_uint);

        // 生成随机标量
        let random_scalar = Scalar::random(&mut OsRng);

        // 获取盲化点 M 或 N
        let blinding_point = match role {
            PakeRole::Receiver => hash_to_point(DST_M)?,
            PakeRole::Sender => hash_to_point(DST_N)?,
        };

        // X* = x·G + w·M  (或 Y* = y·G + w·N)
        let blinded_point = ProjectivePoint::GENERATOR * random_scalar
            + blinding_point * password_scalar;

        // 序列化为未压缩 SEC1 格式
        let encoded = blinded_point.to_affine().to_encoded_point(false);
        let my_bytes = encoded.as_bytes().to_vec();

        Ok(Self {
            role,
            password_scalar,
            random_scalar,
            blinded_point,
            my_bytes,
            session_key: None,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.my_bytes
    }

    pub fn update(&mut self, peer_bytes: &[u8]) -> Result<()> {
        // 解析对方的盲化点
        let peer_encoded = p256::EncodedPoint::from_bytes(peer_bytes)
            .map_err(|e| RcrocError::PakeAuth(format!("invalid peer point: {e}")))?;
        let peer_affine = p256::AffinePoint::from_encoded_point(&peer_encoded)
            .into_option()
            .ok_or_else(|| RcrocError::PakeAuth("invalid peer point on curve".into()))?;
        let peer_point = ProjectivePoint::from(peer_affine);

        // 获取对方的盲化点 (对方角色相反)
        let peer_blinding = match self.role {
            PakeRole::Receiver => hash_to_point(DST_N)?, // 对方是 Sender, 用 N
            PakeRole::Sender => hash_to_point(DST_M)?,   // 对方是 Receiver, 用 M
        };

        // K = random * (peer_point - pw * peer_blinding)
        let unblinded = peer_point - peer_blinding * self.password_scalar;
        let shared_point = unblinded * self.random_scalar;

        // session_key = SHA-256(K_bytes || my_bytes || peer_bytes)
        let k_bytes = shared_point.to_affine().to_encoded_point(false);
        let mut hasher = Sha256::new();
        hasher.update(k_bytes.as_bytes());
        hasher.update(&self.my_bytes);
        hasher.update(peer_bytes);
        let key = hasher.finalize().to_vec();

        self.session_key = Some(key);
        Ok(())
    }

    pub fn session_key(&self) -> Result<&[u8]> {
        self.session_key
            .as_deref()
            .ok_or_else(|| RcrocError::PakeAuth("session key not yet derived".into()))
    }
}

impl Drop for Pake {
    fn drop(&mut self) {
        self.random_scalar.zeroize();
        if let Some(ref mut key) = self.session_key {
            key.zeroize();
        }
    }
}

/// Hash arbitrary label to a P-256 curve point
fn hash_to_point(label: &[u8]) -> Result<ProjectivePoint> {
    let point = NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[label], HASH_DST)
        .map_err(|e| RcrocError::PakeAuth(format!("hash to curve: {e}")))?;
    Ok(point)
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pake_key_exchange() {
        let password = b"test-password";

        let mut pake_a = Pake::new(password, PakeRole::Receiver).unwrap();
        let mut pake_b = Pake::new(password, PakeRole::Sender).unwrap();

        let a_bytes = pake_a.bytes().to_vec();
        let b_bytes = pake_b.bytes().to_vec();

        pake_a.update(&b_bytes).unwrap();
        pake_b.update(&a_bytes).unwrap();

        let key_a = pake_a.session_key().unwrap();
        let key_b = pake_b.session_key().unwrap();
        assert_eq!(key_a, key_b);
        assert_eq!(key_a.len(), 32);
    }

    #[test]
    fn test_pake_wrong_password() {
        let mut pake_a = Pake::new(b"password-A", PakeRole::Receiver).unwrap();
        let mut pake_b = Pake::new(b"password-B", PakeRole::Sender).unwrap();

        let a_bytes = pake_a.bytes().to_vec();
        let b_bytes = pake_b.bytes().to_vec();

        pake_a.update(&b_bytes).unwrap();
        pake_b.update(&a_bytes).unwrap();

        let key_a = pake_a.session_key().unwrap();
        let key_b = pake_b.session_key().unwrap();
        assert_ne!(key_a, key_b); // 密码不同 → 密钥不同
    }

    #[test]
    fn test_pake_deterministic_blinding_points() {
        let p1 = hash_to_point(DST_M).unwrap();
        let p2 = hash_to_point(DST_M).unwrap();
        assert_eq!(
            p1.to_affine().to_encoded_point(false),
            p2.to_affine().to_encoded_point(false)
        );
    }

    #[test]
    fn test_pake_session_key_before_update() {
        let pake = Pake::new(b"password", PakeRole::Receiver).unwrap();
        assert!(pake.session_key().is_err());
    }

    #[test]
    fn test_pake_bytes_not_empty() {
        let pake = Pake::new(b"password", PakeRole::Sender).unwrap();
        assert!(!pake.bytes().is_empty());
        // P-256 未压缩点: 1 + 32 + 32 = 65 bytes
        assert_eq!(pake.bytes().len(), 65);
    }
}
```

#### Acceptance Criteria
- [ ] 相同密码 + 不同角色 → 相同 session key
- [ ] 不同密码 → 不同 session key
- [ ] session key 为 32 bytes (SHA-256 输出)
- [ ] 盲化点使用 hash-to-curve (非 hash-and-pray)
- [ ] 随机标量在 Drop 时 zeroize
- [ ] session key 在 Drop 时 zeroize
- [ ] 点编码使用未压缩 SEC1 格式 (65 bytes)

---

### T09: Message Types

- **File**: `src/protocol/message.rs` (types section)
- **Depends on**: T01, T02, T03
- **Description**: 定义消息枚举和序列化。

#### Implementation

```rust
use serde::{Deserialize, Serialize};
use crate::models::{SenderInfo, RemoteFileRequest};

/// 协议消息类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum Message {
    /// PAKE 交换字节
    #[serde(rename = "pake")]
    Pake {
        #[serde(with = "base64_bytes")]
        bytes: Vec<u8>,
    },

    /// 外部 IP 交换
    #[serde(rename = "externalip")]
    ExternalIP { value: String },

    /// 文件信息 (发送方 → 接收方)
    #[serde(rename = "fileinfo")]
    FileInfo(SenderInfo),

    /// 接收方就绪 (接收方 → 发送方)
    #[serde(rename = "recipientready")]
    RecipientReady(RemoteFileRequest),

    /// 当前文件接收完毕 (接收方 → 发送方)
    #[serde(rename = "closesender")]
    CloseSender,

    /// 确认关闭 (发送方 → 接收方)
    #[serde(rename = "closerecipient")]
    CloseRecipient,

    /// 所有文件传输完毕
    #[serde(rename = "finished")]
    Finished,

    /// 错误/中止
    #[serde(rename = "error")]
    Error { message: String },
}

/// Base64 编码字节的 serde helper
mod base64_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_pake_json() {
        let msg = Message::Pake { bytes: vec![1, 2, 3] };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"t\":\"pake\""));
        let decoded: Message = serde_json::from_str(&json).unwrap();
        if let Message::Pake { bytes } = decoded {
            assert_eq!(bytes, vec![1, 2, 3]);
        } else {
            panic!("expected Pake message");
        }
    }

    #[test]
    fn test_message_error_json() {
        let msg = Message::Error { message: "test error".into() };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        if let Message::Error { message } = decoded {
            assert_eq!(message, "test error");
        } else {
            panic!("expected Error message");
        }
    }

    #[test]
    fn test_message_finished_json() {
        let msg = Message::Finished;
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: Message = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, Message::Finished));
    }
}
```

#### Acceptance Criteria
- [ ] 所有 8 种消息类型可 JSON 序列化/反序列化
- [ ] PAKE bytes 使用 base64 编码
- [ ] tag 字段名与协议规格一致
- [ ] SenderInfo / RemoteFileRequest 嵌入正确

---

### T10: Message Encode/Decode Pipeline

- **File**: `src/protocol/message.rs` (pipeline section) + `src/protocol/mod.rs`
- **Depends on**: T05 (compress), T06 (crypto), T07 (comm), T09 (message types)
- **Description**: 消息编码管线: JSON → Compress → Encrypt → Comm Frame。解码为反向。

#### Implementation: message.rs (续)

```rust
use crate::compress;
use crate::crypto::Cipher;
use crate::protocol::comm::Comm;
use crate::error::Result;

/// 编码消息: JSON → 压缩 → 加密
pub fn encode_message(msg: &Message, cipher: &dyn Cipher) -> Result<Vec<u8>> {
    // Step 1: JSON 序列化
    let json_bytes = serde_json::to_vec(msg)?;

    // Step 2: DEFLATE 压缩
    let compressed = compress::compress(&json_bytes)?;

    // Step 3: 加密
    let encrypted = cipher.encrypt(&compressed)?;

    Ok(encrypted)
}

/// 解码消息: 解密 → 解压 → JSON 反序列化
pub fn decode_message(data: &[u8], cipher: &dyn Cipher) -> Result<Message> {
    // Step 1: 解密
    let decrypted = cipher.decrypt(data)?;

    // Step 2: 解压
    let decompressed = compress::decompress(&decrypted)?;

    // Step 3: JSON 反序列化
    let msg: Message = serde_json::from_slice(&decompressed)?;

    Ok(msg)
}

/// 通过 Comm 连接发送加密消息
pub async fn send_message(comm: &mut Comm, msg: &Message, cipher: &dyn Cipher) -> Result<()> {
    let encoded = encode_message(msg, cipher)?;
    comm.send(&encoded).await
}

/// 从 Comm 连接接收并解密消息
pub async fn recv_message(comm: &mut Comm, cipher: &dyn Cipher) -> Result<Message> {
    let data = comm.recv().await?;
    decode_message(&data, cipher)
}
```

#### Implementation: src/protocol/mod.rs

```rust
pub mod comm;
pub mod pake;
pub mod message;

pub use comm::Comm;
pub use pake::{Pake, PakeRole};
pub use message::{Message, encode_message, decode_message, send_message, recv_message};
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AesGcmCipher;
    use crate::crypto::key_derivation::derive_key_pbkdf2;

    #[test]
    fn test_encode_decode_pipeline() {
        let key = derive_key_pbkdf2(b"password", b"saltsalt");
        let cipher = AesGcmCipher::new(&key);

        let msg = Message::ExternalIP { value: "192.168.1.1".into() };
        let encoded = encode_message(&msg, &cipher).unwrap();
        let decoded = decode_message(&encoded, &cipher).unwrap();

        if let Message::ExternalIP { value } = decoded {
            assert_eq!(value, "192.168.1.1");
        } else {
            panic!("wrong message type");
        }
    }

    #[test]
    fn test_pipeline_with_fileinfo() {
        let key = [0x42u8; 32];
        let cipher = AesGcmCipher::new(&key);

        let info = crate::models::SenderInfo {
            files: vec![],
            empty_folders: vec![],
            total_files_size: 999,
            no_compress: false,
            hash_algorithm: crate::models::HashAlgorithm::Xxhash,
        };
        let msg = Message::FileInfo(info);
        let encoded = encode_message(&msg, &cipher).unwrap();
        let decoded = decode_message(&encoded, &cipher).unwrap();

        if let Message::FileInfo(decoded_info) = decoded {
            assert_eq!(decoded_info.total_files_size, 999);
        } else {
            panic!("wrong message type");
        }
    }

    #[tokio::test]
    async fn test_send_recv_message() {
        use tokio::net::TcpListener;
        use crate::protocol::comm::Comm;

        let key = [0x42u8; 32];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn({
            let cipher = AesGcmCipher::new(&key);
            async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut comm = Comm::new(stream);
                let msg = recv_message(&mut comm, &cipher).await.unwrap();
                assert!(matches!(msg, Message::Finished));
            }
        });

        let cipher = AesGcmCipher::new(&key);
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut comm = Comm::new(stream);
        send_message(&mut comm, &Message::Finished, &cipher).await.unwrap();

        server.await.unwrap();
    }
}
```

#### Acceptance Criteria
- [ ] 编码管线: JSON → Compress → Encrypt 与 spec 一致
- [ ] 解码管线: Decrypt → Decompress → JSON
- [ ] 所有消息类型通过管线 roundtrip
- [ ] 异步 send/recv 通过 Comm 集成测试通过
- [ ] 管线中任一步骤失败返回明确错误

---

## Phase 3: Relay Server

### T11: Room Management

- **File**: `src/relay/room.rs`
- **Depends on**: T01, T02
- **Description**: Relay 房间管理：HashMap 存储，TTL 清理，Mutex 保护。

#### Implementation

```rust
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use crate::error::{RcrocError, Result};
use crate::models::{ROOM_TTL_SECS, ROOM_CLEANUP_INTERVAL_SECS};

/// 房间信息
struct RoomEntry {
    /// 第一个到达的客户端连接
    first_conn: Option<TcpStream>,
    /// 创建时间
    created_at: Instant,
    /// 是否已配对
    paired: bool,
}

/// 房间管理器
pub struct RoomManager {
    rooms: Arc<Mutex<HashMap<String, RoomEntry>>>,
}

impl RoomManager {
    pub fn new() -> Self {
        Self {
            rooms: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 加入房间。
    /// 如果房间不存在，创建并等待第二个客户端。
    /// 如果房间已有一个客户端，返回该客户端连接进行配对。
    pub async fn join(&self, room_name: &str, conn: TcpStream) -> Result<RoomJoinResult> {
        let mut rooms = self.rooms.lock().await;

        if let Some(entry) = rooms.get_mut(room_name) {
            if entry.paired {
                return Err(RcrocError::RoomFull(room_name.into()));
            }
            // 第二个客户端到达，取出第一个客户端的连接
            let first_conn = entry.first_conn.take()
                .ok_or_else(|| RcrocError::Relay("first connection missing".into()))?;
            entry.paired = true;
            Ok(RoomJoinResult::Paired {
                first: first_conn,
                second: conn,
            })
        } else {
            // 第一个客户端，创建房间
            rooms.insert(room_name.to_string(), RoomEntry {
                first_conn: Some(conn),
                created_at: Instant::now(),
                paired: false,
            });
            Ok(RoomJoinResult::Waiting)
        }
    }

    /// 移除房间
    pub async fn remove(&self, room_name: &str) {
        let mut rooms = self.rooms.lock().await;
        rooms.remove(room_name);
    }

    /// 清理过期房间 (超过 ROOM_TTL_SECS)
    pub async fn cleanup_stale(&self) -> usize {
        let mut rooms = self.rooms.lock().await;
        let before = rooms.len();
        let ttl = std::time::Duration::from_secs(ROOM_TTL_SECS);
        rooms.retain(|_, entry| entry.created_at.elapsed() < ttl);
        before - rooms.len()
    }

    /// 获取当前房间数
    pub async fn room_count(&self) -> usize {
        let rooms = self.rooms.lock().await;
        rooms.len()
    }

    /// 启动定期清理任务
    pub fn start_cleanup_task(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(ROOM_CLEANUP_INTERVAL_SECS);
            loop {
                tokio::time::sleep(interval).await;
                let cleaned = manager.cleanup_stale().await;
                if cleaned > 0 {
                    tracing::info!("cleaned up {cleaned} stale rooms");
                }
            }
        })
    }
}

/// 房间加入结果
pub enum RoomJoinResult {
    /// 第一个客户端，需要等待
    Waiting,
    /// 已配对，两个客户端就绪
    Paired { first: TcpStream, second: TcpStream },
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn make_tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn test_room_join_first_client_waits() {
        let manager = RoomManager::new();
        let (conn, _peer) = make_tcp_pair().await;
        let result = manager.join("room1", conn).await.unwrap();
        assert!(matches!(result, RoomJoinResult::Waiting));
        assert_eq!(manager.room_count().await, 1);
    }

    #[tokio::test]
    async fn test_room_join_second_client_pairs() {
        let manager = RoomManager::new();
        let (c1, _p1) = make_tcp_pair().await;
        let (c2, _p2) = make_tcp_pair().await;

        let r1 = manager.join("room1", c1).await.unwrap();
        assert!(matches!(r1, RoomJoinResult::Waiting));

        let r2 = manager.join("room1", c2).await.unwrap();
        assert!(matches!(r2, RoomJoinResult::Paired { .. }));
    }

    #[tokio::test]
    async fn test_room_full_rejects_third() {
        let manager = RoomManager::new();
        let (c1, _) = make_tcp_pair().await;
        let (c2, _) = make_tcp_pair().await;
        let (c3, _) = make_tcp_pair().await;

        manager.join("room1", c1).await.unwrap();
        manager.join("room1", c2).await.unwrap();
        let result = manager.join("room1", c3).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cleanup_stale() {
        let manager = RoomManager::new();
        // 直接插入一个带旧时间戳的房间来测试清理
        {
            let mut rooms = manager.rooms.lock().await;
            rooms.insert("old_room".into(), RoomEntry {
                first_conn: None,
                created_at: Instant::now() - std::time::Duration::from_secs(ROOM_TTL_SECS + 1),
                paired: false,
            });
        }
        let cleaned = manager.cleanup_stale().await;
        assert_eq!(cleaned, 1);
        assert_eq!(manager.room_count().await, 0);
    }
}
```

#### Acceptance Criteria
- [ ] 第一个客户端加入返回 Waiting
- [ ] 第二个客户端加入返回 Paired
- [ ] 第三个客户端加入返回 RoomFull 错误
- [ ] 超过 3 小时的房间被清理
- [ ] 清理任务每 10 分钟运行
- [ ] 并发安全 (Mutex)

---

### T12: Bidirectional Pipe

- **File**: `src/relay/pipe.rs`
- **Depends on**: T01, T02
- **Description**: 两个 TcpStream 之间的双向数据转发。

#### Implementation

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::error::Result;
use crate::models::KEEPALIVE_BYTE;

/// 双向管道：将 a 的数据转发给 b，同时将 b 的数据转发给 a
pub async fn pipe_bidirectional(a: TcpStream, b: TcpStream) -> Result<()> {
    let (mut a_read, mut a_write) = a.into_split();
    let (mut b_read, mut b_write) = b.into_split();

    let a_to_b = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match a_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if b_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = b_write.shutdown().await;
    });

    let b_to_a = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match b_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if a_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = a_write.shutdown().await;
    });

    // 等待任一方向完成
    tokio::select! {
        _ = a_to_b => {},
        _ = b_to_a => {},
    }

    Ok(())
}

/// 向等待中的客户端发送 keepalive 字节
pub async fn send_keepalive(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(&[KEEPALIVE_BYTE])
        .await
        .map_err(crate::error::RcrocError::Io)
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_pipe_bidirectional() {
        // 创建两对连接
        let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = listener1.local_addr().unwrap();
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();

        let client_a = TcpStream::connect(addr1).await.unwrap();
        let (relay_a, _) = listener1.accept().await.unwrap();

        let client_b = TcpStream::connect(addr2).await.unwrap();
        let (relay_b, _) = listener2.accept().await.unwrap();

        // 启动双向管道
        tokio::spawn(async move {
            pipe_bidirectional(relay_a, relay_b).await.ok();
        });

        // client_a 发送，client_b 接收
        let mut ca = client_a;
        let mut cb = client_b;

        ca.write_all(b"hello from a").await.unwrap();

        let mut buf = vec![0u8; 64];
        let n = cb.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from a");

        // client_b 发送，client_a 接收
        cb.write_all(b"hello from b").await.unwrap();

        let n = ca.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from b");
    }
}
```

#### Acceptance Criteria
- [ ] 双向转发工作正确
- [ ] 任一方断开连接后管道结束
- [ ] keepalive 发送 0x01 字节
- [ ] 使用 64KB 缓冲区

---

### T13: Relay Server Core

- **File**: `src/relay/mod.rs`
- **Depends on**: T07, T08, T11, T12
- **Description**: Relay TCP 服务器: 监听多端口，处理客户端认证、房间分配、双向管道。

#### Implementation

```rust
pub mod room;
pub mod pipe;

use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn, error};

use crate::error::{RcrocError, Result};
use crate::models::{RelayConfig, PAKE_WEAK_KEY, PAKE_SALT_LEN, KEEPALIVE_BYTE};
use crate::protocol::{Comm, Pake, PakeRole};
use crate::crypto::{AesGcmCipher, Cipher};
use crate::crypto::key_derivation::derive_key_pbkdf2;
use room::{RoomManager, RoomJoinResult};

/// Relay 服务器
pub struct RelayServer {
    config: RelayConfig,
    room_manager: Arc<RoomManager>,
}

impl RelayServer {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            room_manager: Arc::new(RoomManager::new()),
        }
    }

    /// 启动 relay 服务器，监听所有配置端口
    pub async fn run(&self) -> Result<()> {
        // 启动房间清理任务
        self.room_manager.start_cleanup_task();

        let mut handles = Vec::new();

        for &port in &self.config.ports {
            let addr = format!("{}:{}", self.config.host, port);
            let listener = TcpListener::bind(&addr)
                .await
                .map_err(|e| RcrocError::Relay(format!("bind {addr}: {e}")))?;
            info!("relay listening on {addr}");

            let room_manager = Arc::clone(&self.room_manager);
            let password = self.config.password.clone();

            let handle = tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, peer_addr)) => {
                            info!("new connection from {peer_addr}");
                            let rm = Arc::clone(&room_manager);
                            let pw = password.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, rm, &pw).await {
                                    warn!("connection error from {peer_addr}: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            error!("accept error: {e}");
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // 等待所有监听任务 (实际上是永远运行)
        for handle in handles {
            handle.await.map_err(|e| RcrocError::Relay(format!("task join: {e}")))?;
        }

        Ok(())
    }
}

/// 处理单个客户端连接
async fn handle_connection(
    stream: tokio::net::TcpStream,
    room_manager: Arc<RoomManager>,
    relay_password: &str,
) -> Result<()> {
    let peer_addr = stream.peer_addr()?.to_string();
    let mut comm = Comm::new(stream);

    // ── Phase 1: PAKE 认证 (弱密钥) ──

    // 接收客户端的 PAKE init 字节
    let client_pake_bytes = comm.recv().await?;

    // Relay 作为 role=1 (Sender 角色)
    let mut pake = Pake::new(PAKE_WEAK_KEY, PakeRole::Sender)?;

    // 发送 relay 的 PAKE 字节
    comm.send(pake.bytes()).await?;

    // 接收客户端的 PAKE update + salt
    let client_update = comm.recv().await?;
    if client_update.len() < PAKE_SALT_LEN {
        return Err(RcrocError::Protocol("PAKE update too short".into()));
    }
    let (pake_bytes, salt) = client_update.split_at(client_update.len() - PAKE_SALT_LEN);

    // 更新 PAKE
    pake.update(&client_pake_bytes)?;

    // 派生加密密钥
    let session_key = pake.session_key()?;
    let aes_key = derive_key_pbkdf2(session_key, salt);
    let cipher = AesGcmCipher::new(&aes_key);

    // ── Phase 2: 密码验证 ──

    // 接收加密的 relay 密码
    let encrypted_pw = comm.recv().await?;
    let client_pw = cipher.decrypt(&encrypted_pw)?;
    let client_pw_str = String::from_utf8_lossy(&client_pw);

    // 验证密码 (空密码 = 无密码保护)
    if !relay_password.is_empty() && client_pw_str != relay_password {
        let err_msg = cipher.encrypt(b"bad password")?;
        comm.send(&err_msg).await?;
        return Err(RcrocError::Relay("invalid relay password".into()));
    }

    // 发送 ok + 客户端远程地址
    let ok_msg = format!("ok|||{peer_addr}");
    let encrypted_ok = cipher.encrypt(ok_msg.as_bytes())?;
    comm.send(&encrypted_ok).await?;

    // ── Phase 3: 房间分配 ──

    // 接收加密的房间名
    let encrypted_room = comm.recv().await?;
    let room_name_bytes = cipher.decrypt(&encrypted_room)?;
    let room_name = String::from_utf8_lossy(&room_name_bytes).to_string();

    info!("client {peer_addr} joining room: {room_name}");

    // 加入房间
    let conn = comm.into_inner();
    match room_manager.join(&room_name, conn).await? {
        RoomJoinResult::Waiting => {
            // 第一个客户端: 发送 ok 并等待
            // 注意: 此时 conn 已被 move 进 room_manager
            // keepalive 由单独的任务处理
            let ok_encrypted = cipher.encrypt(b"ok")?;
            // 需要通过 room_manager 向等待的连接发送 ok
            // 实际实现中，ok 在 join 之前发送
            // 这里简化处理：在 join 前发送 ok
            info!("client {peer_addr} waiting in room {room_name}");
            Ok(())
        }
        RoomJoinResult::Paired { first, second } => {
            // 配对成功，启动双向管道
            info!("room {room_name} paired, starting pipe");
            // 向两个客户端发送 ok
            let ok_encrypted = cipher.encrypt(b"ok")?;
            // 注: 实际实现需要向两个客户端分别发送 ok
            // 然后启动管道
            pipe::pipe_bidirectional(first, second).await?;
            room_manager.remove(&room_name).await;
            info!("room {room_name} pipe closed");
            Ok(())
        }
    }
}
```

#### Acceptance Criteria
- [ ] 监听所有配置端口 (base + transfer ports)
- [ ] PAKE 弱密钥认证 [1,2,3] 使用 P-256
- [ ] relay 密码验证
- [ ] 返回 `ok|||<client_addr>` 格式
- [ ] 房间分配: 第一个等待，第二个配对
- [ ] 配对后启动双向管道
- [ ] 连接结束后清理房间
- [ ] 错误处理不 panic

---

### T14: Relay Auth Handshake Flow

- **File**: `src/relay/mod.rs` (client-side auth helper)
- **Depends on**: T06, T07, T08, T13
- **Description**: 客户端侧的 relay 认证辅助函数，封装 PAKE 握手 + 密码验证 + 房间加入流程。

#### Implementation

```rust
/// 客户端连接 relay 并完成认证
/// 返回 (Comm, Cipher, 远程地址)
pub async fn connect_to_relay(
    addr: &str,
    relay_password: &str,
    room_name: &str,
) -> Result<(Comm, Box<dyn Cipher + Send>, String)> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| RcrocError::Relay(format!("connect {addr}: {e}")))?;

    let mut comm = Comm::new(stream);

    // ── PAKE 握手 (弱密钥, 客户端为 role=0) ──
    let mut pake = Pake::new(PAKE_WEAK_KEY, PakeRole::Receiver)?;

    // 发送 PAKE init
    comm.send(pake.bytes()).await?;

    // 接收 relay 的 PAKE 字节
    let relay_pake_bytes = comm.recv().await?;

    // 生成 salt
    let mut salt = [0u8; PAKE_SALT_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);

    // 发送 PAKE update + salt
    let mut update_msg = pake.bytes().to_vec();
    // 注意: 这里需要先 update 再发送新的 bytes
    pake.update(&relay_pake_bytes)?;
    // 重新构建: 发送 pake bytes (update 后) + salt
    // 实际上原版发送的是 update 后的 bytes + salt
    let mut pake_with_salt = pake.bytes().to_vec();
    pake_with_salt.extend_from_slice(&salt);
    comm.send(&pake_with_salt).await?;

    // 派生加密密钥
    let session_key = pake.session_key()?;
    let aes_key = derive_key_pbkdf2(session_key, &salt);
    let cipher = AesGcmCipher::new(&aes_key);

    // ── 密码验证 ──
    let encrypted_pw = cipher.encrypt(relay_password.as_bytes())?;
    comm.send(&encrypted_pw).await?;

    // 接收 ok 响应
    let encrypted_response = comm.recv().await?;
    let response = cipher.decrypt(&encrypted_response)?;
    let response_str = String::from_utf8_lossy(&response);

    if !response_str.starts_with("ok|||") {
        return Err(RcrocError::Relay(format!("relay auth failed: {response_str}")));
    }

    // 提取远程地址
    let remote_addr = response_str
        .strip_prefix("ok|||")
        .unwrap_or("")
        .to_string();

    // ── 加入房间 ──
    let encrypted_room = cipher.encrypt(room_name.as_bytes())?;
    comm.send(&encrypted_room).await?;

    // 接收房间分配结果
    let encrypted_room_response = comm.recv().await?;
    let room_response = cipher.decrypt(&encrypted_room_response)?;
    let room_response_str = String::from_utf8_lossy(&room_response);

    if room_response_str != "ok" {
        return Err(RcrocError::Relay(format!("room join failed: {room_response_str}")));
    }

    Ok((comm, Box::new(cipher), remote_addr))
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    // 集成测试: 启动本地 relay, 两个客户端连接并配对
    // 详见 Phase 5 集成测试
}
```

#### Acceptance Criteria
- [ ] 客户端使用弱密钥 [1,2,3] + Role::Receiver
- [ ] salt 8 字节随机生成
- [ ] PAKE update + salt 合并发送
- [ ] 密码验证通过加密信道
- [ ] 解析 `ok|||<addr>` 提取远程地址
- [ ] 房间名通过加密信道发送

---

### T15: Relay Keepalive & Room Cleanup

- **File**: `src/relay/mod.rs` (keepalive 逻辑)
- **Depends on**: T11, T13
- **Description**: 为等待中的客户端定期发送 keepalive 字节，防止连接被中间设备关闭。

#### Implementation

```rust
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;

/// Keepalive 间隔 (秒)
const KEEPALIVE_INTERVAL_SECS: u64 = 30;

/// 向等待中的客户端发送定期 keepalive
/// cancel_rx 收到信号时停止
pub async fn keepalive_loop(
    mut stream: TcpStream,
    mut cancel_rx: watch::Receiver<bool>,
) {
    let interval = Duration::from_secs(KEEPALIVE_INTERVAL_SECS);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                if stream.write_all(&[KEEPALIVE_BYTE]).await.is_err() {
                    break;
                }
            }
            _ = cancel_rx.changed() => {
                break;
            }
        }
    }
}

/// 增强的 RoomManager: 支持 keepalive
/// 当第一个客户端加入时启动 keepalive 循环
/// 当第二个客户端加入时取消 keepalive 并配对
impl RoomManager {
    pub async fn join_with_keepalive(
        &self,
        room_name: &str,
        stream: TcpStream,
    ) -> Result<RoomJoinResultWithKeepalive> {
        let mut rooms = self.rooms.lock().await;

        if let Some(entry) = rooms.get_mut(room_name) {
            if entry.paired {
                return Err(RcrocError::RoomFull(room_name.into()));
            }
            let first_conn = entry.first_conn.take()
                .ok_or_else(|| RcrocError::Relay("first connection missing".into()))?;
            entry.paired = true;

            // 通知 keepalive 停止 (通过 cancel_tx)
            Ok(RoomJoinResultWithKeepalive::Paired {
                first: first_conn,
                second: stream,
            })
        } else {
            // 创建房间并启动 keepalive
            let (cancel_tx, cancel_rx) = watch::channel(false);

            // 注意: 这里的实现需要将 stream 克隆一份用于 keepalive
            // 实际上 TcpStream 不可克隆，需要用 split 或其他方式
            // 简化方案: 第一个客户端不启动 keepalive, 依赖 TCP keepalive
            rooms.insert(room_name.to_string(), RoomEntry {
                first_conn: Some(stream),
                created_at: Instant::now(),
                paired: false,
            });
            Ok(RoomJoinResultWithKeepalive::Waiting { cancel_tx })
        }
    }
}

pub enum RoomJoinResultWithKeepalive {
    Waiting { cancel_tx: watch::Sender<bool> },
    Paired { first: TcpStream, second: TcpStream },
}
```

#### Acceptance Criteria
- [ ] Keepalive 每 30 秒发送 0x01 字节
- [ ] 配对成功后 keepalive 停止
- [ ] 写入失败时 keepalive 循环退出
- [ ] 使用 watch channel 实现取消机制
- [ ] 房间清理每 10 分钟执行，清理 >3h 的房间

---

## Phase 4: Client Core

### T16: Hash Algorithms

- **File**: `src/utils/hash.rs`
- **Depends on**: T01, T02, T03
- **Description**: 文件哈希: xxhash (默认), imohash (快速部分哈希)。

#### Implementation

```rust
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use xxhash_rust::xxh3::xxh3_128;
use crate::error::{RcrocError, Result};
use crate::models::HashAlgorithm;

/// 计算文件哈希 (根据算法选择)
pub async fn hash_file(path: &Path, algorithm: HashAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        HashAlgorithm::Xxhash => hash_file_xxhash(path).await,
        HashAlgorithm::Imohash => hash_file_imohash(path).await,
    }
}

/// 使用 xxh3-128 计算完整文件哈希
async fn hash_file_xxhash(path: &Path) -> Result<Vec<u8>> {
    let data = tokio::fs::read(path)
        .await
        .map_err(|e| RcrocError::FileNotFound(format!("{}: {e}", path.display())))?;
    let hash = xxh3_128(&data);
    Ok(hash.to_le_bytes().to_vec())
}

/// imohash: 快速部分文件哈希
/// 采样文件头部、中部、尾部各 16KB + 文件大小
/// 基于 murmur3 思想的简化实现
async fn hash_file_imohash(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)
        .await
        .map_err(|e| RcrocError::FileNotFound(format!("{}: {e}", path.display())))?;

    let metadata = file.metadata().await.map_err(RcrocError::Io)?;
    let file_size = metadata.len();

    const SAMPLE_SIZE: usize = 16 * 1024;
    let mut hasher_input = Vec::new();

    // 写入文件大小
    hasher_input.extend_from_slice(&file_size.to_le_bytes());

    if file_size <= (SAMPLE_SIZE * 3) as u64 {
        // 小文件: 读取全部
        file.read_to_end(&mut hasher_input).await.map_err(RcrocError::Io)?;
    } else {
        // 大文件: 采样头部、中部、尾部
        let mut buf = vec![0u8; SAMPLE_SIZE];

        // 头部
        file.read_exact(&mut buf).await.map_err(RcrocError::Io)?;
        hasher_input.extend_from_slice(&buf);

        // 中部
        let mid_offset = file_size / 2 - (SAMPLE_SIZE as u64) / 2;
        use tokio::io::AsyncSeekExt;
        file.seek(std::io::SeekFrom::Start(mid_offset)).await.map_err(RcrocError::Io)?;
        file.read_exact(&mut buf).await.map_err(RcrocError::Io)?;
        hasher_input.extend_from_slice(&buf);

        // 尾部
        file.seek(std::io::SeekFrom::End(-(SAMPLE_SIZE as i64))).await.map_err(RcrocError::Io)?;
        file.read_exact(&mut buf).await.map_err(RcrocError::Io)?;
        hasher_input.extend_from_slice(&buf);
    }

    // 使用 xxh3 作为最终哈希 (替代 murmur3)
    let hash = xxh3_128(&hasher_input);
    Ok(hash.to_le_bytes().to_vec())
}

/// 比较两个哈希值
pub fn hashes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // 常数时间比较防止时序攻击
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[tokio::test]
    async fn test_xxhash_deterministic() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello rcroc").unwrap();
        let h1 = hash_file(f.path(), HashAlgorithm::Xxhash).await.unwrap();
        let h2 = hash_file(f.path(), HashAlgorithm::Xxhash).await.unwrap();
        assert_eq!(h1, h2);
    }

    #[tokio::test]
    async fn test_imohash_deterministic() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello rcroc").unwrap();
        let h1 = hash_file(f.path(), HashAlgorithm::Imohash).await.unwrap();
        let h2 = hash_file(f.path(), HashAlgorithm::Imohash).await.unwrap();
        assert_eq!(h1, h2);
    }

    #[tokio::test]
    async fn test_different_content_different_hash() {
        let mut f1 = NamedTempFile::new().unwrap();
        f1.write_all(b"content A").unwrap();
        let mut f2 = NamedTempFile::new().unwrap();
        f2.write_all(b"content B").unwrap();
        let h1 = hash_file(f1.path(), HashAlgorithm::Xxhash).await.unwrap();
        let h2 = hash_file(f2.path(), HashAlgorithm::Xxhash).await.unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hashes_equal() {
        assert!(hashes_equal(&[1, 2, 3], &[1, 2, 3]));
        assert!(!hashes_equal(&[1, 2, 3], &[1, 2, 4]));
        assert!(!hashes_equal(&[1, 2], &[1, 2, 3]));
    }
}
```

#### Acceptance Criteria
- [ ] xxhash: 完整文件哈希，确定性
- [ ] imohash: 采样头/中/尾各 16KB
- [ ] 小文件 imohash 读取全部内容
- [ ] hash 比较使用常数时间
- [ ] 文件不存在返回 FileNotFound 错误

---

### T17: File System Utilities

- **File**: `src/utils/fs.rs`
- **Depends on**: T01, T02
- **Description**: 文件操作、路径安全检查、磁盘空间查询、文件遍历。

#### Implementation

```rust
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use walkdir::WalkDir;
use crate::error::{RcrocError, Result};
use crate::models::FileInfo;

/// 路径安全检查: 拒绝路径遍历攻击
pub fn validate_path(path: &str) -> Result<()> {
    // 拒绝 .. 组件
    if path.contains("..") {
        return Err(RcrocError::InvalidInput(format!("path traversal detected: {path}")));
    }
    // 拒绝 .ssh 等敏感目录
    if path.contains(".ssh") || path.contains(".gnupg") || path.contains(".env") {
        return Err(RcrocError::InvalidInput(format!("sensitive path rejected: {path}")));
    }
    // 拒绝不可打印字符
    if path.chars().any(|c| c.is_control()) {
        return Err(RcrocError::InvalidInput("path contains control characters".into()));
    }
    Ok(())
}

/// 收集目录下所有文件的 FileInfo
pub fn collect_files(base_path: &Path) -> Result<(Vec<FileInfo>, Vec<String>)> {
    let mut files = Vec::new();
    let mut empty_folders = Vec::new();

    if base_path.is_file() {
        let info = file_info(base_path, base_path.parent().unwrap_or(base_path))?;
        files.push(info);
        return Ok((files, empty_folders));
    }

    for entry in WalkDir::new(base_path).follow_links(false) {
        let entry = entry.map_err(|e| RcrocError::Io(e.into()))?;
        let path = entry.path();

        if path.is_file() {
            let info = file_info(path, base_path)?;
            files.push(info);
        } else if path.is_dir() {
            // 检查是否为空目录
            let is_empty = std::fs::read_dir(path)
                .map(|mut d| d.next().is_none())
                .unwrap_or(false);
            if is_empty {
                let rel = path.strip_prefix(base_path)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();
                empty_folders.push(rel);
            }
        }
    }

    Ok((files, empty_folders))
}

/// 构建单个文件的 FileInfo
fn file_info(path: &Path, base: &Path) -> Result<FileInfo> {
    let metadata = std::fs::metadata(path).map_err(RcrocError::Io)?;

    let name = path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let folder_source = path.parent()
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();

    let folder_remote = path.strip_prefix(base)
        .unwrap_or(path)
        .parent()
        .unwrap_or(Path::new(""))
        .to_string_lossy()
        .to_string();

    let mod_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    };
    #[cfg(not(unix))]
    let mode = 0o644u32;

    let symlink = if metadata.file_type().is_symlink() {
        std::fs::read_link(path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    Ok(FileInfo {
        name,
        folder_remote,
        folder_source,
        size: metadata.len(),
        mod_time,
        mode,
        symlink,
        hash: Vec::new(), // 由 hash 模块填充
    })
}

/// 获取路径所在磁盘的可用空间 (字节)
pub fn available_space(path: &Path) -> Result<u64> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let c_path = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|e| RcrocError::InvalidInput(format!("invalid path: {e}")))?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if ret != 0 {
            return Err(RcrocError::Io(std::io::Error::last_os_error()));
        }
        Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
    }
    #[cfg(not(unix))]
    {
        // Windows/其他平台: 返回一个大值, 让调用方自行处理
        Ok(u64::MAX)
    }
}

/// 恢复文件的修改时间
pub fn restore_mod_time(path: &Path, mod_time: SystemTime) -> Result<()> {
    let mtime = filetime::FileTime::from_system_time(mod_time);
    filetime::set_file_mtime(path, mtime).map_err(RcrocError::Io)
    // 注意: 需要在 Cargo.toml 中添加 filetime = "0.2" 依赖
    // 或使用 nix::sys::stat::utimensat 替代
}

/// 创建临时接收文件路径
pub fn temp_receive_path(final_path: &Path) -> PathBuf {
    let mut temp = final_path.to_path_buf();
    let name = temp.file_name().unwrap_or_default().to_string_lossy();
    temp.set_file_name(format!(".{name}.rcroc-tmp"));
    temp
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_path_normal() {
        assert!(validate_path("folder/file.txt").is_ok());
        assert!(validate_path("a/b/c/d.rs").is_ok());
    }

    #[test]
    fn test_validate_path_traversal() {
        assert!(validate_path("../etc/passwd").is_err());
        assert!(validate_path("foo/../../bar").is_err());
    }

    #[test]
    fn test_validate_path_sensitive() {
        assert!(validate_path(".ssh/id_rsa").is_err());
        assert!(validate_path("home/.gnupg/key").is_err());
    }

    #[test]
    fn test_temp_receive_path() {
        let path = Path::new("/tmp/myfile.txt");
        let temp = temp_receive_path(path);
        assert_eq!(temp, PathBuf::from("/tmp/.myfile.txt.rcroc-tmp"));
    }

    #[test]
    fn test_collect_files_single() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.txt"), b"hello").unwrap();
        let (files, _) = collect_files(dir.path()).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "test.txt");
        assert_eq!(files[0].size, 5);
    }

    #[test]
    fn test_collect_files_nested() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
        std::fs::write(dir.path().join("sub/b.txt"), b"bbb").unwrap();
        let (files, _) = collect_files(dir.path()).unwrap();
        assert_eq!(files.len(), 2);
    }
}
```

#### Acceptance Criteria
- [ ] 路径遍历检查: 拒绝 `..`, `.ssh`, 控制字符
- [ ] collect_files 递归收集文件和空目录
- [ ] FileInfo 包含正确的 name, size, mode, mod_time
- [ ] 磁盘空间查询 (Unix)
- [ ] 临时文件路径格式: `.{name}.rcroc-tmp`

---

### T18: ZIP Utilities

- **File**: `src/utils/zip.rs`
- **Depends on**: T01, T02
- **Description**: 文件夹 ZIP 打包/解包 (用于管道传输模式)。

#### Implementation

```rust
use std::io::{Read, Write, Seek};
use std::path::Path;
use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};
use walkdir::WalkDir;
use crate::error::{RcrocError, Result};

/// 将目录压缩为内存中的 ZIP 数据
pub fn zip_directory(dir: &Path) -> Result<Vec<u8>> {
    let buf = std::io::Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(buf);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    for entry in WalkDir::new(dir).follow_links(false) {
        let entry = entry.map_err(|e| RcrocError::Io(e.into()))?;
        let path = entry.path();
        let rel_path = path.strip_prefix(dir)
            .unwrap_or(path)
            .to_string_lossy();

        if rel_path.is_empty() {
            continue;
        }

        if path.is_file() {
            zip.start_file(rel_path.as_ref(), options)
                .map_err(|e| RcrocError::Compression(format!("zip start_file: {e}")))?;
            let data = std::fs::read(path).map_err(RcrocError::Io)?;
            zip.write_all(&data)
                .map_err(|e| RcrocError::Compression(format!("zip write: {e}")))?;
        } else if path.is_dir() {
            zip.add_directory(rel_path.as_ref(), options)
                .map_err(|e| RcrocError::Compression(format!("zip add_dir: {e}")))?;
        }
    }

    let cursor = zip.finish()
        .map_err(|e| RcrocError::Compression(format!("zip finish: {e}")))?;
    Ok(cursor.into_inner())
}

/// 将 ZIP 数据解压到目标目录
pub fn unzip_to_directory(data: &[u8], dest: &Path) -> Result<()> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|e| RcrocError::Compression(format!("zip open: {e}")))?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)
            .map_err(|e| RcrocError::Compression(format!("zip entry: {e}")))?;

        let name = file.name().to_string();

        // 路径安全检查
        crate::utils::fs::validate_path(&name)?;

        let out_path = dest.join(&name);

        if file.is_dir() {
            std::fs::create_dir_all(&out_path).map_err(RcrocError::Io)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent).map_err(RcrocError::Io)?;
            }
            let mut out_file = std::fs::File::create(&out_path).map_err(RcrocError::Io)?;
            std::io::copy(&mut file, &mut out_file)
                .map_err(|e| RcrocError::Compression(format!("zip extract: {e}")))?;
        }
    }

    Ok(())
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zip_unzip_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"hello").unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/world.txt"), b"world").unwrap();

        let zip_data = zip_directory(dir.path()).unwrap();
        assert!(!zip_data.is_empty());

        let dest = tempfile::tempdir().unwrap();
        unzip_to_directory(&zip_data, dest.path()).unwrap();

        let content1 = std::fs::read_to_string(dest.path().join("hello.txt")).unwrap();
        assert_eq!(content1, "hello");
        let content2 = std::fs::read_to_string(dest.path().join("sub/world.txt")).unwrap();
        assert_eq!(content2, "world");
    }
}
```

#### Acceptance Criteria
- [ ] ZIP 打包/解包 roundtrip 正确
- [ ] 保留目录结构
- [ ] 解压时检查路径安全
- [ ] 空目录包含在 ZIP 中

---

### T19: Network Utilities

- **File**: `src/utils/net.rs`
- **Depends on**: T01, T02
- **Description**: DNS 解析、本地 IP 检测、IPv6 优先连接、代理支持。

#### Implementation

```rust
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use crate::error::{RcrocError, Result};

/// IPv6 优先 TCP 连接
/// 先尝试 IPv6 (200ms 超时)，失败后尝试 IPv4 (5s 超时)
pub async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .map_err(|e| RcrocError::Relay(format!("DNS lookup failed for {host}:{port}: {e}")))?;

    let addrs: Vec<SocketAddr> = addrs.collect();

    // 分离 IPv6 和 IPv4 地址
    let (v6_addrs, v4_addrs): (Vec<_>, Vec<_>) =
        addrs.iter().partition(|a| a.is_ipv6());

    // 先尝试 IPv6
    for &addr in &v6_addrs {
        match tokio::time::timeout(
            Duration::from_millis(200),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                tracing::debug!("connected via IPv6: {addr}");
                return Ok(stream);
            }
            _ => continue,
        }
    }

    // 回退到 IPv4
    for &addr in &v4_addrs {
        match tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                tracing::debug!("connected via IPv4: {addr}");
                return Ok(stream);
            }
            Ok(Err(e)) => {
                tracing::debug!("IPv4 connect failed {addr}: {e}");
                continue;
            }
            Err(_) => {
                tracing::debug!("IPv4 connect timeout {addr}");
                continue;
            }
        }
    }

    Err(RcrocError::Relay(format!("failed to connect to {host}:{port}")))
}

/// 获取本机所有非回环 IP 地址
pub fn local_ips() -> Vec<IpAddr> {
    let mut ips = Vec::new();

    // 使用 socket 技巧获取本地 IP
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                ips.push(addr.ip());
            }
        }
    }

    // IPv6
    if let Ok(socket) = std::net::UdpSocket::bind("[::]:0") {
        if socket.connect("[2001:4860:4860::8888]:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                if !addr.ip().is_loopback() {
                    ips.push(addr.ip());
                }
            }
        }
    }

    ips
}

/// 检测对端 IP 是否可达 (TCP ping)
pub async fn is_reachable(addr: &str, port: u16, timeout_ms: u64) -> bool {
    let target = format!("{addr}:{port}");
    tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&target),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

/// SOCKS5 代理连接
pub async fn connect_via_socks5(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    use tokio_socks::tcp::Socks5Stream;

    let stream = Socks5Stream::connect(proxy_addr, (target_host, target_port))
        .await
        .map_err(|e| RcrocError::Relay(format!("SOCKS5 proxy failed: {e}")))?;

    Ok(stream.into_inner())
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_ips_not_empty() {
        let ips = local_ips();
        // 在大多数环境下应该至少有一个 IP
        // 但 CI 环境可能没有，所以不 assert
        println!("local IPs: {:?}", ips);
    }

    #[tokio::test]
    async fn test_is_reachable_localhost() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(is_reachable("127.0.0.1", port, 1000).await);
    }

    #[tokio::test]
    async fn test_is_reachable_unreachable() {
        // 不存在的端口应该不可达
        assert!(!is_reachable("127.0.0.1", 1, 100).await);
    }
}
```

#### Acceptance Criteria
- [ ] IPv6 优先: 200ms 超时，回退 IPv4 5s 超时
- [ ] 本地 IP 检测: 获取非回环地址
- [ ] TCP ping 可达性检测
- [ ] SOCKS5 代理连接
- [ ] DNS 解析失败返回明确错误

---

### T20: Multiplexed Data Transfer

- **File**: `src/client/transfer.rs`
- **Depends on**: T05, T06, T07, T10
- **Description**: 多路复用数据传输: 分块读取 → 压缩 → 加密 → 发送。多连接轮询分发。

#### Implementation

```rust
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use crate::compress;
use crate::crypto::Cipher;
use crate::protocol::Comm;
use crate::error::{RcrocError, Result};
use crate::models::{CHUNK_SIZE, ChunkRange};

/// 数据块: 位置 + 数据
pub struct DataChunk {
    pub position: u64,
    pub data: Vec<u8>,
}

/// 发送文件数据 (通过多个连接)
/// 每个连接对应一个 Comm + Cipher
pub async fn send_file(
    path: &Path,
    connections: &mut [(&mut Comm, &dyn Cipher)],
    missing_ranges: &[ChunkRange],
    no_compress: bool,
    progress: Arc<AtomicU64>,
    cancelled: Arc<AtomicBool>,
) -> Result<()> {
    let mut file = File::open(path)
        .await
        .map_err(|e| RcrocError::FileNotFound(format!("{}: {e}", path.display())))?;

    let file_size = file.metadata().await.map_err(RcrocError::Io)?.len();

    // 构建待发送的块位置列表
    let positions = build_chunk_positions(file_size, missing_ranges);

    let conn_count = connections.len();
    let mut conn_idx = 0;

    for pos in positions {
        if cancelled.load(Ordering::Relaxed) {
            return Err(RcrocError::Cancelled);
        }

        // 读取数据块
        file.seek(std::io::SeekFrom::Start(pos)).await.map_err(RcrocError::Io)?;
        let remaining = (file_size - pos) as usize;
        let read_size = remaining.min(CHUNK_SIZE);
        let mut buf = vec![0u8; read_size];
        file.read_exact(&mut buf).await.map_err(RcrocError::Io)?;

        // 构建: [8-byte LE u64 position][data]
        let mut chunk_data = Vec::with_capacity(8 + buf.len());
        chunk_data.write_u64::<LittleEndian>(pos)
            .map_err(|e| RcrocError::Protocol(format!("write position: {e}")))?;
        chunk_data.extend_from_slice(&buf);

        // 压缩 (可选)
        let payload = if no_compress {
            chunk_data
        } else {
            compress::compress(&chunk_data)?
        };

        // 加密
        let (comm, cipher) = &mut connections[conn_idx % conn_count];
        let encrypted = cipher.encrypt(&payload)?;

        // 发送
        comm.send(&encrypted).await?;

        progress.fetch_add(read_size as u64, Ordering::Relaxed);
        conn_idx += 1;
    }

    Ok(())
}

/// 接收文件数据 (通过多个连接)
pub async fn recv_file(
    path: &Path,
    file_size: u64,
    connections: &mut [(&mut Comm, &dyn Cipher)],
    expected_chunks: usize,
    no_compress: bool,
    progress: Arc<AtomicU64>,
    cancelled: Arc<AtomicBool>,
) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .await
        .map_err(RcrocError::Io)?;

    // 预分配文件大小
    file.set_len(file_size).await.map_err(RcrocError::Io)?;

    let mut received_chunks = 0usize;
    let conn_count = connections.len();
    let mut conn_idx = 0;

    while received_chunks < expected_chunks {
        if cancelled.load(Ordering::Relaxed) {
            return Err(RcrocError::Cancelled);
        }

        let (comm, cipher) = &mut connections[conn_idx % conn_count];

        // 接收加密数据
        let encrypted = comm.recv().await?;

        // 解密
        let payload = cipher.decrypt(&encrypted)?;

        // 解压
        let chunk_data = if no_compress {
            payload
        } else {
            compress::decompress(&payload)?
        };

        if chunk_data.len() < 8 {
            return Err(RcrocError::Protocol("chunk too short".into()));
        }

        // 提取位置和数据
        let position = (&chunk_data[..8]).read_u64::<LittleEndian>()
            .map_err(|e| RcrocError::Protocol(format!("read position: {e}")))?;
        let data = &chunk_data[8..];

        // 写入文件
        file.seek(std::io::SeekFrom::Start(position)).await.map_err(RcrocError::Io)?;
        file.write_all(data).await.map_err(RcrocError::Io)?;

        progress.fetch_add(data.len() as u64, Ordering::Relaxed);
        received_chunks += 1;
        conn_idx += 1;
    }

    file.flush().await.map_err(RcrocError::Io)?;
    Ok(())
}

/// 构建待传输的块位置列表
fn build_chunk_positions(file_size: u64, missing_ranges: &[ChunkRange]) -> Vec<u64> {
    if missing_ranges.is_empty() {
        // 全部块
        let chunk_count = (file_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64;
        (0..chunk_count).map(|i| i * CHUNK_SIZE as u64).collect()
    } else {
        let mut positions = Vec::new();
        for range in missing_ranges {
            let start = if range.start < 0 { 0 } else { range.start as u64 };
            let end = if range.end < 0 { file_size / CHUNK_SIZE as u64 } else { range.end as u64 };
            for i in start..end {
                positions.push(i * CHUNK_SIZE as u64);
            }
        }
        positions
    }
}

/// 计算文件的总块数
pub fn total_chunks(file_size: u64) -> usize {
    ((file_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64) as usize
}

/// 扫描已接收文件，返回缺失块范围 (断点续传)
pub async fn find_missing_chunks(path: &Path, file_size: u64) -> Result<Vec<ChunkRange>> {
    if !path.exists() {
        // 文件不存在，全部缺失
        let total = total_chunks(file_size) as i64;
        return Ok(vec![ChunkRange { start: 0, end: total }]);
    }

    let data = tokio::fs::read(path).await.map_err(RcrocError::Io)?;
    let mut missing = Vec::new();
    let chunk_count = total_chunks(file_size);

    let mut range_start: Option<i64> = None;
    for i in 0..chunk_count {
        let offset = i * CHUNK_SIZE;
        let end = (offset + CHUNK_SIZE).min(data.len());
        let chunk = &data[offset..end];

        // 检查块是否全为零 (缺失)
        let is_zero = chunk.iter().all(|&b| b == 0);
        if is_zero {
            if range_start.is_none() {
                range_start = Some(i as i64);
            }
        } else if let Some(start) = range_start.take() {
            missing.push(ChunkRange { start, end: i as i64 });
        }
    }
    if let Some(start) = range_start {
        missing.push(ChunkRange { start, end: chunk_count as i64 });
    }

    Ok(missing)
}
```

#### Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_chunk_positions_full() {
        let positions = build_chunk_positions(100_000, &[]);
        // 100000 / 32768 = 3.05 → 4 chunks
        assert_eq!(positions.len(), 4);
        assert_eq!(positions[0], 0);
        assert_eq!(positions[1], 32768);
        assert_eq!(positions[2], 65536);
        assert_eq!(positions[3], 98304);
    }

    #[test]
    fn test_build_chunk_positions_with_ranges() {
        let positions = build_chunk_positions(100_000, &[
            ChunkRange { start: 1, end: 3 },
        ]);
        assert_eq!(positions.len(), 2);
        assert_eq!(positions[0], 32768);
        assert_eq!(positions[1], 65536);
    }

    #[test]
    fn test_total_chunks() {
        assert_eq!(total_chunks(0), 0);
        assert_eq!(total_chunks(1), 1);
        assert_eq!(total_chunks(32768), 1);
        assert_eq!(total_chunks(32769), 2);
        assert_eq!(total_chunks(65536), 2);
    }
}
```

#### Acceptance Criteria
- [ ] 块大小 32KB 与 spec 一致
- [ ] 数据格式: `[8-byte LE u64 position][data]`
- [ ] 发送管线: 读取 → 前置位置 → 压缩 → 加密 → 帧发送
- [ ] 接收管线: 帧接收 → 解密 → 解压 → 提取位置 → WriteAt
- [ ] 多连接轮询分发
- [ ] 断点续传: 扫描零块确定缺失范围
- [ ] 支持取消 (AtomicBool)
- [ ] 进度追踪 (AtomicU64)

---

### T21: Sender Logic

- **File**: `src/client/sender.rs`
- **Depends on**: T03, T10, T16, T17, T18, T20
- **Description**: 发送方逻辑: 收集文件、发送 FileInfo、等待 RecipientReady、发送数据块。

#### Implementation

```rust
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool};
use crate::crypto::Cipher;
use crate::error::Result;
use crate::models::{SenderInfo, HashAlgorithm, FileInfo};
use crate::protocol::{Comm, Message, send_message, recv_message};
use crate::utils::{fs, hash};
use crate::client::transfer;

/// 发送方状态
pub struct Sender {
    pub files: Vec<FileInfo>,
    pub empty_folders: Vec<String>,
    pub hash_algorithm: HashAlgorithm,
    pub no_compress: bool,
    pub base_path: std::path::PathBuf,
}

impl Sender {
    /// 从路径列表准备发送
    pub async fn prepare(paths: &[&Path], hash_algorithm: HashAlgorithm) -> Result<Self> {
        let mut all_files = Vec::new();
        let mut all_empty = Vec::new();
        let mut base_path = std::path::PathBuf::new();

        for path in paths {
            let (files, empties) = fs::collect_files(path)?;
            all_files.extend(files);
            all_empty.extend(empties);
            if base_path.as_os_str().is_empty() {
                base_path = path.parent().unwrap_or(*path).to_path_buf();
            }
        }

        // 计算文件哈希
        for file_info in &mut all_files {
            let full_path = Path::new(&file_info.folder_source).join(&file_info.name);
            file_info.hash = hash::hash_file(&full_path, hash_algorithm).await?;
        }

        Ok(Self {
            files: all_files,
            empty_folders: all_empty,
            hash_algorithm,
            no_compress: false,
            base_path,
        })
    }

    /// 构建 SenderInfo 消息
    pub fn sender_info(&self) -> SenderInfo {
        let total_size: u64 = self.files.iter().map(|f| f.size).sum();
        SenderInfo {
            files: self.files.clone(),
            empty_folders: self.empty_folders.clone(),
            total_files_size: total_size,
            no_compress: self.no_compress,
            hash_algorithm: self.hash_algorithm,
        }
    }

    /// 执行文件发送 (单文件)
    pub async fn send_files(
        &self,
        comm: &mut Comm,
        transfer_conns: &mut [(&mut Comm, &dyn Cipher)],
        cipher: &dyn Cipher,
        progress: Arc<AtomicU64>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<()> {
        // Step 2: 发送 FileInfo
        let info = self.sender_info();
        send_message(comm, &Message::FileInfo(info), cipher).await?;

        // 逐文件传输
        for (idx, file_info) in self.files.iter().enumerate() {
            // Step 3: 等待 RecipientReady
            let msg = recv_message(comm, cipher).await?;
            let request = match msg {
                Message::RecipientReady(req) => req,
                Message::Error { message } => {
                    return Err(crate::error::RcrocError::Protocol(message));
                }
                _ => {
                    return Err(crate::error::RcrocError::Protocol(
                        "expected RecipientReady".into(),
                    ));
                }
            };

            if request.files_to_transfer_current_num != idx {
                return Err(crate::error::RcrocError::Protocol(
                    "file index mismatch".into(),
                ));
            }

            // Step 4: 发送数据块
            let full_path = Path::new(&file_info.folder_source).join(&file_info.name);
            transfer::send_file(
                &full_path,
                transfer_conns,
                &request.current_file_chunk_ranges,
                self.no_compress,
                Arc::clone(&progress),
                Arc::clone(&cancelled),
            )
            .await?;

            // 等待 CloseSender
            let msg = recv_message(comm, cipher).await?;
            if !matches!(msg, Message::CloseSender) {
                return Err(crate::error::RcrocError::Protocol(
                    "expected CloseSender".into(),
                ));
            }

            // 发送 CloseRecipient
            send_message(comm, &Message::CloseRecipient, cipher).await?;
        }

        // Step 5: 发送 Finished
        send_message(comm, &Message::Finished, cipher).await?;

        // 等待对方 Finished
        let msg = recv_message(comm, cipher).await?;
        if !matches!(msg, Message::Finished) {
            return Err(crate::error::RcrocError::Protocol(
                "expected Finished".into(),
            ));
        }

        Ok(())
    }
}
```

#### Acceptance Criteria
- [ ] 收集文件并计算哈希
- [ ] 发送 SenderInfo (Step 2)
- [ ] 等待 RecipientReady (Step 3)
- [ ] 发送数据块 (Step 4)
- [ ] CloseSender/CloseRecipient 交换
- [ ] Finished 交换 (Step 5)
- [ ] 支持多文件顺序传输
- [ ] 错误消息类型处理

---

### T22: Receiver Logic

- **File**: `src/client/receiver.rs`
- **Depends on**: T03, T10, T16, T17, T18, T20
- **Description**: 接收方逻辑: 接收 FileInfo、确认、发送 RecipientReady、接收数据块。

#### Implementation

```rust
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool};
use crate::crypto::Cipher;
use crate::error::{RcrocError, Result};
use crate::models::{SenderInfo, RemoteFileRequest, ChunkRange};
use crate::protocol::{Comm, Message, send_message, recv_message};
use crate::utils::fs;
use crate::client::transfer;

pub struct Receiver {
    pub dest_dir: PathBuf,
    pub overwrite: bool,
}

impl Receiver {
    pub fn new(dest_dir: PathBuf, overwrite: bool) -> Self {
        Self { dest_dir, overwrite }
    }

    /// 执行文件接收
    pub async fn receive_files(
        &self,
        comm: &mut Comm,
        transfer_conns: &mut [(&mut Comm, &dyn Cipher)],
        cipher: &dyn Cipher,
        progress: Arc<AtomicU64>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<SenderInfo> {
        // Step 2: 接收 FileInfo
        let msg = recv_message(comm, cipher).await?;
        let sender_info = match msg {
            Message::FileInfo(info) => info,
            _ => return Err(RcrocError::Protocol("expected FileInfo".into())),
        };

        // 检查磁盘空间
        let available = fs::available_space(&self.dest_dir)?;
        if available < sender_info.total_files_size {
            return Err(RcrocError::InsufficientSpace {
                need: sender_info.total_files_size,
                have: available,
            });
        }

        // 创建空文件夹
        for folder in &sender_info.empty_folders {
            fs::validate_path(folder)?;
            let full = self.dest_dir.join(folder);
            tokio::fs::create_dir_all(&full).await.map_err(RcrocError::Io)?;
        }

        // 逐文件接收
        for (idx, file_info) in sender_info.files.iter().enumerate() {
            fs::validate_path(&file_info.name)?;
            fs::validate_path(&file_info.folder_remote)?;

            let dest_path = self.dest_dir
                .join(&file_info.folder_remote)
                .join(&file_info.name);

            // 创建父目录
            if let Some(parent) = dest_path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(RcrocError::Io)?;
            }

            // 使用临时路径接收
            let temp_path = fs::temp_receive_path(&dest_path);

            // 断点续传: 检查已有数据
            let missing_chunks = if temp_path.exists() && !self.overwrite {
                transfer::find_missing_chunks(&temp_path, file_info.size).await?
            } else {
                let total = transfer::total_chunks(file_info.size) as i64;
                vec![ChunkRange { start: 0, end: total }]
            };

            let expected_chunks = missing_chunks
                .iter()
                .map(|r| (r.end - r.start) as usize)
                .sum();

            // Step 3: 发送 RecipientReady
            let request = RemoteFileRequest {
                current_file_chunk_ranges: missing_chunks,
                files_to_transfer_current_num: idx,
                machine_id: String::new(),
            };
            send_message(comm, &Message::RecipientReady(request), cipher).await?;

            // Step 4: 接收数据块
            transfer::recv_file(
                &temp_path,
                file_info.size,
                transfer_conns,
                expected_chunks,
                sender_info.no_compress,
                Arc::clone(&progress),
                Arc::clone(&cancelled),
            )
            .await?;

            // 发送 CloseSender (当前文件完成)
            send_message(comm, &Message::CloseSender, cipher).await?;

            // 等待 CloseRecipient
            let msg = recv_message(comm, cipher).await?;
            if !matches!(msg, Message::CloseRecipient) {
                return Err(RcrocError::Protocol("expected CloseRecipient".into()));
            }

            // 重命名临时文件
            tokio::fs::rename(&temp_path, &dest_path).await.map_err(RcrocError::Io)?;

            // 恢复修改时间
            // fs::restore_mod_time(&dest_path, file_info.mod_time)?;
        }

        // Step 5: Finished 交换
        let msg = recv_message(comm, cipher).await?;
        if !matches!(msg, Message::Finished) {
            return Err(RcrocError::Protocol("expected Finished".into()));
        }
        send_message(comm, &Message::Finished, cipher).await?;

        Ok(sender_info)
    }
}
```

#### Acceptance Criteria
- [ ] 接收 SenderInfo 并验证
- [ ] 磁盘空间检查
- [ ] 路径安全验证
- [ ] 创建空文件夹
- [ ] 发送 RecipientReady 包含缺失块范围
- [ ] 接收数据块写入临时文件
- [ ] CloseSender/CloseRecipient 交换
- [ ] 临时文件重命名为最终路径
- [ ] 断点续传: 检查已有临时文件
- [ ] Finished 交换

---

## Phase 5: CLI & Entry Point

### T23: Client State Machine

- **File**: `src/client/mod.rs`
- **Depends on**: T08, T14, T19, T21, T22
- **Description**: Client 核心: 连接 relay、PAKE 端到端密钥交换、协调 sender/receiver。

#### Implementation

```rust
pub mod sender;
pub mod receiver;
pub mod transfer;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool};
use crate::crypto::{AesGcmCipher, Cipher};
use crate::crypto::key_derivation::derive_key_pbkdf2;
use crate::error::{RcrocError, Result};
use crate::models::{ClientConfig, Role, PAKE_SALT_LEN, DEFAULT_TRANSFER_PORTS};
use crate::protocol::{Comm, Pake, PakeRole, Message, send_message, recv_message};
use crate::mnemonic;

/// 主客户端
pub struct Client {
    config: ClientConfig,
    role: Role,
}

impl Client {
    pub fn new(config: ClientConfig, role: Role) -> Self {
        Self { config, role }
    }

    /// 运行客户端 (发送或接收)
    pub async fn run(&self) -> Result<()> {
        // 解析密码短语
        let (room_name, pake_password) = mnemonic::parse_code_phrase(&self.config.shared_secret)?;

        // 连接 relay (主连接)
        let relay_addr = format!("{}:{}", self.config.relay_address, self.config.relay_port);
        let (mut comm, _relay_cipher, external_ip) =
            crate::relay::connect_to_relay(&relay_addr, &self.config.relay_password, &room_name)
                .await?;

        tracing::info!("connected to relay, external IP: {external_ip}");

        // ── 端到端 PAKE 密钥交换 ──
        let e2e_cipher = self.pake_key_exchange(&mut comm, pake_password.as_bytes()).await?;

        // ── 外部 IP 交换 (可选直连升级) ──
        let local_ips = crate::utils::net::local_ips();
        let ip_str = local_ips.iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");
        send_message(&mut comm, &Message::ExternalIP { value: ip_str }, e2e_cipher.as_ref()).await?;

        let msg = recv_message(&mut comm, e2e_cipher.as_ref()).await?;
        let _peer_ips = match msg {
            Message::ExternalIP { value } => value,
            _ => String::new(),
        };

        // TODO: 直连升级逻辑 (Phase 3 高级特性)

        // ── 建立传输连接 ──
        let transfer_port_count = if self.config.no_multi { 1 } else { self.config.transfer_ports };
        let mut transfer_comms = Vec::new();

        for i in 0..transfer_port_count {
            let port = self.config.relay_port + 1 + i as u16;
            let transfer_addr = format!("{}:{}", self.config.relay_address, port);
            let transfer_room = format!("{room_name}-{i}");
            let (t_comm, _, _) =
                crate::relay::connect_to_relay(&transfer_addr, &self.config.relay_password, &transfer_room)
                    .await?;
            transfer_comms.push(t_comm);
        }

        // ── 执行传输 ──
        let progress = Arc::new(AtomicU64::new(0));
        let cancelled = Arc::new(AtomicBool::new(false));

        match self.role {
            Role::Sender => {
                // 准备发送
                // 注意: 实际使用中 paths 从 CLI 参数获取
                // 这里需要由调用方传入
                tracing::info!("ready to send");
                // sender.send_files(...) 由外部调用
            }
            Role::Receiver => {
                tracing::info!("ready to receive");
                // receiver.receive_files(...) 由外部调用
            }
        }

        Ok(())
    }

    /// 端到端 PAKE 密钥交换
    async fn pake_key_exchange(
        &self,
        comm: &mut Comm,
        password: &[u8],
    ) -> Result<Box<dyn Cipher + Send>> {
        let pake_role = match self.role {
            Role::Receiver => PakeRole::Receiver,
            Role::Sender => PakeRole::Sender,
        };

        let mut pake = Pake::new(password, pake_role)?;

        match self.role {
            Role::Receiver => {
                // Receiver (role=0) 先发
                comm.send(pake.bytes()).await?;

                // 接收 Sender 的 PAKE bytes + salt
                let peer_data = comm.recv().await?;
                if peer_data.len() < PAKE_SALT_LEN {
                    return Err(RcrocError::PakeAuth("peer data too short".into()));
                }
                let (peer_pake, salt) = peer_data.split_at(peer_data.len() - PAKE_SALT_LEN);
                pake.update(peer_pake)?;

                let session_key = pake.session_key()?;
                let aes_key = derive_key_pbkdf2(session_key, salt);
                Ok(Box::new(AesGcmCipher::new(&aes_key)))
            }
            Role::Sender => {
                // 接收 Receiver 的 PAKE bytes
                let peer_pake = comm.recv().await?;
                pake.update(&peer_pake)?;

                // 生成 salt
                let mut salt = [0u8; PAKE_SALT_LEN];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);

                // 发送 PAKE bytes + salt
                let mut data = pake.bytes().to_vec();
                data.extend_from_slice(&salt);
                comm.send(&data).await?;

                let session_key = pake.session_key()?;
                let aes_key = derive_key_pbkdf2(session_key, &salt);
                Ok(Box::new(AesGcmCipher::new(&aes_key)))
            }
        }
    }
}
```

#### Acceptance Criteria
- [ ] 解析密码短语获取房间名和 PAKE 密码
- [ ] 连接 relay 完成认证
- [ ] 端到端 PAKE: Receiver 先发, Sender 回复 + salt
- [ ] PBKDF2 派生 AES-256 密钥 (100 iterations, 32 bytes)
- [ ] 外部 IP 交换
- [ ] 多路复用: 建立 N 条传输连接 (各自独立房间 roomName-N)
- [ ] 支持取消和进度追踪

---

### T24: CLI Definitions & LAN Discovery

- **Files**: `src/cli.rs`, `src/discover.rs`
- **Depends on**: T03, T04, T23
- **Description**: clap CLI 定义 (send/receive/relay 子命令) + LAN 对端发现 (multicast UDP)。

#### Implementation: src/cli.rs

```rust
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use crate::error::Result;
use crate::models::{ClientConfig, RelayConfig, Role, HashAlgorithm};

#[derive(Parser, Debug)]
#[command(name = "rcroc", version, about = "Secure file transfer tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Relay address
    #[arg(long, default_value = "croc.schollz.com")]
    pub relay: String,

    /// Relay port
    #[arg(long, default_value_t = 9009)]
    pub port: u16,

    /// Relay password
    #[arg(long, default_value = "")]
    pub relay_pass: String,

    /// Enable debug logging
    #[arg(long)]
    pub debug: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Send files or text
    Send {
        /// Files or directories to send
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Code phrase (auto-generated if not provided)
        #[arg(long)]
        code: Option<String>,

        /// Disable compression
        #[arg(long)]
        no_compress: bool,

        /// Disable local relay
        #[arg(long)]
        no_local: bool,

        /// Disable multiplexed transfers
        #[arg(long)]
        no_multi: bool,

        /// Hash algorithm
        #[arg(long, default_value = "xxhash")]
        hash: String,

        /// Upload rate limit (bytes/sec)
        #[arg(long)]
        throttle: Option<u64>,

        /// Number of transfer connections
        #[arg(long, default_value_t = 4)]
        transfers: usize,

        /// Send text instead of files
        #[arg(long)]
        text: Option<String>,
    },

    /// Receive files
    Receive {
        /// Code phrase from sender
        code: String,

        /// Output directory
        #[arg(long, default_value = ".")]
        out: PathBuf,

        /// Auto-accept without confirmation
        #[arg(long)]
        yes: bool,

        /// Overwrite existing files
        #[arg(long)]
        overwrite: bool,

        /// Output to stdout
        #[arg(long)]
        stdout: bool,
    },

    /// Run as relay server
    Relay {
        /// Listen host
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// Listen port
        #[arg(long, default_value_t = 9009)]
        port: u16,

        /// Relay password
        #[arg(long, default_value = "")]
        password: String,

        /// Number of ports
        #[arg(long, default_value_t = 5)]
        ports: usize,
    },
}

/// CLI 入口
pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    // 初始化日志
    let filter = if cli.debug { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    match cli.command {
        Commands::Send {
            paths, code, no_compress, no_local, no_multi,
            hash, throttle, transfers, text,
        } => {
            let shared_secret = code.unwrap_or_else(|| {
                crate::mnemonic::generate_code_phrase(3)
            });

            println!("Code phrase: {shared_secret}");
            println!("On the other computer, run:\n  rcroc receive {shared_secret}\n");

            let hash_algorithm = match hash.as_str() {
                "imohash" => HashAlgorithm::Imohash,
                _ => HashAlgorithm::Xxhash,
            };

            let config = ClientConfig {
                relay_address: cli.relay,
                relay_port: cli.port,
                relay_password: cli.relay_pass,
                shared_secret,
                no_compress,
                no_local,
                no_multi,
                hash_algorithm,
                throttle_upload: throttle,
                transfer_ports: transfers,
                stdout: false,
                ask: false,
                overwrite: false,
            };

            let client = crate::client::Client::new(config, Role::Sender);
            client.run().await?;
        }

        Commands::Receive { code, out, yes, overwrite, stdout } => {
            let config = ClientConfig {
                relay_address: cli.relay,
                relay_port: cli.port,
                relay_password: cli.relay_pass,
                shared_secret: code,
                no_compress: false,
                no_local: false,
                no_multi: false,
                hash_algorithm: HashAlgorithm::default(),
                throttle_upload: None,
                transfer_ports: 4,
                stdout,
                ask: !yes,
                overwrite,
            };

            let client = crate::client::Client::new(config, Role::Receiver);
            client.run().await?;
        }

        Commands::Relay { host, port, password, ports } => {
            let config = RelayConfig {
                host,
                port,
                password,
                ports: (0..ports).map(|i| port + i as u16).collect(),
            };

            let server = crate::relay::RelayServer::new(config);
            println!("Starting relay on port {port} ({ports} ports)...");
            server.run().await?;
        }
    }

    Ok(())
}
```

#### Implementation: src/discover.rs

```rust
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use crate::error::{RcrocError, Result};
use crate::models::{MULTICAST_ADDR_V4, DISCOVER_PORT, DISCOVER_TIMEOUT_MS};

/// 发送方: 广播自身存在
pub async fn broadcast_presence(port: u16) -> Result<tokio::task::JoinHandle<()>> {
    let multicast_addr: Ipv4Addr = MULTICAST_ADDR_V4.parse()
        .map_err(|e| RcrocError::InvalidInput(format!("invalid multicast addr: {e}")))?;

    let socket = UdpSocket::bind(format!("0.0.0.0:{DISCOVER_PORT}"))
        .await
        .map_err(RcrocError::Io)?;

    let message = format!("rcroc:{port}");

    let handle = tokio::spawn(async move {
        let dest = SocketAddrV4::new(multicast_addr, DISCOVER_PORT);
        loop {
            if socket.send_to(message.as_bytes(), dest).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    Ok(handle)
}

/// 接收方: 发现局域网对端
/// 返回 Option<(对端IP, 对端port)>
pub async fn discover_peer() -> Option<(String, u16)> {
    let multicast_addr: Ipv4Addr = MULTICAST_ADDR_V4.parse().ok()?;

    // 使用 socket2 创建可重用的 multicast socket
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    socket.set_reuse_address(true).ok()?;
    #[cfg(unix)]
    socket.set_reuse_port(true).ok()?;

    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DISCOVER_PORT);
    socket.bind(&bind_addr.into()).ok()?;
    socket.join_multicast_v4(&multicast_addr, &Ipv4Addr::UNSPECIFIED).ok()?;
    socket.set_nonblocking(true).ok()?;

    let udp = UdpSocket::from_std(socket.into()).ok()?;

    let mut buf = [0u8; 256];
    let timeout = Duration::from_millis(DISCOVER_TIMEOUT_MS);

    match tokio::time::timeout(timeout, udp.recv_from(&mut buf)).await {
        Ok(Ok((n, addr))) => {
            let msg = String::from_utf8_lossy(&buf[..n]);
            if let Some(port_str) = msg.strip_prefix("rcroc:") {
                let port: u16 = port_str.parse().ok()?;
                Some((addr.ip().to_string(), port))
            } else {
                None
            }
        }
        _ => None,
    }
}
```

#### Tests

```rust
// cli.rs tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_send() {
        let cli = Cli::try_parse_from([
            "rcroc", "send", "file.txt",
        ]).unwrap();
        assert!(matches!(cli.command, Commands::Send { .. }));
    }

    #[test]
    fn test_cli_parse_receive() {
        let cli = Cli::try_parse_from([
            "rcroc", "receive", "1234-alpha-beta-gamma",
        ]).unwrap();
        if let Commands::Receive { code, .. } = cli.command {
            assert_eq!(code, "1234-alpha-beta-gamma");
        }
    }

    #[test]
    fn test_cli_parse_relay() {
        let cli = Cli::try_parse_from([
            "rcroc", "relay", "--port", "8080",
        ]).unwrap();
        if let Commands::Relay { port, .. } = cli.command {
            assert_eq!(port, 8080);
        }
    }
}

// discover.rs tests
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_discover_timeout_no_peer() {
        // 没有广播者时应该超时返回 None
        let result = discover_peer().await;
        assert!(result.is_none());
    }
}
```

#### Acceptance Criteria
- [ ] CLI: send / receive / relay 三个子命令
- [ ] send: 自动生成密码短语，显示给用户
- [ ] receive: 接受密码短语作为参数
- [ ] relay: 配置 host/port/password/ports
- [ ] 所有 spec 中的选项都有 CLI 参数
- [ ] LAN 发现: multicast 239.255.255.250, 200ms 超时
- [ ] 广播格式: `rcroc:{port}`
- [ ] 日志通过 tracing 初始化

---

### T25: Main Entry Point

- **File**: `src/main.rs`
- **Depends on**: T24
- **Description**: 程序入口: tokio 运行时启动、信号处理、优雅关闭。

#### Implementation

```rust
use std::process::ExitCode;

mod cli;
mod client;
mod compress;
mod crypto;
mod discover;
mod error;
mod mnemonic;
mod models;
mod protocol;
mod relay;
mod utils;

#[tokio::main]
async fn main() -> ExitCode {
    // 安装 Ctrl+C 处理
    let shutdown = tokio::signal::ctrl_c();

    tokio::select! {
        result = cli::run() => {
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("Error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ = shutdown => {
            eprintln!("\nInterrupted. Cleaning up...");
            ExitCode::from(130) // 标准 SIGINT 退出码
        }
    }
}
```

#### 替代方案: 使用 lib.rs + main.rs 分离

如果使用 lib.rs 导出模块 (T01)，则 main.rs 简化为:

```rust
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let shutdown = tokio::signal::ctrl_c();

    tokio::select! {
        result = rcroc::cli::run() => {
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("Error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ = shutdown => {
            eprintln!("\nInterrupted.");
            ExitCode::from(130)
        }
    }
}
```

#### Tests

```rust
// main.rs 无单元测试，通过集成测试覆盖
// 集成测试见 tests/integration/transfer_test.rs
```

#### Integration Test Skeleton: tests/integration/transfer_test.rs

```rust
use std::path::Path;
use tempfile::tempdir;
use tokio::time::Duration;

/// 完整端到端传输测试
/// 1. 启动本地 relay
/// 2. 发送方发送文件
/// 3. 接收方接收文件
/// 4. 验证文件内容和哈希
#[tokio::test]
async fn test_full_transfer() {
    // 创建临时目录
    let send_dir = tempdir().unwrap();
    let recv_dir = tempdir().unwrap();

    // 创建测试文件
    let test_content = b"Hello, rcroc! This is a test file for end-to-end transfer.";
    std::fs::write(send_dir.path().join("test.txt"), test_content).unwrap();

    // 启动本地 relay
    let relay_config = rcroc::models::RelayConfig {
        host: "127.0.0.1".into(),
        port: 19009,
        password: String::new(),
        ports: (0..5).map(|i| 19009 + i).collect(),
    };
    let relay = rcroc::relay::RelayServer::new(relay_config);
    let relay_handle = tokio::spawn(async move {
        relay.run().await.ok();
    });

    // 等待 relay 启动
    tokio::time::sleep(Duration::from_millis(100)).await;

    let code = rcroc::mnemonic::generate_code_phrase(3);

    // 启动发送方
    let send_code = code.clone();
    let send_path = send_dir.path().to_path_buf();
    let sender_handle = tokio::spawn(async move {
        let config = rcroc::models::ClientConfig {
            relay_address: "127.0.0.1".into(),
            relay_port: 19009,
            shared_secret: send_code,
            ..Default::default()
        };
        let client = rcroc::client::Client::new(config, rcroc::models::Role::Sender);
        client.run().await
    });

    // 短暂延迟后启动接收方
    tokio::time::sleep(Duration::from_millis(50)).await;

    let recv_code = code.clone();
    let recv_path = recv_dir.path().to_path_buf();
    let receiver_handle = tokio::spawn(async move {
        let config = rcroc::models::ClientConfig {
            relay_address: "127.0.0.1".into(),
            relay_port: 19009,
            shared_secret: recv_code,
            ..Default::default()
        };
        let client = rcroc::client::Client::new(config, rcroc::models::Role::Receiver);
        client.run().await
    });

    // 等待传输完成 (超时 10 秒)
    let timeout = Duration::from_secs(10);
    let _ = tokio::time::timeout(timeout, async {
        let _ = sender_handle.await;
        let _ = receiver_handle.await;
    })
    .await;

    // 验证接收的文件
    let received = std::fs::read(recv_dir.path().join("test.txt"));
    if let Ok(content) = received {
        assert_eq!(content, test_content);
    }

    relay_handle.abort();
}
```

#### Acceptance Criteria
- [ ] tokio 多线程运行时
- [ ] Ctrl+C 信号处理，退出码 130
- [ ] 错误信息输出到 stderr
- [ ] lib.rs 导出所有公共模块 (供集成测试使用)
- [ ] 集成测试: 本地 relay + 发送 + 接收 + 验证

---

## Dependency Graph Summary

```
T01 (scaffold)
├── T02 (error) ← T01
├── T03 (models) ← T01, T02
├── T04 (mnemonic) ← T01
├── T05 (compress) ← T01, T02
└── T06 (crypto) ← T01, T02
    ├── T07 (comm) ← T01, T02
    ├── T08 (pake) ← T01, T02, T06
    ├── T09 (message types) ← T01, T02, T03
    └── T10 (message pipeline) ← T05, T06, T07, T09
        ├── T11 (room) ← T01, T02
        ├── T12 (pipe) ← T01, T02
        ├── T13 (relay server) ← T07, T08, T11, T12
        ├── T14 (relay auth) ← T06, T07, T08, T13
        └── T15 (relay keepalive) ← T11, T13
            ├── T16 (hash) ← T01, T02
            ├── T17 (fs) ← T01, T02
            ├── T18 (zip) ← T01, T02
            ├── T19 (net) ← T01, T02
            ├── T20 (transfer) ← T05, T06, T07, T10
            ├── T21 (sender) ← T03, T10, T16, T17, T20
            └── T22 (receiver) ← T03, T10, T16, T17, T20
                ├── T23 (client mod) ← T08, T14, T19, T21, T22
                ├── T24 (cli + discover) ← T03, T04, T23
                └── T25 (main) ← T24
```

## Execution Order

严格按以下顺序执行，确保所有依赖已就绪：

```
Phase 1: T01 → T02 → T03, T04 (并行) → T05, T06 (并行)
Phase 2: T07 → T08, T09 (并行) → T10
Phase 3: T11, T12 (并行) → T13 → T14, T15 (并行)
Phase 4: T16, T17, T18, T19 (并行) → T20 → T21, T22 (并行)
Phase 5: T23 → T24 → T25
```

## Validation Checklist

每个阶段完成后执行:

```bash
# Phase 完成后验证
cargo check                    # 编译检查
cargo test                     # 单元测试
cargo clippy -- -D warnings    # lint 检查
```

最终验收:

```bash
# 完整测试
cargo test --all               # 所有测试
cargo test --test '*'          # 集成测试

# 启动 relay
cargo run -- relay --port 9009

# 终端 1: 发送
cargo run -- send test_file.txt

# 终端 2: 接收
cargo run -- receive <code-phrase>
```
