# rcroc

Rust 实现的 croc 风格文件传输工具。

## 已实现能力

- `relay` 中继服务（房间匹配 + 双向 pipe）
- `send` / `receive` 端到端加密传输（P-256 ECDH + PBKDF2 + AES-256-GCM）
- `Comm` 帧协议：`magic("croc") + len(le u32) + payload`
- 多文件/目录传输（包含空目录）
- 断点续传（接收端 sidecar 清单，按缺失块回传请求）
- 多路复用数据连接（`--transfers`）
- LAN 发现（multicast 广播/发现 relay 地址）
- LAN 直连升级（发送端自动启动本地 relay，发现成功后自动绕过远端 relay）
- 代理支持：SOCKS5、HTTP CONNECT（`--proxy`）
- 多哈希算法与传输后校验（`sha256` / `xxh3`）
- `.gitignore` 过滤（目录发送时遵循 gitignore 规则）
- 数据包可选 `DEFLATE` 压缩
- 密钥支持 `--secret` 或环境变量 `CROC_SECRET`

## 快速开始

```bash
cargo build
```

启动 relay：

```bash
cargo run -- relay --listen 0.0.0.0:9009 --relay-password pass
```

接收端：

```bash
cargo run -- receive \
  --secret 1234-acorn-amber-anchor \
  --relay 127.0.0.1:9009 \
  --relay-password pass \
  --out ./downloads \
  --transfers 4 \
  --resume
```

发送端（多路径）：

```bash
cargo run -- send ./file1 ./dirA ./emptyDir \
  --secret 1234-acorn-amber-anchor \
  --relay 127.0.0.1:9009 \
  --relay-password pass \
  --transfers 4 \
  --hash-algorithm sha256
```

## LAN 发现

发送端开启广播：

```bash
cargo run -- send ./file1 --secret ... --relay 192.168.1.10:9009 --lan-discovery
```

接收端开启发现（先尝试发现，失败后回落到 `--relay`）：

```bash
cargo run -- receive --secret ... --relay 127.0.0.1:9009 --lan-discovery --discover-timeout 5
```

说明：
- 发送端在 `--lan-discovery` 下会自动启动本地 relay（随机端口）并广播该地址。
- 接收端优先连接发现到的本地 relay，失败时回退到 `--relay` 指定地址。
- 发送端会同时等待本地/远端候选连接，谁先匹配就使用谁，数据通道跟随该路径。

## 代理

```bash
# HTTP CONNECT
cargo run -- send ./file1 --secret ... --relay host:9009 --proxy http://127.0.0.1:3128

# SOCKS5
cargo run -- receive --secret ... --relay host:9009 --proxy socks5://127.0.0.1:1080
```

## 哈希校验

- 发送端在 `TransferPlan` 中携带每个文件的 hash。
- 接收端在文件完成后重新计算 hash 并比对，不一致则报错并保留续传状态。
- 当断点续传遇到“本地文件大小完整但内容错误”时，会先发现 hash 不一致，再自动请求全量重传该文件。

## .gitignore 过滤

- 发送目录时会读取并遵循目录层级中的 `.gitignore` 规则。
- 被忽略的文件/目录不会进入传输计划。
- 显式传入的单文件路径仍会发送（即使它可能被某个目录规则忽略）。

## 目录

- `src/protocol/*`：帧协议、消息编解码、密钥交换
- `src/crypto/*`：AES-GCM + PBKDF2
- `src/relay/mod.rs`：房间管理与 pipe
- `src/client/sender.rs`：发送流程（计划/请求/多路数据）
- `src/client/receiver.rs`：接收流程（缺块请求/恢复写入）
- `src/client/resume.rs`：断点续传状态持久化
- `src/discover.rs`：LAN 广播与发现
- `src/net.rs`：直连/代理连接

## 已知限制

- 当前是 rcroc 内部协议互通，不与原版 Go croc 完全互操作
- 未实现原版 PAKE2/SIEC 兼容（按你的要求保持无需兼容）
- 尚未实现：限速、QR、SOCKS5/HTTP 认证头
