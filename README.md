# rcroc

Rust 实现的 croc 风格文件传输工具（rcroc 协议）。

## 1 分钟上手

先启动 relay（服务端）：

```bash
rcroc relay --listen 0.0.0.0:9009
```

发送端：

```bash
rcroc send /path/to/file --relay 107.174.204.124:9009
```

发送端会输出类似：

```text
Code is: fLuOQ4XY

On the other computer run

rcroc fLuOQ4XY --relay 107.174.204.124:9009
```

接收端（简写）：

```bash
rcroc fLuOQ4XY --relay 107.174.204.124:9009
```

也支持完整写法：

```bash
rcroc receive --secret fLuOQ4XY --relay 107.174.204.124:9009
```

## 默认行为（无需手动写）

- 默认启用 LAN 探测与局域网数据通道升级（可自动绕过远端 relay 走内网）
- 默认 `--transfers 4`
- 默认 `--hash-algorithm xxh3`
- 默认 `--relay-password pass`
- 默认接收目录 `--out .`

所以日常命令不需要写这些默认参数。

## 进度显示

- 发送端：每个文件显示 `Sending ...` 进度条、百分比、吞吐速率。
- 接收端：每个文件显示 `Receiving ...` 进度条、百分比、吞吐速率。

## 常用场景

发送目录：

```bash
rcroc send ./my-dir --relay 107.174.204.124:9009
```

指定接收目录：

```bash
rcroc fLuOQ4XY --relay 107.174.204.124:9009 --out /tmp/downloads
```

关闭 LAN 探测（强制仅走 relay）：

```bash
rcroc send ./file.bin --relay 107.174.204.124:9009 --no-lan-discovery
```

自定义 relay 密码（两端必须一致）：

```bash
rcroc send ./file.bin --relay 107.174.204.124:9009 --relay-password yourpass
rcroc fLuOQ4XY --relay 107.174.204.124:9009 --relay-password yourpass
```

## 开发构建

```bash
cargo build --release
```

## 主要能力

- relay 中继（房间匹配 + 双向 pipe）
- 端到端加密传输（P-256 ECDH + PBKDF2 + AES-256-GCM）
- 多文件/目录传输（含空目录）
- 断点续传
- 多路并发传输
- LAN 探测 + 局域网数据通道升级
- 代理支持（SOCKS5、HTTP CONNECT）
- `.gitignore` 过滤

## 已知限制

- 仅保证 rcroc 协议互通，不保证与 Go `croc` 互通
- 暂未实现限速、QR、SOCKS5/HTTP 认证头
