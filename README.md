# X365 协议核心（core）

X365 协议的 Go 参考实现，位于本仓库 `core/` 目录，module 路径为
`github.com/365vpn/x365/core`。桌面端、移动端与 CLI 均基于本包构建。

## 协议概览

X365 是一个面向代理转发的应用层协议，建立在以下分层之上：

```
SOCKS5 客户端
      │
      ▼
┌─────────────────────────────────────────┐
│ HTTP/1.1 chunked transfer encoding      │  ← 分帧层
│ Content-Type: application/grpc          │  ← 伪装层（gRPC 语义外观）
│ TE: trailers                            │
├─────────────────────────────────────────┤
│ X365 二进制头（寻址 + 认证）              │  ← 应用层
├─────────────────────────────────────────┤
│ TLS 1.3 + REALITY 握手                   │  ← 传输安全层
└─────────────────────────────────────────┘
```

### X365 二进制头

每个隧道连接的首个 chunk 携带如下结构：

```
┌───────────┬─────┬─────┬────────────┬────────┬──────┬─────────┐
│  "X365"   │ ver │ cmd │    UUID    │  port  │ atyp │ address │
│  4 bytes  │  1  │  1  │  16 bytes  │ 2 bytes│  1   │  变长   │
└───────────┴─────┴─────┴────────────┴────────┴──────┴─────────┘
```

- `cmd`: `0x01` = TCP CONNECT
- `atyp`: `0x01` IPv4（4 字节）/ `0x02` 域名（1 字节长度 + 域名）/ `0x03` IPv6（16 字节）
- 服务端在响应的首个 chunk 中回显 `"X365"` 作为隧道建立确认

### REALITY 握手

传输层采用 REALITY 握手（xray-core 26.3.27 兼容）：ClientHello 的
SessionId 字段中嵌入协议版本、时间戳与 shortID，并通过 ECDHE 临时密钥
与服务端 X25519 公钥派生会话密钥（HKDF + AES-GCM）完成无证书服务端认证，
拒绝 fallback 证书。

## URI 格式

```
x365://<uuid>@<host>:<port>?path=<path>&host=<host>&sni=<sni>&pbk=<pubkey>&sid=<shortid>&fp=<fingerprint>#<备注>
```

## 使用

```go
cfg, err := x365.ParseURI("x365://...")
if err != nil { ... }

// 直接拨一条隧道
conn, err := x365.Dial(ctx, cfg, "example.com", 443)

// 或启动本地 SOCKS5 服务
pm := x365.NewProxyManager()
pm.Start(cfg, "127.0.0.1:10808")
```

## 构建

```sh
go build ./...
```

## License

MIT
