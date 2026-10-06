# X365 协议核心（core）

X365 协议的 Go 参考实现，位于本仓库 `core/` 目录，module 路径为
`github.com/SakurakaiCat/x365-core`。桌面端、移动端与 CLI 均基于本包构建。

X365 协议在设计上受到既有 VPN / 代理隧道协议的启发（例如 gRPC 外观的
分帧伪装、REALITY 类无证书握手、XHTTP 类 HTTP/2 传输），但**协议格式与
全部实现均为本项目独立设计、独立编码**，不基于任何第三方客户端的源码，
也不隶属、不依赖于任何第三方服务商。

## 协议概览

X365 是一个面向代理转发的应用层协议，建立在以下分层之上，传输层同时
支持 HTTP/2 全双工（默认）与 HTTP/1.1 chunked 两种承载：

```
SOCKS5 客户端
      │
      ▼
┌─────────────────────────────────────────┐
│ XHTTP：HTTP/2 单流全双工（默认）          │  ← 分帧层
│ 或 HTTP/1.1 chunked（legacy，type=h1）   │
│ Content-Type: application/grpc          │  ← 伪装层（gRPC 语义外观）
│ UA: Chrome/120 Win + referer + padding   │
├─────────────────────────────────────────┤
│ X365 二进制头（寻址 + 认证）              │  ← 应用层
├─────────────────────────────────────────┤
│ TLS 1.3 + REALITY 握手（chrome_120 指纹） │  ← 传输安全层
└─────────────────────────────────────────┘
```

### X365 二进制头

每个隧道连接的请求体首块携带如下结构：

```
┌───────────┬─────┬─────┬────────────┬────────┬──────┬─────────┐
│  "X365"   │ ver │ cmd │    UUID    │  port  │ atyp │ address │
│  4 bytes  │  1  │  1  │  16 bytes  │ 2 bytes│  1   │  变长   │
└───────────┴─────┴─────┴────────────┴────────┴──────┴─────────┘
```

- `cmd`: `0x01` = TCP CONNECT（`0x02`/`0x03` 为 UDP 指令，本包暂未实现）
- `atyp`: `0x01` IPv4（4 字节）/ `0x02` 域名（1 字节长度 + 域名）/ `0x03` IPv6（16 字节）
- 服务端在响应体首 5 字节回显 `"X365"` + status（`0x00` = 成功；
  非零表示服务端错误，如未授权）。拨号失败时本包返回
  `x365: server status 0x%02x` 错误
- 认证依据为 REALITY 握手 + X365 头中的 UUID

### XHTTP 传输（默认）

本包默认使用 XHTTP 承载：把隧道流放进一条 HTTP/2 POST 请求的请求体与
响应体之间，实现全双工。线上行为要点：

- REALITY 握手使用 uTLS 的 Chrome 120 ClientHello 配置（`fp=chrome`）
- HTTP/2 连接建立序列保持最小化：preface + 空 SETTINGS 帧（不发送
  PRIORITY / WINDOW_UPDATE），HEADERS 后紧接 DATA
- 请求为单条 HTTP/2 POST，`:path` 为 `<path>/?x_padding=<65 个 X>`
  （反指纹填充参数），携带 `content-type: application/grpc`、
  Chrome/120 Windows UA、`referer: https://<sni><path>?x_padding=...`，
  配置了 token 时附 `authorization: Bearer <JWT>`
- 之后请求体与响应体的 DATA 帧即为全双工隧道流；本包实现完整的
  HTTP/2 流控（读侧回 WINDOW_UPDATE，写侧等待服务端 WINDOW_UPDATE）
- 调试：设置 `X365_DEBUG=1` 输出帧级日志

### HTTP/1.1 chunked 传输（legacy）

`type=h1` 时使用传统承载：单条 `POST` 请求 + `Transfer-Encoding: chunked`
分帧，首个 chunk 携带 X365 二进制头，服务端以 `"X365"` + status 确认后
双向透传。该路径建议携带 `Authorization: Bearer <JWT>`。

### 认证与 token

token 为账户 JWT（登录接口返回的 access token），可通过 `token=` URI
参数或 `X365Config.Token` 字段传入。两种承载均支持携带；服务端对不同
承载的校验强度不同，实测 xhttp 路径不校验 token（认证来自 REALITY +
X365 头中的 UUID），h1 路径在缺少浏览器 UA 时对 token 有硬性要求，
故建议始终携带以贴近正常客户端行为。

### REALITY 握手

传输层采用 REALITY 握手：ClientHello 的 SessionId 字段中嵌入协议版本、
时间戳与 shortID，并通过 ECDHE 临时密钥与服务端 X25519 公钥派生会话密钥
（HKDF + AES-GCM）完成无证书服务端认证，拒绝 fallback 证书。

## URI 格式

```
x365://<uuid>@<host>:<port>?path=<path>&host=<host>&sni=<sni>&pbk=<pubkey>&sid=<shortid>&fp=<fingerprint>&type=<xhttp|h1>&token=<JWT>#<备注>
```

- `type`/`network`：`xhttp`（默认）或 `h1`（legacy chunked）
- `token`：账户 JWT（可选，建议携带）
- `fp`：`chrome`（默认，Chrome 120 指纹）或 `auto`

## 使用

```go
cfg, err := x365.ParseURI("x365://...")
if err != nil { ... }

// 直接拨一条隧道（默认 xhttp）
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
