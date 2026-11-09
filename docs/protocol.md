# agentd 协议规范

- 状态：v0.7 草案，已有可运行实现
- 日期：2026-11-09
- 对应：设计文档 `docs/design.md` v0.16。本文只定义线上格式、状态机、校验步骤和常量，不重复讨论取舍；取舍见设计文档对应章节
- 形式化部分：`proto/agentd/v1/wire.proto` 是所有 protobuf 消息的权威定义，本文引用其中的消息名

目录

0. [约定与常量](#0-约定与常量)
1. [relay 与 agentserver 的监听与端点](#1-relay-与-agentserver-的监听与端点)
2. [transport](#2-transport)
3. [会话层](#3-会话层)
4. [流的通用格式](#4-流的通用格式)
5. [控制通道](#5-控制通道)
6. [tcp 流](#6-tcp-流)
7. [task 流](#7-task-流)
8. [加入、名字与 URI](#8-加入名字与-uri)
9. [状态码总表](#9-状态码总表)
10. [安全要点与实现注意](#10-安全要点与实现注意)
11. [实现检查清单](#11-实现检查清单)
12. [状态机](#12-状态机)
- [附录 A：一次 exec_command 的完整消息](#附录-a一次-exec_command-的完整消息)
- [附录 B：一条 TLS 连接的完整消息](#附录-b一条-tls-连接的完整消息)

---

## 0. 约定与常量

### 0.1 术语

| 术语 | 含义 |
| --- | --- |
| 节点 | 一个 agentd 实例，身份是 Ed25519 公钥；一台设备可以运行多个实例，各有实例目录与密钥（设计文档 9.2） |
| agentserver | 控制面、管理平台兼后端：目录、路由表、策略、证书、relay 指派；只和 relay 说话，回答 relay 的查询，签名发给节点的控制消息 |
| relay | 数据面与节点接入（agentrelay）：节点唯一连接的服务端；终结会话与控制流，转发前向后端查询选路与预检结果（答案缓存），充当 HTTP 服务边缘 |
| 后端 | 本文里指 agentserver 对 relay 的那一面 |
| transport 连接 | 节点到 relay、relay 到 agentserver 的一条物理连接（WebSocket、HTTP Upgrade 或 XHTTP 会话），对上提供可靠有序的双向字节流；节点间直连预留 `p2p`（QUIC） |
| 会话 | transport 连接上完成 Noise_IK 握手后的加密通道。节点只有一条，对端是 relay；relay 到 agentserver 一条 |
| 控制流 | 节点会话里的流 1，在 relay 终结；节点与 agentserver 的控制消息经它和 relay 会话往返，agentserver 发出的带签名 |
| 流 | 会话内 yamux 多路复用出的一条双向字节流 |
| 发起方 / 接收方 | 开流的一方 / 被开流的一方。relay 转发时对上游是接收方、对下游是发起方，但 `Open` 的签名者始终是原始发起节点 |
| 下一跳 | 一条流所在会话的对端：经 relay 时是 relay，直连时是对端节点；`OpenBody.to` 永远是下一跳 |
| 提供侧 | egress、service、executor 角色所在的节点 |
| 路由表 | agentserver 上的（源，协议，域名模式）→ 目的节点 / direct / reject，不下发（设计文档 6.5） |
| 分流表 | agentserver 按节点从路由表渲染给 ingress 的投影（`IngressRoutes`）：（协议，域名模式）→ 直连 / 交给下一跳 / 拒绝，不含目的节点 |
| LP | 长度前缀：`[u32 大端长度][字节]`，长度不含前缀本身 |

### 0.2 编码

- 多字节整数一律大端。
- 结构化消息一律 protobuf（proto3），定义在 `proto/agentd/v1/wire.proto`。字段只增不改，弃用字段保留编号；接收方忽略未知字段。
- 公钥在线上是 32 字节原始值；在文本（配置、CLI、日志、URI）里是 base64url 无填充编码，恰好 43 字符。
- 域名在线上一律小写、无末尾点、IDNA 的 A-label 形式。
- 被签名的消息都是信封：`body`（序列化字节）加 `sig`。签名用 RFC 8032 的 Ed25519ctx，上下文字符串见各节；接收方先对收到的 `body` 字节验签再解码，所以不需要规范化编码。
- 时间：`uint64` 字段是 Unix 秒；`timestamp` 字段是 12 字节 TAI64N：前 8 字节大端为 `2^62 + 10 + Unix 秒`（与 wireguard-go 的 `tai64n` 一致），后 4 字节大端为纳秒。比较按 12 字节逐字节。

### 0.3 分层

```
┌───────────────────────────────────────────────────────────────────────────────┐
│ 流内容：control（LP 控制消息；agentserver 发出的在 Signed 信封里）                │
│         tcp（Open、Ack 后裸字节）/ task（Open、Ack、TaskResult）                  │
├───────────────────────────────────────────────────────────────────────────────┤
│ yamux：流、窗口、FIN / RST、ping                                               │
├───────────────────────────────────────────────────────────────────────────────┤
│ Noise 帧：[u16 长度][密文]，握手后每帧明文 ≤ 16 KiB                               │
├───────────────────────────────────────────────────────────────────────────────┤
│ transport：WebSocket / HTTP Upgrade / XHTTP，提供双向字节流                      │
└───────────────────────────────────────────────────────────────────────────────┘
```

relay 到 agentserver 的 relay 会话同样是「transport → Noise 帧 → yamux」，只有一条流，承载 relay 的查询、节点消息的转交和后端的答案与推送（LP 控制消息）。

### 0.4 版本

- 主版本写死在 Noise prologue：ASCII `agentd/1`（8 字节）。主版本变化意味着握手不兼容。
- 次版本在握手载荷里协商：`ClientHello.min_version` / `max_version` 与服务端支持区间取交集的最大值，写入 `ServerHello.version`。本文定义次版本 1。
- 次版本内的演进只靠 protobuf 字段新增和新的 `Kind` / `Status` 值；未知的控制消息忽略，未知的 `Kind` 回 `BAD_REQUEST`。

### 0.5 常量

| 名称 | 值 | 说明 |
| --- | --- | --- |
| `PROLOGUE` | `agentd/1` | Noise prologue |
| `NOISE_PROTOCOL` | `Noise_IK_25519_ChaChaPoly_BLAKE2s` | 会话握手 |
| `CTX_OPEN` | `agentd/open/v1` | `Open` 签名的 Ed25519ctx 上下文 |
| `CTX_TASK_RESULT` | `agentd/task-result/v1` | `TaskResult` 签名的上下文 |
| `CTX_MEMBERSHIP` | `agentd/membership/v1` | 成员证书签名的上下文 |
| `MEMBERSHIP_TTL` | 3600 秒 | 成员证书有效期 |
| `MEMBERSHIP_RENEW` | 1800 秒 | 剩余有效期低于此值时续发 |
| `OPEN_MAX_CERTS` | 16 | `StreamOpen.certs` 的上限 |
| `CTX_RELAY` | `agentd/relay/v1` | relay 证书签名的上下文（签名者是 workspace 密钥） |
| `CTX_CONTROL` | `agentd/control/v1` | 发给节点的控制消息（`Signed`，workspace 密钥签）的签名上下文 |
| `RELAY_CERT_TTL` | 30 天 | relay 证书有效期，剩余一半时续签 |
| `RELAY_CACHE_TTL` | 60 秒 | relay 缓存控制面答案的默认时长（答案可带自己的 `ttl_seconds`） |
| `RELAY_CACHE_MAX` | 100,000 条 | relay 缓存条目上限，LRU |
| `RELAY_LOOKUP_TIMEOUT` | 5 秒 | relay 等待控制面答案；超时按控制面不可达处理 |
| `FRAME_MAX_PLAINTEXT` | 16384 字节 | 握手后每个 Noise 帧的明文上限（密文上限由 Noise 规定为 65535） |
| `REKEY_INTERVAL` | 2^20 条消息 | 每方向每发送或接收这么多条消息后 Rekey |
| `SESSION_MAX_AGE` | 24 小时（软）/ 25 小时（硬） | 到软上限且无活跃流时重建会话，到硬上限强制 |
| `TRANSPORT_DIAL_TIMEOUT` | 10 秒 | TCP、TLS、HTTP 升级或首个 XHTTP 请求完成 |
| `HANDSHAKE_TIMEOUT` | 5 秒 | transport 就绪到 Noise 握手完成（含 relay 向后端查询的时间） |
| `CONTROL_OPEN_TIMEOUT` | 5 秒 | 握手完成到控制流的 Ack |
| `ACK_TIMEOUT` | 15 秒 | 发起方等待 Ack |
| `OPEN_TIME_WINDOW` | ±300 秒 | `OpenBody.issued_at` 相对接收方时钟 |
| `NONCE_CACHE_TTL` | 600 秒 | (from, nonce) 记忆时长 |
| `TASK_DEDUP_TTL` | 600 秒 | executor 缓存 (from, call_id) 结果 |
| `EARLY_DATA_MAX` | 16 KiB | 接收方在 Ack 前缓冲的首段数据上限 |
| `OPEN_MAX` | 1 MiB | `StreamOpen` 的 LP 长度上限 |
| `ACK_MAX` | 64 KiB | |
| `TASK_RESULT_MAX` | 2 MiB | |
| `CONTROL_MSG_MAX` | 16 MiB | 单条控制消息 |
| `IDLE_TIMEOUT_TLS` | 300 秒 | `tcp` 流（proto TLS / HTTP）双向无数据 |
| `IDLE_TIMEOUT_SSH` | 无 | SSH 不设空闲超时 |
| `DRAIN_AFTER_FIN` | 5 秒 | 双向 FIN 后到释放 |
| `EGRESS_DIAL_TIMEOUT` | 10 秒 | 提供侧拨号源站或本地目标 |
| `TCP_KEEPALIVE` | 30 秒 | 提供侧拨出的 TCP 连接 |
| `YAMUX` | 见 3.4 | |
| `RECONNECT_BACKOFF` | 1 秒起，倍增，上限 60 秒，±20% 抖动 | 会话就绪满 60 秒后归零 |
| `XHTTP_MAX_POST` | 1,000,000 字节 | packet-up 单个 POST 体 |
| `XHTTP_MIN_POST_INTERVAL` | 30 毫秒 | |
| `XHTTP_REORDER_BUFFER` | 30 个 | 服务端乱序缓冲 |
| `XHTTP_SESSION_GC` | 30 秒 | 上下行其中一半迟迟不到 |
| `TOKEN_BYTES` | 16 字节 | 加入令牌，base64url 22 字符，默认 TTL 24 小时 |
| `SESSION_ID_BYTES` / `NONCE_BYTES` / `TRACE_ID_BYTES` | 16 字节 | |

---

## 1. relay 与 agentserver 的监听与端点

数据面 agentrelay 是节点唯一连接的服务端，对公网监听 443（以及 80 用于跳转）。控制面 agentserver 只需对 relay 和管理员可达。

relay，一个 TLS 监听器按 SNI 分流：

| SNI | 证书 | 交给 |
| --- | --- | --- |
| 等于 relay 域名（如 `relay-hk.agentsrv.example.com`） | relay 自己的证书 | `GET /ws`、`GET /up`、`GET /x/<sid>`、`POST /x/<sid>[/<seq>]`：节点会话的 transport（2 节）；`GET /.well-known/agentd?workspace=<基础域名>`：JSON `{"relay_cert":"<base64url 的 RelayCert，该 workspace 的那张>","protocol":{"major":1,"min":1,"max":1},"transports":{"ws":"/ws","httpupgrade":"/up","xhttp":"/x"}}`，供 `agentd join` 首次接触时用加入链接里的 `key`（workspace 公钥）验证这个 relay；本 relay 不服务该 workspace 时 404；其他路径 404，固定的无特征页面 |
| 匹配某个被指派到本 relay 的 workspace 的 `*.<基础域名>` | 控制面经 `WorkspaceCerts` 下发的通配证书，只在内存 | edge（设计文档 5.8）：按控制面的答案判定访问者（含公网访问者）后反向代理到服务节点 |
| 其他或无 SNI | 无 | 关闭连接 |

relay 另监听 UDP 3478 作 STUN 反射（2.6）；80 端口回 301 到 https。

agentserver 监听 relay 会话的 transport 端点（同样的 `/ws`、`/up`、`/x/…` 路径，SNI 等于控制面域名，证书可以是 ACME 的也可以是 relay 通过 `control.ca_file` 信任的私有 CA 签的）与 `GET /.well-known/agentserver`（JSON `{"identity":"<agentserver 公钥>","protocol":{"major":1,"min":1,"max":1},"transports":{…}}`，relay 的 `control.public_key` 为空时据此取得公钥，信任来自 TLS 校验）和一个只对本机或内网开放的 admin API（CLI 经它操作）。它没有面向节点的端点：节点的控制流在 relay 终结，relay 把需要后端处理的消息转给它。transport 路径可配，节点从加入链接得知 relay 的，从 `Welcome.relays` 得知其他 relay 的。

---

## 2. transport

### 2.1 抽象

transport 只做一件事：在节点和 relay 之间（以及 relay 和 agentserver 之间）提供一条可靠有序的双向字节流，字节边界没有意义。会话层以上与 transport 无关。

```go
// 节点侧
type Dialer interface {
    Dial(ctx context.Context) (Conn, error)   // 返回时 transport 已就绪，可直接发 Noise 消息 1
}
// 服务端侧：每种 transport 是一个 http.Handler，产生 Conn 交给会话层
type Conn interface {
    io.ReadWriteCloser
    SetReadDeadline(time.Time) error
    SetWriteDeadline(time.Time) error
}
```

agentserver 与 relay 对未完成 Noise 握手的连接按 IP 限速（令牌桶，默认每分钟 10 次失败），`HANDSHAKE_TIMEOUT` 内没完成握手即关闭。

### 2.2 WebSocket（默认）

请求：

```
GET /ws HTTP/1.1
Host: agentsrv.example.com
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: <随机>
Sec-WebSocket-Protocol: agentd.v1
User-Agent: <浏览器样式，可配置>
```

响应：`101 Switching Protocols`，`Sec-WebSocket-Accept`，`Sec-WebSocket-Protocol: agentd.v1`。服务端没有回显子协议时节点断开并报错「不是 agentd 服务端」。

字节流映射：

- 只用二进制消息。所有二进制消息的载荷按顺序拼接就是字节流；一条消息可以含多个 Noise 帧或半个帧，接收方不得假设消息边界与帧边界对齐。
- 发送方的实现建议：单一写 goroutine，把同一时刻待发的 Noise 帧合并成一条消息，单条消息不超过 64 KiB。
- 收到文本消息即协议错误，关闭连接（状态码 1002）。
- WebSocket 层的 Ping / Pong 不作为保活依据（CDN 可能不透传）；保活由 yamux 承担。实现若收到 Ping 必须按规范回 Pong。
- 关闭：会话层关闭后发 Close 帧，状态码 1000；握手失败用 1008；超时未完成握手直接断 TCP。

HTTP/1.1。经 Cloudflare 时边缘到源站也是 HTTP/1.1，与 WebSocket 兼容。

### 2.3 HTTP Upgrade

与 Xray-core 的 httpupgrade 相同的办法：握手头伪装成 WebSocket，升级后不做 WebSocket 分帧，直接裸字节。

请求头与 2.2 相同但路径为 `/up`、不带 `Sec-WebSocket-Protocol`。响应 `101 Switching Protocols` 加 `Sec-WebSocket-Accept`。之后双向裸字节即为字节流。

服务端注意：用 `bufio.Reader` 解析请求后，必须把它已经预读的字节接到字节流前面，否则节点在 101 之前发出的数据会丢（Xray 的 `hub.go` 丢弃了这部分，设计文档 7.7）。v1 的节点在收到 101 之前不发送数据，这条是防御性要求。

经 Cloudflare 能否使用需实测（设计文档第 10 节第 15 条）。

### 2.4 XHTTP

参考 Xray-core `transport/internet/splithttp`。两种模式：

**packet-up**（默认，经 CDN）

- 会话 ID `sid`：节点生成 16 字节随机数，base64url 22 字符。
- 下行：`GET /x/<sid>`。响应 `200`，头 `Content-Type: text/event-stream`、`Cache-Control: no-store`、`X-Accel-Buffering: no`，HTTP/1.1 用 chunked，HTTP/2 用流式 body。响应体就是服务端到节点的字节流。
- 上行：`POST /x/<sid>/<seq>`，`seq` 从 0 递增的十进制，`Content-Type: application/octet-stream`，体长度 1 到 `XHTTP_MAX_POST` 字节。响应 `200` 空体。相邻 POST 间隔不小于 `XHTTP_MIN_POST_INTERVAL`；节点把多次写合并成一个 POST 直到达到上限或间隔到期。
- 服务端按 `seq` 重排，最多缓冲 `XHTTP_REORDER_BUFFER` 个乱序包，超出则关闭会话（回 `409`）。`seq` 重复回 `409`；体超长回 `413`；`sid` 不存在且不是首个请求回 `404`。
- GET 和首个 POST 谁先到都可以，另一半在 `XHTTP_SESSION_GC` 内未到则回收会话。
- 多实例部署时负载均衡必须按 `sid` 保持亲和，会话状态只在进程内。
- 节点优先用 HTTP/2 发请求，减少连接数；每个 `sid` 的 GET 与 POST 可以走不同 HTTP 连接。

**stream-one**（直连，无 CDN 缓冲）

- 单个 `POST /x/<sid>`，`Content-Type: application/grpc`，请求体与响应体都是流式，分别是上行与下行字节流。
- 节点不能确定路径上没有缓冲代理时不要用它。

透传给会话层的仍然是一条字节流，Noise 帧、yamux 与上面两种模式无关。

### 2.5 节点的连接策略

- 认 relay：节点只钉 `workspace.public_key`。连接一个 relay 前必须持有它在本 workspace 的有效 `RelayCert`（签名用 workspace 公钥与 `CTX_RELAY` 验证、`workspace` 等于自己的、未过期）：首次从加入链接的 `relay` URL 取 `/.well-known/agentd?workspace=<基础域名>`，之后用 `Welcome.relays` / `Update.relays` 里的，缓存在 `state/`。证书无效或过期的 relay 不连。
- TLS：所有 transport 都跑在 TLS 上，按标准 WebPKI 校验 relay URL 的主机名，SNI 为该主机名；没有跳过校验的选项，开发环境也用真实或本地受信的证书。Noise 握手额外认证 relay 身份，TLS 校验是纵深。
- 超时：`TRANSPORT_DIAL_TIMEOUT` 内完成 TCP、TLS 和 HTTP 升级（或 XHTTP 的首个请求）；之后 `HANDSHAKE_TIMEOUT` 内完成与 relay 的 Noise 握手；之后 `CONTROL_OPEN_TIMEOUT` 内控制流的 Ack 到达。任一超时视为本次连接失败。
- 重连：`RECONNECT_BACKOFF`；`ServerHello.retry_after_seconds` 或 `Notice.retry_after_seconds` 存在时按它等待；收到 `Notice{REMOVED}` 或 `ServerHello{NOT_A_MEMBER}` 后停止重连并提示重新 join。
- `transport: auto`：按 ws、xhttp、httpupgrade 顺序，当前 transport 连续 3 次在握手完成前失败就换下一种；成功一次后固定使用，再次连续失败 3 次再换。
- TUN 模式下所有出站连接绑定物理接口（设计文档 5.2）。
- 一个节点进程只维护一条会话；重建会话时先建新会话再关旧会话（relay 按 3.6 替换）。连不上当前 relay 连续 3 次时换 `Welcome.relays` 里的下一个并在控制流上发 `RelayReport`；握手得到 `WRONG_RELAY` 时按其附带的 relay 证书换 relay。`Update.assigned_relay` 变化时关闭当前会话、连新 relay。

### 2.6 预留：P2P 直连

v1 不实现。设计见设计文档 7.8；以下名字、编号与格式已预留，实现时不得挪作他用：

- transport 名字 `p2p`：一条 QUIC 连接上的双向流作为 2.1 的 `Conn`；QUIC 自带的 TLS 用临时自签证书且不校验，认证靠其上的 Noise_IK。
- 直连会话：由公钥字节序较小的一方作 Noise_IK 发起方，静态密钥是由自身 Ed25519 身份派生的 X25519，对端公钥来自目录；prologue 仍为 `agentd/1`，握手载荷用同样的 `ClientHello` / `ServerHello`，其中 `join_token`、`proposed_name` 不出现，`workspace` 必填。直连会话上有 yamux，没有控制流（`KIND_CONTROL` 的 `Open` 回 `BAD_REQUEST`）；yamux 保活 25 秒以兼顾 NAT 映射。
- 控制消息编号：18 `P2PCandidates`（节点 → 服务端：候选地址列表，开启 P2P、网络变化、映射刷新时发送）；19 `P2PConnect`（节点 → 服务端：请求与某对端直连）；20 `P2PInvite`（服务端 → 双方：对端身份、候选地址、16 字节打洞 nonce、发起方标记）；21 `P2PResult`（节点 → 服务端：选定的地址对或失败原因）。
- 状态码：60 `P2P_DISABLED`（任一方未开启）、61 `P2P_NOT_ALLOWED`（请求方对对端没有任何 allow）、62 `P2P_NO_CANDIDATES`、63 `P2P_PUNCH_FAILED`；64 到 69 继续预留。
- 探测报文：UDP，`agentd-punch/1`（14 字节 ASCII）+ nonce（16 字节）+ 发送方公钥前 8 字节 + 1 字节类型（0 探测、1 回应），共 39 字节；每 100 毫秒一轮、持续 5 秒；收到带正确 nonce 的回应即选定地址对。
- `Advertise.p2p_enabled` 表示节点是否加入 P2P 发现，v1 恒为 false。
- 直连时 `Open.to` 是对端自己（任务另有 `task.executor`）；没有 `RelayInfo`，接收方不得依赖它；没有清单 A 的预检，接收节点按清单 B 独立判定，成员证书由发起方随 `StreamOpen.certs` 出示（5.7）。egress 流的出口由发起方从该域名上一次经中继得到的 `Ack.responder` 记住，分流表版本变化时清掉。
---

## 3. 会话层

### 3.1 密钥

节点密钥文件是实例目录下的 `node.key`（默认实例 `~/.agentd/node.key`，其他实例 `~/.agentd/instances/<名>/node.key`，见设计文档 9.2），权限 0600，文本格式：

```
# agentd node key v1
private-key: <base64url 无填充的 32 字节 Ed25519 种子>
```

公钥由种子派生。agentserver 与 relay 的密钥文件格式相同（`key_file`）。组与 workspace 的 Ed25519 密钥对由 agentserver 生成并加密存放在状态库里，不落单独文件（5.7）。

Noise 握手用的 X25519 密钥按 libsodium 的转换从 Ed25519 密钥派生，不单独保存：

- 私钥：`h = SHA-512(seed)`，取 `h[0:32]`，clamp（`h[0] &= 248; h[31] &= 127; h[31] |= 64`）。
- 公钥：Edwards 点 `(x, y)` 到 Montgomery `u = (1 + y) / (1 - y) mod p`，32 字节小端（Go：`filippo.io/edwards25519` 的 `Point.BytesMontgomery()`）。

记作 `X(pk)`。响应方在握手里校验 `X(ClientHello.identity) == 握手静态公钥`；发起方把对端公钥派生后作为 IK 的 `PeerStatic`：节点用 relay 证书里的公钥，relay 用配置的 `control.public_key`。节点配置里的 workspace 公钥（`workspace.public_key`）不用于握手，只用来验 relay 证书、控制消息和 workspace 成员证书的签名。relay 证书 `RelayCert{body, sig}` 由 agentserver 用该 workspace 的私钥按 `CTX_RELAY` 签名，节点先验签再派生。

### 3.2 握手

两处握手用同一套消息与参数：节点 ⇄ relay（transport 就绪后），relay ⇄ agentserver（relay 会话）。字节流上的内容从第一个字节起都是 `[u16 大端长度][帧]`；握手的两条消息各占一帧。

参数：协议 `Noise_IK_25519_ChaChaPoly_BLAKE2s`，prologue `agentd/1`。发起方是节点或 relay；响应方静态公钥分别来自 relay 证书和 relay 配置的 `control.public_key`。`ClientHello.session_kind` 声明会话种类（`NODE`、`RELAY`），响应方不服务该种类时回 `BAD_REQUEST`。

```
发起方                                                      响应方
  │ 帧 1：Noise IK 消息 1 = e(32) ‖ enc(s)(48) ‖ enc(ClientHello)   │
  │ ───────────────────────────────────────────────────────────▶ │
  │                                                              │ 完成 DH，解出 s 与 ClientHello
  │                                                              │ 校验（下表）；relay 向后端查公钥或转加入请求
  │ ◀─────────────────────────────────────────────────────────── │
  │ 帧 2：Noise IK 消息 2 = e(32) ‖ enc(ServerHello)                │
  │ 双方 Split()，进入 transport 模式                              │
```

响应方对消息 1 的校验顺序与结果（标注了只在某种握手里出现的步骤；「后端」步骤由 relay 发 `RelayLookup{node}` 或 `RelayLookup{join}` 请 agentserver 判定，答案缓存，5.8）：

| 步骤 | 失败时 |
| --- | --- |
| Noise 解密与 DH 成功 | 直接断开，不回任何字节（扫描者拿不到信息） |
| `ClientHello` 可解码，`identity` 32 字节，`timestamp` 12 字节 | `BAD_REQUEST` |
| `[min_version, max_version]` 与响应方区间有交集 | `VERSION_MISMATCH` |
| `X(identity) == 握手静态公钥` | `IDENTITY_MISMATCH` |
| `timestamp` 大于该 `identity` 上次成功握手的值（relay 记在内存，加入请求由后端持久化） | `TIMESTAMP_OLD` |
| 节点，带 `join_token`：后端按 8.3 处理加入 | `TOKEN_*`、`NAME_TAKEN`、`BAD_NAME`、`IDENTITY_IN_USE`、`WORKSPACE_MISMATCH` |
| 节点，不带令牌：后端答复 `identity` 在某个 workspace 的目录中 | `NOT_A_MEMBER` |
| 节点：后端答复 `identity` 所在 workspace 指派给了本 relay | `WRONG_RELAY`（`ServerHello.assigned_relay` 带正确的 relay 证书） |
| 节点：后端可达，或该公钥有缓存的答案 | `CONTROL_NOT_READY`（带 `retry_after_seconds`） |
| relay 会话：`identity` 在 relay 注册表中 | `NOT_A_MEMBER` |
| 响应方未过载 | `SERVER_BUSY`（带 `retry_after_seconds`） |

失败时响应方仍完成握手并在消息 2 里发送带状态码的 `ServerHello`，然后关闭连接：握手在密码学上已经成功，错误只有持有私钥的发起方能解出，这样发起方能看到原因。成功时 `ServerHello.status = OK`，带 `version`、`session_id`、`workspace`、`name`、`role_caps`（来自后端答案）、`server_identity`（relay 公钥）、`server_time`；relay 从此接受该节点的数据流，并在它开控制流后送达后端给的 `Welcome`。

发起方对消息 2 的处理：解密失败说明响应方静态密钥与预期不符，节点报「relay 身份与证书不符」并换 relay，relay 报「agentserver 公钥与配置不一致」并停止重连直到用户处理；`status != OK` 按 9 节处理；`|server_time - 本地时间| > 60 秒` 记录告警。

时间戳记忆：relay 按 `identity` 在内存记上次成功握手的 TAI64N；agentserver 为加入请求持久化。发起方每次握手取当前时间，时钟回拨时会被拒，`agentd status` 显示原因。

### 3.3 加密帧、Rekey 与寿命

- 握手后每帧 `[u16 长度][Noise transport 密文]`，明文不超过 `FRAME_MAX_PLAINTEXT`，密文等于明文长度加 16。写入方把上层字节流按不超过 16 KiB 切帧，读出方把解密后的明文拼回字节流。
- 两个 CipherState（发送、接收）各自计数。处理完 nonce 为 `k · 2^20 − 1` 的消息后，立即对该 CipherState 调用 Noise 规范 §11.3 的 `Rekey()`；不发信号，两侧按同一规则各自进行。Rekey 不重置 nonce。
- 会话到 `SESSION_MAX_AGE` 软上限后，节点在没有活跃流时主动重建；到硬上限时强制重建。relay 对超过硬上限的会话发 `Notice{SHUTDOWN}`（relay 自己产生、不签名，5.5）后关闭。
- 解密失败是致命错误：关闭 transport 连接，重连。

### 3.4 多路复用

解密后的字节流上跑 yamux（wire 与 hashicorp/yamux 兼容，实现用 libp2p 的 go-yamux v5）。帧头 12 字节：

```
Version(1)=0 | Type(1) | Flags(2) | StreamID(4) | Length(4)
Type:  Data=0  WindowUpdate=1  Ping=2  GoAway=3
Flags: SYN=0x1  ACK=0x2  FIN=0x4  RST=0x8
```

- 角色：发起连接的一方（节点对 relay，relay 对 agentserver）是 yamux client（奇数流 ID，从 1 起），响应方是 server（偶数流 ID，从 2 起）。两侧都可以开流。节点会话上流 1 是控制流；relay 会话上只有流 1。
- 参数：`InitialStreamWindowSize 256 KiB`，`MaxStreamWindowSize 16 MiB`，`KeepAliveInterval 30 s`（两侧都开），`ConnectionWriteTimeout 30 s`，`MaxIncomingStreams 1024`，`MaxMessageSize 64 KiB`，`AcceptBacklog 256`。
- 半关闭：FIN 标志（`CloseWrite()`）；中止：RST 标志（`Reset()`）。任何写错误路径都以 `Reset()` 收尾（设计文档 7.7）。
- yamux 的 ping 是会话保活的唯一机制：30 秒一次，`ConnectionWriteTimeout` 内未得到应答则关闭会话并重连。

### 3.5 状态机

节点侧（一条会话）：

```
Idle ──dial──▶ Connecting ──transport 就绪──▶ Handshaking ──ServerHello OK──▶ ControlOpening ──Ack OK──▶ Ready
  ▲                │                              │                               │                        │
  │                └── 失败 / 超时 ──▶ Backoff ◀───┴── 失败 / 超时 ◀───────────────┘                        ▼
  └──────────────── 退避到期 ───────────────────────────────────────────────────────────── Closing ──▶ Idle
                                                              （收到 Notice{REMOVED} 或 ServerHello{NOT_A_MEMBER} 时进入 Stopped，不再重连）
```

relay 每条节点会话：`Accepted → AwaitHello（5 秒）→ Resolving（问后端或查缓存）→ Authenticated（接受数据流与控制流）→ ControlReady（控制流已开，已送达 Welcome）→ Closed`。relay 会话两侧：`Accepted → AwaitHello → Authenticated → Ready`。完整的状态机见第 12 节。

### 3.6 会话替换与关闭

- 同一 `identity` 的新会话握手成功时：relay 对旧会话的所有流 RST 并关闭。新会话立即成为该节点的唯一会话。
- agentserver 优雅关闭：对 relay 会话发 `Notice{SHUTDOWN, retry_after_seconds}` 后关闭；relay 据此进入 `Disconnected`（12.9），节点的会话不受影响。relay 优雅关闭：对所有节点会话发 `Notice{SHUTDOWN, retry_after_seconds}`（不签名），通知后端，再对所有流 RST 并关闭连接；节点重连或换 relay。
- 节点主动关闭（`agentd leave`、退出）：对活跃流 RST，关闭 transport 连接即可，不需要控制消息。
- 会话断开时：`tcp` 流对应的本地 / 源站 TCP 连接一律关闭；进行中的 `exec_command` 进程继续运行，结果进入去重缓存（7.3）。

---

## 4. 流的通用格式

### 4.1 第一帧：StreamOpen

每条流由发起方写入的第一条消息是 LP 编码的 `StreamOpen`，长度上限 `OPEN_MAX`。

```
StreamOpen { open: Open { body: bytes(OpenBody), sig: 64 字节 }, certs: [MembershipCert], relay: RelayInfo }
sig = Ed25519ctx(sk_from, ctx = "agentd/open/v1", body)
```

`OpenBody` 字段与各 `kind` 的要求：

| 字段 | CONTROL | TCP | TASK |
| --- | --- | --- | --- |
| `workspace` | 必填，等于会话的 workspace | 同左 | 同左 |
| `from` | 等于会话身份 | 等于发起节点身份（edge 发起时为 relay 身份） | 等于发起节点身份 |
| `to` | relay 身份（relay 会话上：agentserver 身份） | 下一跳：经 relay 开的流是 relay 身份；edge → 服务节点是服务节点身份；直连是对端节点身份 | 下一跳：relay 身份，直连时是 executor 身份 |
| `issued_at`、`nonce` | 必填 | 必填 | 必填 |
| `sig` | 空 | 必填 | 必填 |
| `tcp` | 无 | `proto`、`domain`、`port`（edge → 节点另有 `http_peer`） | 无 |
| `task` | 无 | 无 | `executor`（目标 executor 身份）与 `call`（完整 `FunctionCall`） |

`from` 与 `to` 的语义：

- `from` 是本条流的起点，也是签名者。
- `to` 是下一跳：这条流所在会话的对端，也就是第一个读到它的那一方。节点在会话上开的流，`to` 是 relay（控制流也是）；P2P 直连上开的流，`to` 是对端节点；edge 向服务节点开的流，`to` 是服务节点；relay 会话上的那条流，`to` 是 agentserver。它不是最终目的地：egress 流的出口由控制面按路由表选出，发起方不知道也不写；服务流的服务节点由 `tcp.domain` 经服务表决定；任务的 executor 写在 `task.executor`。relay 转发时不改写 `to`，提供侧收到经中继的流时要求 `to` 等于自己所连 relay 的身份。
- 一条链路可以由多条流串成，每条流各有自己的 `Open`、`from`、`to` 和签名。HTTP 服务就是两条：`laptop → relay`（`to` = relay）和 `relay → homepc`（`from` = relay，`to` = homepc，由 relay 签名），见 6.3。

relay 转发时保持 `open` 的字节不变，填入 `relay`（`from_name` 来自握手时后端的答案、`rules_version` 来自控制面的答案、`trace_id`、`relayed_at`）。签名只覆盖 `open.body`，`relay` 不在签名内。`certs` 是发起方附上的成员证书（5.7），同样不在签名内，relay 原样转发。

**校验清单 A（relay，收到节点开的流）**，按顺序，第一个失败的决定 `Ack.status`。1 到 8 是 relay 的本地校验，9 向控制面查询（答案缓存），10 是 relay 自己知道的在线状态：

1. LP 长度 ≤ `OPEN_MAX`，消息可解码，`kind` 已知：否则 `BAD_REQUEST`。
2. `kind == CONTROL` 只允许作为流 1 出现一次（5.1），其他流上 `BAD_REQUEST`。
3. `workspace` 等于会话 workspace（握手时后端给的）：`WORKSPACE_MISMATCH`。
4. `from` 等于会话身份：`FROM_MISMATCH`。
5. `to` 等于本 relay 的身份：`BAD_REQUEST`（发起方写错了下一跳，常见于改派期间的旧流）。
6. `kind != CONTROL` 时 `sig` 用 `from` 验证：`BAD_SIGNATURE`。
7. `|issued_at − now| ≤ 300`：`TIMESTAMP_OUT_OF_WINDOW`。
8. `(from, nonce)` 未见过，记入 `NONCE_CACHE_TTL` 缓存：`REPLAY`。
9. 选路与预检：后端不可达且无缓存：`CONTROL_NOT_READY`。否则向后端发 `RelayLookup{stream{workspace, from, kind, proto, domain, port, executor}}`（5.8），命中缓存则不发。控制面依次做三件事，任何一步失败都把应回的状态码放进答案：先选出目的节点，`TCP` 先查服务表（`tcp.domain` 是某服务的 `fqdn` → 服务节点，HTTP 服务则交给本 relay 的 edge，6.3；在基础域名之下但没有这个服务 `SERVICE_UNKNOWN`；未就绪 `SERVICE_NOT_READY`），否则查路由表（源包含 `from`、协议匹配的条目里最具体的域名匹配：目的为节点 → 出口；`direct`、`reject` 或无匹配 `NO_RULE`，答案带 `rules_version`），`TASK` 的目的节点是 `task.executor`（不在目录 `BAD_REQUEST`）；再查角色（`TCP` 要求 `from` 有 ingress 上限、`TASK` 要求 submitter 上限，目的节点要有 egress / service / executor 上限：`ROLE_NOT_ALLOWED`）；最后用目的节点的策略预检（`server` 模式用中央渲染的，`local` 模式用它随 `Advertise` 上报的，5.3）：请求方的身份集合按目录取 {`from`} ∪ 所在组的公钥 ∪ {workspace 公钥}，对已知维度（协议、域名、端口 / 服务名；任务只看 who）判定，任一 deny 命中或没有 allow 命中：`ACL_DENIED`；HTTP 服务的公网访问者（`from` 为空）只在该服务有 `public_key: "*"` 的 allow 规则且没有覆盖它的 deny 时放行。
10. 目的节点的会话在本 relay 上在线：`TARGET_OFFLINE`（交给 edge 的 HTTP 服务不查这一步）。

通过后 relay 向目的节点开流转发；在此之前不向它发送任何东西。这就是三段式的中间一段：控制面选路与预检，relay 转发。

**校验清单 B（提供侧节点，收到 relay 转来的流或直连的流）**，顺序就是三段式的最后一段：先验签（1 到 7），再校验发起者与动作（8），最后执行（9）：

1. LP 长度与解码、`kind` 已知：`BAD_REQUEST`。
2. `workspace` 等于自己的 workspace：`WORKSPACE_MISMATCH`。
3. `to` 等于送来这条流的会话对端：经中继时是自己所连 relay 的身份，直连时是自己；`kind == TASK` 时 `task.executor` 等于自己；`kind == TCP` 且 `tcp.domain` 是自己某个服务的 `fqdn` 时按服务处理，否则按 egress 处理（本节点须启用 egress）。不符：`BAD_REQUEST`（送错节点的证据，记入日志）。
4. `sig` 用 `from` 验证：`BAD_SIGNATURE`。edge 发起的 HTTP 流 `from` 必须等于 `Welcome.relays` 里某个 relay 的公钥。
5. `|issued_at − now| ≤ 300`：`TIMESTAMP_OUT_OF_WINDOW`。
6. `(from, nonce)` 未见过：`REPLAY`。
7. 验证 `StreamOpen.certs` 中签发者等于生效策略某条规则 `public_key` 的成员证书（5.7），身份集合 = {`from`} ∪ 通过验证的签发者；没有规则的 `public_key` 在身份集合里且没有 `*` 规则：`UNKNOWN_PEER`。
8. 生效策略（本地或下发，5.6）对「发起者的身份集合，动作：协议、域名、端口 / 工具名、argv 前缀 / 服务名」判定：`POLICY_DENIED`、`PORT_NOT_ALLOWED`、`UNSUPPORTED_TOOL`、`INVALID_ARGUMENTS`、`BUSY`。
9. 执行（拨号、启动进程）：`DIAL_FAILED`、`RESOLVE_FAILED`、`TIMEOUT`。

`relay.from_name` 只用于日志，不参与任何判断。

### 4.2 Ack

接收方（目的节点，或在 relay 自己拒绝时由 relay）回写的第一条消息是 LP 编码的 `Ack`。`status == OK` 后才允许发送该方向的其他数据。`status != OK` 时发送方发完 Ack 立即 `Reset()`。目的节点在 `responder` 里填自己的身份；relay 把目的节点的 Ack 原样转发给发起方，只在 `trace_id` 为空时填入；relay 自己产生的 Ack 里 `responder` 为空、`rules_version` 是控制面答案里的路由表版本。发起方用 `responder` 写决策日志和记住域名对应的出口（P2P，2.6），不用它做任何授权判断。

发起方等待 Ack 最多 `ACK_TIMEOUT`，超时按 `TIMEOUT` 处理。

### 4.3 各 kind 的后续格式

| kind | 发起方 → 接收方 | 接收方 → 发起方 |
| --- | --- | --- |
| CONTROL | `StreamOpen`，之后 LP `ControlMessage` 序列（节点发出的不签名） | `Ack`，之后 LP `ControlMessage` 序列（agentserver 发出的在 `Signed` 信封里，5.1） |
| TCP | `StreamOpen`，紧接着裸字节（可在 Ack 之前开始） | `Ack`，之后裸字节 |
| TASK | `StreamOpen`（含完整请求），然后 FIN | `Ack`，然后恰好一条 LP `TaskResult`，然后 FIN |

### 4.4 半关闭、RESET、超时与背压

| 事件 | yamux 流上 | 对应的 TCP 或进程 |
| --- | --- | --- |
| 本地连接读到 EOF | `CloseWrite()`（FIN） | — |
| 收到 FIN | — | `TCPConn.CloseWrite()`；进程的 stdin 关闭 |
| 本地连接出错或 RST | `Reset()` | — |
| 收到 RST | — | `Close()`；杀进程由 executor 策略决定（默认不杀，见 7.3） |
| 双向 FIN | `DRAIN_AFTER_FIN` 后释放 | `Close()` |
| 空闲超时 | `Reset()` | `Close()` |
| 会话断开 | 全部流视为 RST | 全部关闭 |

背压：两个方向各一个拷贝循环，缓冲 64 KiB；yamux 每流窗口满时拷贝循环阻塞，TCP 接收窗口随之收紧，源站自然减速。不在任何位置做无界缓冲。

---

## 5. 控制通道

### 5.1 建立：控制流与消息的来回

与 relay 的握手成功后节点必须开的第一条流（yamux 流 ID 1）是控制流：`StreamOpen{open.body.kind = CONTROL, from = 自己, to = relay, workspace, issued_at, nonce}`，`sig` 为空。relay 按清单 A 的 1、3 到 8 校验（`kind` 必须是 `CONTROL`，`to` 是自己），回 `Ack{OK}`，随后立即送达后端在握手答案里给的 `Welcome`。每会话只允许一条控制流，第二条回 `BAD_REQUEST`。

控制流上的每条消息是 LP `ControlMessage`，长度上限 `CONTROL_MSG_MAX`：

- agentserver → 节点的消息（`Welcome`、`Update`、`PolicyUpdate`、`Notice`、`AdvertiseResult`、P2P 信令）一律是 `ControlMessage{signed: Signed}`：`Signed.body` 是序列化的 `SignedBody{recipient, issued_at, msg}`，`sig = Ed25519ctx(该 workspace 的私钥, CTX_CONTROL, body)`，私钥由 agentserver 保管。后端把它装在 `Deliver{identity, signed}` 里交给 relay，relay 原样写进该节点的控制流。节点校验：`sig` 对得上 `workspace.public_key`；`recipient` 等于自己；`|issued_at − now| ≤ OPEN_TIME_WINDOW`；再按消息自己的版本号（`directory_version`、`routes.version`、`PolicyUpdate.version`）丢弃不比当前新的内容。任一失败丢弃并告警（relay 伪造或回放的证据）。
- 节点 → agentserver 的消息（`Advertise`、`PolicyApplied`、`Pull`、`RelayReport`、P2P 信令）直接写在控制流上，不签名；relay 装进 `NodeMessage{identity, msg}` 转给后端，`identity` 是会话身份。

节点收到 Ack 后即可发送 `Advertise`，不必等 `Welcome`。

```
节点                               relay                              agentserver
  │ ── SYN(1) + [StreamOpen CONTROL] ─▶ │                                   │
  │ ◀── [Ack OK] ─────────────────────  │                                   │
  │ ◀── [Signed{Welcome}] ────────────  │  （握手时随 RelayAnswer{node} 取得）│
  │ ── [Advertise] ──────────────────▶  │ ── NodeMessage{laptop, Advertise} ─▶ │
  │ ◀── [Signed{AdvertiseResult}] ────  │ ◀── Deliver{laptop, Signed} ─────── │
  │ ◀── [Signed{Update}] … ───────────  │ ◀── Deliver … ────────────────────  │  增量，随时
  │ ── [Pull] ───────────────────────▶  │ ── NodeMessage{laptop, Pull} ─────▶ │  需要时
  │ ◀── [Signed{Welcome}] ────────────  │ ◀── Deliver{laptop, Signed} ─────── │  对 Pull 的回应是一次全量
```

控制流被 RST 或关闭等同于会话失效：双方关闭会话并重连；relay 向后端报告节点离线。后端不可达时 relay 保持控制流，但没有新消息可送，节点发来的消息排队最多 `RELAY_LOOKUP_TIMEOUT` 后丢弃并记日志（节点重连后会重发 `Advertise`）。

### 5.2 Welcome

全量状态，在 `Signed` 信封里：relay 握手时从后端的 `node` / `join` 答案取得，控制流打开后送达；对 `Pull` 的回应也是一份。服务端按节点的角色上限裁剪：`routes`（分流表）只发给有 ingress 上限的节点；`executors` 只发给有 submitter 上限的节点；`directory`、`services`、`self` 发给所有节点；有提供侧角色上限的节点另有 `policy`（5.6）；`memberships` 是本节点当前持有的成员证书（5.7）；`relays`（relay 证书）与 `assigned_relay` 给所有节点（5.8）。`Directory.version` 与 `IngressRoutes.version` 都是 workspace 内单调递增的整数，任何变更都加一；`IngressRoutes.version` 等于渲染它的路由表版本，与 relay 答案里的 `rules_version` 同源。

分流表的渲染（设计文档 6.5）：取路由表里源包含该节点（节点本身、它所在的组或 workspace）的条目，每条保留协议与域名模式，目的只保留种类（`VIA` / `DIRECT` / `REJECT`）、丢掉出口节点；顺序与 `default` 照抄。ingress 按「最具体的匹配赢」判定，判为 `VIA` 的域名交给会话；路由表本身不在线上传输。

节点侧不过滤：`routes`、`directory`、`services`、`executors` 都接受；分流表只决定直连还是交给 relay，目录只用于显示和复制公钥，都不授予权限。

### 5.3 Advertise 与生效策略的上报

节点在控制流就绪后、以及本地配置热更新后发送 `Advertise`，relay 以 `NodeMessage` 转给后端，整体替换上一次的声明。内容：

- `services`：每个 `proto: http` 或 `ssh` 服务的名字、协议。
- `executor`：描述、工具列表。
- `policy_sources`：egress、service、executor 各自的 `local` 或 `server`（5.6）。
- `policy`：来源为 `local` 的角色上报自己的生效策略（只填对应的组），形态与 `PolicyUpdate.policy` 相同（`public_key` 本来就是公钥或 `*`，不需要解析）。控制面用它做转发预检（4.1 清单 A 第 9 步）和 HTTP 服务的边缘判定；本地策略仍逐条执行。来源为 `server` 的角色不填，控制面用自己渲染的那一份。
- `p2p_enabled`：是否加入 P2P 发现（v1 恒为 false，2.6）。

服务端校验：声明的角色在 `role_caps` 内（否则 `ROLE_NOT_ALLOWED`，整个 Advertise 拒绝）；服务名合法且在 workspace 内未被其他节点或服务占用（否则该服务进入 `rejected_services`，其余生效）；描述与工具描述截断到 512 字节；`policy` 里的 target 只能是字面模式。经 `Deliver` 回签名的 `AdvertiseResult`，其中 `services` 带上分配的 `fqdn` 与 `state`。通过的内容进入目录并通过 `Update` 推给其他成员；服务或策略变化时向 relay 推 `RelayInvalidate`。

### 5.4 Update 与 Pull

- `Update` 是增量（在 `Signed` 信封里，每个收件节点一份）：目录用 `upsert_members` / `removed_members` 加新的 `directory_version`；路由表变更时整体替换 `routes`；服务与 executor 用 upsert / removed；在线状态用 `presence`，服务端合并后至多每秒推一次；成员证书续发用 `memberships`，吊销用 `revoked_memberships`（5.7）；`relays` 更新 relay 证书列表，`assigned_relay` 变化时节点关闭当前会话、连新 relay（5.8）。
- 节点若发现 `directory_version` 不是严格递增（丢了中间版本），或在 `NO_RULE` 的 Ack 里看到比自己分流表新的 `rules_version`，发送 `Pull`，服务端回一次完整 `Welcome`。
- 版本一致性：relay 产生的 Ack 带控制面选路所用的 `rules_version`。ingress 收到 `NO_RULE` 时，若该版本比自己的分流表新，就 `Pull` 后按新表重新判定这条连接（多半变成直连或拒绝）；版本相同或更旧（relay 的缓存落后）则按 `fallback` 处理并记录。

### 5.5 Notice

`Notice` 由 agentserver 签发（`Signed`）；唯一的例外是 relay 自己关闭或替换会话时发的 `Notice{SHUTDOWN}`，不签名，节点只据此决定重连时机。

| kind | 服务端随后的动作 | 节点的动作 |
| --- | --- | --- |
| SHUTDOWN | 关闭连接 | 按 `retry_after_seconds` 重连，没有则按退避 |
| REMOVED | 关闭连接 | 停止重连，`agentd status` 显示「已被移出」，等待用户重新 join |
| RENAMED | 无 | 更新本地显示名；配置里的 `name` 由节点改写 |
| ROLES_CHANGED | 无 | 更新角色上限，超出上限的本地角色停用并告警 |
| MESSAGE | 无 | 记录日志 |

### 5.6 策略下发

消息：`PolicyUpdate{version, policy}`（agentserver → 节点，在 `Signed` 信封里）与 `PolicyApplied{version, applied, message}`（节点 → agentserver，经 relay 转交）。提供侧节点的 `Welcome` 里也带一份完整的 `PolicyUpdate`。模型与渲染算法见设计文档 6.6 到 6.8。

- `policy` 是为该节点渲染好的全量策略，三组：`egress`、`exec`、`services`；每条是 `(public_key, action, target)`，`public_key` 是一把公钥，为空表示 `*`，域名只有 `DOMAIN` / `SUFFIX` 两种字面模式。`version` 是该节点自己的版本号，单调递增；内容没变不重发。
- 节点处理：对 `policy_source: server` 的角色原子替换该组生效的下发策略，叠加本地配置里的 deny 规则；对 `local` 的角色丢弃该组。回 `PolicyApplied{version, applied}`，`applied` 为真表示至少有一个角色应用了它。
- 服务端处理：记录每个节点最近 `applied` 的版本；`PolicyApplied` 在 10 秒内未到则重发一次，再失败记录告警，不影响会话。
- 节点在 `Advertise.policy_sources` 里按角色报告来源。agentserver 回答 relay 的流查询（4.1 清单 A 第 9 步）时按目的角色选用预检的策略：`server` 用自己渲染的，`local` 用节点随 `Advertise` 上报的生效策略（5.3）；service 角色为 `server` 时服务的访问控制以中央策略为准。
- 判定语义（节点与边缘一致）：任一 deny 命中即拒绝；否则任一 allow 命中即允许；否则拒绝。target 的匹配：egress 为 `proto` 等于规则的协议、域名匹配任一模式、端口在 `ports` 内（未给则按协议默认 443 / 22）；exec 为 argv 前缀匹配，`stdin` / `shell` 只在 allow 规则上有意义；service 为服务名相等。
- 本地配置的书写形态与下发的完全相同：`public_key` 是一把公钥（节点、组或 workspace 的，base64url 43 字符，可带 `agentd://` 前缀）或 `*`，没有别名；多把公钥就写多条；egress 规则一条一个协议；target 一律是字面的域名模式、argv 前缀或服务名；节点上没有集合的概念（域名集合第一期不做，将来也只在 agentserver 上展开）。

### 5.7 成员证书

组与 workspace 各有一对 Ed25519 密钥，由 agentserver 保管（设计文档 6.8）；workspace 密钥还签发给成员的控制消息与 relay 证书，是成员唯一钉住的信任根。成员资格以证书表达，证书签给成员、由成员随请求出示，接收方据此把组公钥或 workspace 公钥算进请求方的身份集合。

```
MembershipCert { body: bytes(MembershipCertBody), sig }
MembershipCertBody { member, issuer, workspace, issued_at, expires_at, name }
sig = Ed25519ctx(issuer 的私钥, ctx = "agentd/membership/v1", body)
```

- `issuer` 是组公钥或 workspace 公钥；`name` 是组名（workspace 证书为空），只供显示。
- 有效期 `MEMBERSHIP_TTL`（默认 3600 秒）。agentserver 在 `Welcome.memberships` 里发给节点它当前的全部证书；剩余有效期不足 `MEMBERSHIP_RENEW`（1800 秒）时经 `Update.memberships` 续发新证书；节点以 `(member, issuer)` 为键保留最新一份。
- 吊销：成员离组或离开 workspace 时，agentserver 停止续发，并向该 workspace 的全部节点推送 `Update.revoked_memberships`，每条是 `(member, issuer, until)`，`until` 取已签发证书里最晚的 `expires_at`；节点保留吊销记录到 `until`。被移出 workspace 的节点同时收到 `Notice{REMOVED}`。
- 发起方开流时把自己持有的全部有效证书附在 `StreamOpen.certs`，最多 `OPEN_MAX_CERTS`（16）份，超出回 `BAD_REQUEST`。证书不在 `Open` 的签名内，中继可以丢弃它们（只会导致拒绝），不能伪造。
- 接收方（清单 B 第 7 步）：只检查签发者出现在自己生效策略里的证书，其余忽略。每份证书要求：`sig` 对得上 `issuer`；`body.member == OpenBody.from`；`body.workspace` 等于自己的 workspace；`issued_at ≤ now + 300`；`expires_at > now`；`(member, issuer)` 不在吊销记录里。通过的证书的 `issuer` 加入请求方的身份集合，与 `from` 一起参与策略判定。
- relay 转发时原样保留 `StreamOpen.certs`；控制面的预检按目录里的成员关系算请求方的身份集合，不依赖证书。
- `Directory` 里带组列表（组名、组公钥、成员）和 workspace 公钥，供 `agentd peers` 显示、复制进规则；节点判定不读目录。
- 组的管理：`agentserver group create|delete|add|remove|list --workspace <ws>`。新建组时生成密钥对；删除组时向全部节点推送该组公钥的吊销（`issuer` 维度，`member` 为空表示全部成员）。

### 5.8 relay 与后端

relay 以自己的 Ed25519 身份作 Noise_IK 发起方连到 agentserver（`control.url`），`ClientHello.session_kind = RELAY`，后端按 relay 注册表（`agentserver relay add`）认公钥。relay 每次连接都在 `ClientHello.relay`（`RelayRegistration`）里报告名字、对节点公布的 https URL、各 transport 路径与 STUN 地址，后端据此更新注册表与 relay 证书；公钥尚未登记时，`ClientHello.join_token` 是 relay 注册令牌（admin API `POST /relays/tokens` 签发的一次性令牌，或 `relay_join_token_env` 的长期引导令牌），校验通过且名字未占用则登记，否则回 `TOKEN_INVALID`、`BAD_NAME` 或 `NAME_TAKEN`。relay 会话上 relay 是 yamux client，只开一条流（`StreamOpen{kind: CONTROL, from: relay, to: agentserver}`），承载下表的 LP `ControlMessage`。

| 方向 | 消息 | 内容 |
| --- | --- | --- |
| relay → agentserver | `RelayLookup` | 按需查询，四种：`node{identity}`（握手：这把公钥是谁、哪个 workspace、名字、角色上限、是否指派给我）；`join{identity, token, proposed_name, workspace}`（带令牌的握手，后端按 8.3 处理加入）；`stream{workspace, from, kind, proto, domain, port, executor}`（转发一条流：后端先选路、再查角色、再用目的节点的策略预检，返回目的节点与路由表版本，或应回给发起方的状态码；`from` 为空表示 edge 公网 443 上的匿名访问者，只能问 HTTP 服务）；`cert{workspace}`（edge 缺该 workspace 的通配证书） |
| agentserver → relay | `RelayAnswer` | 对应 `request_id` 的答案：`status`、`ttl_seconds`，以及 `node` / `route` / `certs` 之一。`node` 答案含 workspace、名字、角色上限和签好名的 `Welcome`；错误答案同样可缓存（`join` 的答案不缓存） |
| relay → agentserver | `NodeMessage` | 某节点在控制流上发来的消息（`Advertise`、`PolicyApplied`、`Pull`、`RelayReport`、P2P 信令），`identity` 是会话身份，relay 以此证明来源 |
| agentserver → relay | `Deliver` | 发给某节点的控制消息，已在 `Signed` 信封里；relay 原样写进该节点的控制流，节点不在线则丢弃（它重连时会拿到新的 `Welcome`） |
| relay → agentserver | `RelayPresence` | 上线与下线的节点公钥；relay 会话重建后先报一遍全部在线节点 |
| agentserver → relay | `RelayInvalidate` | 某 workspace 的目录、路由表、服务、策略或证书变了：relay 丢弃该 workspace 的全部缓存（`workspace` 为空表示全部）；`removed` 里的节点若有会话立即关闭 |
| agentserver → relay | `WorkspaceCerts` | 服务域名的通配证书与私钥，签发或续期时推送（也是 `cert` 查询的答案）；relay 只在内存持有，同 workspace 的新证书替换旧的 |
| agentserver → relay | `RelayCert` | relay 在它服务的每个 workspace 的身份证书（由该 workspace 密钥按 `CTX_RELAY` 签，`body.workspace` 标明，有效期 `RELAY_CERT_TTL`），会话建立时与续签时推送；relay 在 `/.well-known/agentd` 上按 workspace 公布 |

- 缓存：`node` 与 `stream` 的答案以查询内容为键缓存 `ttl_seconds`（后端默认给 `RELAY_CACHE_TTL`），LRU 有界 `RELAY_CACHE_MAX`；`RelayInvalidate` 按 workspace 整体清除。`Welcome` 不缓存：每次握手的 `node` 答案都带当前的一份。relay 不持有目录、路由表或策略的副本，也不自己做选路或策略判定，这些逻辑只有 agentserver 一处实现。
- 后端不可达：已有会话与已缓存的答案继续工作；缓存未命中的握手回 `ServerHello{CONTROL_NOT_READY}`，未命中的流回 `Ack{CONTROL_NOT_READY}`，发起方退避重试；控制流上收到的节点消息最多排队 `RELAY_LOOKUP_TIMEOUT` 后丢弃；证书到期不再续。relay 会话重新就绪时 relay 清空全部缓存，重报在线节点（`RelayPresence`），后端随后推各 workspace 的证书，并为在线节点重新送达 `Welcome`。
- 查询超时 `RELAY_LOOKUP_TIMEOUT`，超时按后端不可达处理；同一键的并发查询合并为一次。
- `Welcome.relays` 列出该 workspace 可用 relay 的证书（名字、公钥、各 transport 的 URL、STUN 地址、有效期），`Welcome.assigned_relay` 是当前指派；节点只连指派的那一个，`Update.assigned_relay` 变化时关闭当前会话、连新的。节点连续 3 次连不上当前 relay 时换列表里的下一个，并在就绪后发 `RelayReport`；后端据此改派并在 `Update.assigned_relay` 里通知。

---

## 6. tcp 流

### 6.1 ingress → egress

```
ingress                        relay                                    egress
  │ SYN + [StreamOpen tcp] + ClientHello 字节 ─▶│                                  │
  │                               │ 清单 A；问控制面：选出口、预检        │
  │                               │ ── SYN + [StreamOpen(+relay)] + 字节 ────────▶ │
  │                               │                                  清单 B；策略；并行：拨号 domain:port
  │                               │                                  缓冲首段数据（≤ 16 KiB）
  │                               │                                  拨通后复核协议（6.4），转发缓冲
  │                               │ ◀── [Ack OK] ────────────────────────────────  │
  │ ◀── [Ack OK] ─────────────────│                                                 │
  │ ◀═══════════════════ 双向裸字节 ═══════════╪═══════════════════════════════════▶ │
```

- `StreamOpen.open.body.tcp = {proto, domain, port}`，`to` 是 relay 的身份；ingress 只凭分流表知道这个域名要交给下一跳，不知道出口。relay 向控制面查询（清单 A 第 9 步，答案缓存），控制面用路由表选出出口；`direct` / `reject` / 无匹配回 `NO_RULE` 并带 `rules_version`。
- 首段数据紧跟 `StreamOpen` 发送，不等 Ack。ingress 本地保留一份直到收到 Ack，以便回退直连时回放。
- egress 的 Ack 在拨号结束后发送：成功 `OK`；失败 `RESOLVE_FAILED`、`DIAL_FAILED`（连接被拒等）、`TIMEOUT`（`EGRESS_DIAL_TIMEOUT`）。策略拒绝则不拨号，直接 `POLICY_DENIED`、`PORT_NOT_ALLOWED`。
- ingress 对 Ack 错误的处理：`NO_RULE` 且 Ack 的 `rules_version` 比自己的分流表新时先 `Pull`，再按新表重新判定这条连接；`TARGET_OFFLINE`、`CONTROL_NOT_READY` 与其余的 `NO_RULE` 按配置 `fallback`（默认直连回放）；其余向本地连接 RST 并记录决策日志。目的地是 fake-IP 或服务域名时不回退。`Ack{OK}.responder` 是实际服务的 egress，写进决策日志。
- 端口：`proto: tls` 默认 443，`proto: ssh` 默认 22；egress 策略可配 `ports` 列表。

### 6.2 ingress → ssh 服务节点

与 6.1 相同，差别：

- `to` 仍是 relay；控制面在回答 relay 的查询时用服务表而不是路由表选出服务所在节点，并用该节点的策略预检；`domain` 必须等于服务的 `fqdn`，`port` 必须等于服务声明的端口（SSH 为 22），否则 `BAD_REQUEST`。
- 节点侧：`to` 是自己所连的 relay；按 `domain` 找到服务配置，按 `service` 规则判定发起者，拨号 `target`。

### 6.3 HTTP 服务：经 edge

两段，各是一条 `tcp` 流、各有自己的 `Open` 与签名；第一段的 `to` 是 relay（下一跳，也是 TLS 的终点），第二段的 `from` 是 relay、`to` 是服务节点。laptop 的签名只覆盖第一段：

```
ingress ── tcp/tls(domain=nas.home…, port 443, to=relay) ──▶ relay 的 edge ── tcp/http(domain, http_peer, from=relay, to=homepc) ──▶ homepc
```

第一段：

- relay 校验：清单 A，其中第 9 步控制面答复 `target_kind = EDGE`：`domain` 是某个服务的 `fqdn` 且 `proto: http`；`state == READY`（否则 `SERVICE_NOT_READY`）；`port == 443`；服务节点的 `service` 规则允许 `from`（公钥命中或 `*`）。回 `Ack{OK}`，然后把这条流当作一个 `net.Conn` 交给 edge 的 TLS 监听逻辑：用控制面下发的该 workspace 通配证书终结 TLS，ALPN 提供 `h2` 与 `http/1.1`。
- 公网直连 443 的访问不经这一段，直接进入 edge 的 TLS 监听，身份为空；relay 以空 `from` 向控制面查询该 `fqdn`（答案缓存），没有 `public_key: "*"` allow 规则的服务回一个固定的 403 说明页。

第二段（edge 作为 HTTP/1.1 客户端）：

- edge 为每个服务节点维护一个 HTTP/1.1 连接池，每条「连接」是一条 `tcp` 流：`StreamOpen{kind TCP, from = relay 身份, to = 服务节点, tcp = {proto HTTP, domain = fqdn, http_peer = {identity, name} 或空}}`，由 relay 的 Ed25519 密钥签名。
- 节点按清单 B 校验（`from` 必须是 `Welcome.relays` 里某个 relay 的公钥），按 `domain` 找到服务配置，回 `Ack{OK}`，然后把流当作一条 HTTP/1.1 服务端连接：解析请求，反向代理到 `target`（明文 HTTP，保留原始 Host，设计文档 5.4），支持 keep-alive 与 WebSocket 升级。
- edge 注入的头：`X-Forwarded-For`、`X-Forwarded-Proto: https`、`X-Forwarded-Host`；成员访问时 `X-Agentd-Peer: <name>`、`X-Agentd-Peer-Key: <公钥>`；公网访问时剥离客户端自带的这两个头并不再注入。

`http_peer` 不参与签名以外的校验；节点只把它作为日志与可选的本地访问控制输入。

### 6.4 协议复核（提供侧）

- `proto: tls`：在把客户端字节转发给源站之前，累积到完整的第一个 TLS record（按 record 头长度，上限 16 KiB、5 秒），解析 ClientHello，SNI 必须等于 `domain`（不区分大小写）。不是 ClientHello、没有 SNI 或不一致：`PROTOCOL_MISMATCH`，RST。源站方向的字节可以先行转发。
- `proto: ssh`：客户端首行（到 CRLF，上限 255 字节）必须以 `SSH-` 开头；在此之前不把客户端字节转给源站，但源站字节可以先行转发（旧客户端先等服务端 banner）。不符：`PROTOCOL_MISMATCH`，RST。
- `proto: http`（edge → 节点）：不复核。

### 6.5 空闲与关闭

- `IDLE_TIMEOUT_TLS` 用于 `proto: tls` 与 `http`，双向无数据即超时；`proto: ssh` 不设空闲超时。
- 关闭语义按 4.4 的映射表。提供侧对拨出的 TCP 连接开启 `TCP_KEEPALIVE`，`TCP_NODELAY` 保持开启。

---

## 7. task 流

### 7.1 时序

```
submitter                      relay                                    executor
  │ SYN + [StreamOpen task] + FIN ─▶│                                           │
  │                                 │ 清单 A；问控制面：task.executor 的角色、预检
  │                                 │ ── SYN + [StreamOpen(+relay)] + FIN ─────▶ │
  │                                 │                                 清单 B；去重；解析参数；策略
  │                                 │ ◀── [Ack OK] ─────────────────────────────  │ 启动进程，等 yield_time_ms
  │ ◀── [Ack OK] ───────────────────│                                              │
  │ ◀── [TaskResult] + FIN ─────────┼───────────────────────────────────────────  │
  │ 验签，渲染给 AI agent             │                                              │
```

发起方发完 `StreamOpen` 就 `CloseWrite()`；executor 在 Ack 之后恰好发送一条 `TaskResult` 并 `CloseWrite()`。

### 7.2 签名与校验

请求：`OpenBody.task = {executor, call}`，`executor` 是目标 executor 的身份，`call = FunctionCall{call_id, name, arguments}`，整体在 `Open` 的签名内；`to` 是下一跳（relay，直连时是 executor 自己）。

结果：`TaskResult{body = bytes(TaskResultBody), sig}`，`sig = Ed25519ctx(sk_executor, "agentd/task-result/v1", body)`。`TaskResultBody` 含 `call_id`、`from`（executor）、`to`（submitter）、`issued_at`、`output`、`final = true`。

submitter 校验：`sig` 用 `OpenBody.task.executor` 的公钥验证；`body.from == OpenBody.task.executor`；`body.to == 自己`；`call_id` 相同；`|issued_at − now| ≤ 300`。任一失败按「结果未知」处理并记录「可能被篡改」。

### 7.3 去重、重试与超时

- executor 以 `(from, call_id)` 为键：
  - 已有完成的结果（`TASK_DEDUP_TTL` 内）：不执行，回 `Ack{OK}` 与缓存的 `TaskResult`。
  - 正在执行：附着到进行中的执行，完成时两条流都收到同一结果。
  - 新调用：执行。
  - 同一 `call_id` 但 `name` 或 `arguments` 不同：`BAD_REQUEST`。
- `nonce` 去重与 `call_id` 去重是两回事：重试必须换新的 `nonce` 和 `issued_at`（否则 `REPLAY`），但沿用 `call_id`。
- submitter 等待 Ack `ACK_TIMEOUT`；等待 `TaskResult` 的上限是 `yield_time_ms + 30 秒`。超时则 RST 流，向调用方报「结果未知」并附 `call_id`；调用方可用同一 `call_id` 重试，取回缓存结果或附着到进行中的执行。
- 流被 RST（会话断开等）不终止已启动的进程：进程按 unified exec 的语义继续存在，`session_id` 仍可用 `write_stdin` 访问，结果进入缓存。executor 的并发与空闲上限由 `limits` 控制。
- 错误分类：到不了执行阶段的问题用 Ack 状态码（`POLICY_DENIED`、`UNSUPPORTED_TOOL`、`INVALID_ARGUMENTS`、`SESSION_NOT_FOUND`、`BUSY`）；进入执行后的问题（启动失败、非零退出、超时截断）都是正常的 `TaskResult`，由 `exit_code`、`is_error`、`error_message` 表达，与 Codex 的 tool output 语义一致。

### 7.4 参数校验

`arguments` 是 JSON 对象。未知字段或不接受的字段一律 `INVALID_ARGUMENTS`，错误信息指出字段名。

`exec_command`：

| 字段 | 类型 | 必填 | 默认 | 范围 | 说明 |
| --- | --- | --- | --- | --- | --- |
| `cmd` | string | 是 | | 1 到 65536 字节 | 由 executor 解析为简单命令序列（设计文档 5.6） |
| `workdir` | string | 否 | 配置的 `workdir` | 清理并解析符号链接后必须位于配置目录之内 | |
| `tty` | bool | 否 | false | | |
| `yield_time_ms` | number | 否 | 10000 | 250 到 30000，超出则钳制 | |
| `max_output_tokens` | number | 否 | 10000 | 1 到配置上限，超出则钳制 | |
| 不接受 | `shell`、`login`、`environment_id`、`justification`、`sandbox_permissions`、`additional_permissions`、`prefix_rule` | | | | `INVALID_ARGUMENTS` |

`write_stdin`：

| 字段 | 类型 | 必填 | 默认 | 范围 | 说明 |
| --- | --- | --- | --- | --- | --- |
| `session_id` | integer | 是 | | 必须是本 executor 上由同一 `from` 创建且仍存在的会话 | 否则 `SESSION_NOT_FOUND` |
| `chars` | string | 否 | 空 | 0 到 1 MiB | 空表示只轮询 |
| `yield_time_ms` | number | 否 | 非空写入 250，空轮询 5000 | 非空写入上限 30000，空轮询上限 300000 | |
| `max_output_tokens` | number | 否 | 10000 | 同上 | |

会话归属：unified exec 会话属于创建它的 `from`；其他节点即使在策略里被允许 `write_stdin`，也不能访问别人的会话。

### 7.5 输出

`FunctionCallOutput.output_text` 由 executor 按 Codex `codex-rs/core/src/tools/context.rs` 的 `response_text` 渲染：

```
Chunk ID: <id>                        （可选）
Wall time: 0.8000 seconds
Process exited with code 0             或  Process running with session ID 3
Original token count: 12345            （截断时）
Output:
<正文>
```

结构化字段（`wall_time_seconds`、`exit_code`、`session_id`、`chunk_id`、`original_token_count`、`output`）与 Codex 的 `unified_exec_output_schema` 对应；submitter 把 `output_text` 作为 MCP 的文本内容，把结构化字段放进 `structuredContent`，`is_error` 映射到 MCP 的 `isError`。正文按 `max_output_tokens` 和配置的字节上限（默认 1 MiB）截断，`original_token_count` 记录截断前的估计值。

---

## 8. 加入、名字与 URI

### 8.1 URI 文法（ABNF）

```
agentd-uri    = "agentd://" ( key-form / name-form )
key-form      = 43base64url                 ; 32 字节 Ed25519 公钥，base64url 无填充
name-form     = ws-domain "/" [ label / ( "group/" label ) ]   ; 空 path 是 workspace 密钥的名字形式，group/<label> 是组
join-link     = "agentd://" ws-domain "/" [label] "?" params
params        = param *( "&" param )        ; 顺序无关，值可百分号编码
param         = ( "relay=" https-url ) / ( "key=" 43base64url ) / ( "token=" 22base64url )
ws-domain     = 1*( label "." ) label       ; workspace 基础域名，小写
label         = ( ALPHA / DIGIT ) [ *61( ALPHA / DIGIT / "-" ) ( ALPHA / DIGIT ) ]   ; RFC 1123，比较时折叠为小写
base64url     = ALPHA / DIGIT / "-" / "_"
```

区分规则：authority 不含 `.` 且恰好 43 个 base64url 字符、无 path，是密钥形式；否则是名字形式。两种形式的等价关系与解析顺序见设计文档 3.1。

### 8.2 加入链接

`agentserver token create` 输出的链接形如：

```
agentd://home.agentsrv.example.com/dorm?relay=https://relay-hk.agentsrv.example.com&key=Ws3kL…&token=Qm9…
```

- `relay`：被指派 relay 的 transport 端点 HTTPS URL（可带非默认端口和路径前缀）。
- `key`：workspace 的 Ed25519 公钥，成员唯一的信任根；用它验证 relay 证书（取自 `<relay>/.well-known/agentd?workspace=<authority>`）、所有控制消息和 workspace 成员证书的签名。缺失时 `agentd join` 从同一端点取 relay 证书里的签发者公钥并打印指纹要求确认。
- `token`：加入令牌。
- path 为空表示名字由设备提出（`--name` 或清洗后的 hostname）。

`agentd join` 把 `relay`、`key`、workspace（authority）、名字写入配置（`workspace.relay.url`、`workspace.public_key`、`workspace.domain`、`metadata.name`），然后按 3.2 与 relay 握手，`ClientHello` 带 `join_token`、`workspace` 与可选的 `proposed_name`；relay 把加入请求转给后端校验（5.8）。

### 8.3 令牌

- 16 字节随机数，文本为 base64url 22 字符；服务端只保存 `SHA-256(令牌)`，以及绑定的 workspace、可选名字、角色上限、过期时间、创建者、使用时间。
- 一次性：加入成功时原子地标记已用；并发的第二次使用得到 `TOKEN_USED`。
- 默认 TTL 24 小时；`agentserver token revoke` 可提前作废。
- 服务端处理加入的顺序：令牌存在且 workspace 与 `ClientHello.workspace` 一致（`TOKEN_INVALID` / `WORKSPACE_MISMATCH`）→ 未用（`TOKEN_USED`）→ 未过期（`TOKEN_EXPIRED`）→ `identity` 不在任何目录（`IDENTITY_IN_USE`）→ 名字 = 令牌的名字或 `proposed_name`，合法（`BAD_NAME`）且未被节点或服务占用（`NAME_TAKEN`）→ 写入目录、标记令牌 → `ServerHello{OK}`。
- 令牌只出现在加入链接、Noise 消息 1 的加密载荷和 relay 转给后端的加入请求里，CDN 读不到，relay 读得到；不进入任何日志。

### 8.4 名字规则

- 实例名、服务名、workspace 名都是 RFC 1123 label：`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`，输入时大写折叠为小写。
- 实例名与服务名共用 workspace 内的名字空间。
- 保留名：`www`、`agentserver`、`group`。
- 建议长度不超过 32，原因见设计文档 3.1。

---

## 9. 状态码总表

| 状态码 | 由谁产生 | 场景 | 发起方的处理 |
| --- | --- | --- | --- |
| `OK` | 任何 | 成功 | 继续 |
| `VERSION_MISMATCH` | 握手（agentserver 或 relay） | 版本无交集 | 停止重连，提示升级 |
| `NOT_A_MEMBER` | relay 握手（后端答复）；relay 会话 | 公钥不在目录（relay 会话：不在 relay 注册表） | 停止重连，提示 join |
| `TOKEN_INVALID` / `TOKEN_USED` / `TOKEN_EXPIRED` | relay 握手（后端答复） | 加入失败 | 提示重新获取链接 |
| `NAME_TAKEN` / `BAD_NAME` | relay 握手（后端答复）、Advertise | 名字问题 | 提示换名字 |
| `IDENTITY_IN_USE` | relay 握手（后端答复） | 公钥已属于其他实例 | 提示先 remove 旧实例 |
| `TIMESTAMP_OLD` | 握手（agentserver 或 relay） | 节点时钟回拨 | 退避重试，提示校时 |
| `IDENTITY_MISMATCH` | 握手（agentserver 或 relay） | 载荷身份与握手密钥不符 | 实现错误，停止 |
| `SERVER_BUSY` | 握手（agentserver 或 relay） | 过载或关闭中 | 按 `retry_after_seconds` 重试 |
| `BAD_SIGNATURE` / `FROM_MISMATCH` | relay 或提供侧 | 签名或来源问题 | 失败并记录；不回退 |
| `TIMESTAMP_OUT_OF_WINDOW` | relay 或提供侧 | 时钟偏差 | 失败，提示校时 |
| `REPLAY` | relay 或提供侧 | nonce 重复 | 换 nonce 重发一次 |
| `ROLE_NOT_ALLOWED` | relay（控制面答复）、Advertise | 角色上限 | 失败并记录 |
| `NO_RULE` | relay（控制面答复） | 路由表里该发起方、协议、域名没有出口（`direct`、`reject` 或无匹配）且不是服务域名 | Ack 的 `rules_version` 比分流表新则 `Pull` 后按新表重判，否则按 `fallback` |
| `TARGET_OFFLINE` | relay | 目标离线 | 按 `fallback` |
| `ACL_DENIED` | relay（控制面答复） | 预检：目的节点的策略（受管为中央渲染的，自管为上报的生效策略）不允许发起方 | 失败并记录 |
| `SERVICE_NOT_READY` / `SERVICE_UNKNOWN` | relay（控制面答复） | 服务状态 | 本地 RST，不回退 |
| `CONTROL_NOT_READY` | relay | 后端不可达且无缓存答案（握手或开流） | 退避重试；流按 `fallback` |
| `WRONG_RELAY` | relay 握手（后端答复） | 节点的 workspace 未指派给这个 relay | 按 `ServerHello.assigned_relay` 换 relay |
| `RELAY_UNAVAILABLE` | agentserver | workspace 当前没有可用 relay | 保持当前会话，等待 `Update.assigned_relay` |
| `WORKSPACE_MISMATCH` / `BAD_REQUEST` | 任何 | 格式或归属错误；`to` 不是收到流的一方、`task.executor` 不是自己 | 失败并记录 |
| `UNKNOWN_PEER` | 提供侧 | 没有规则的 `public_key` 等于 `from` 或其证书签发者，也没有 `*` 规则 | 失败，提示把节点、组或 workspace 公钥写进规则 |
| `POLICY_DENIED` / `PORT_NOT_ALLOWED` | 提供侧 | 本地策略 | 失败并记录 |
| `PROTOCOL_MISMATCH` | 提供侧 | 首段数据与声明不符 | 失败，RST |
| `UNSUPPORTED_TOOL` / `INVALID_ARGUMENTS` / `SESSION_NOT_FOUND` | executor | 任务请求问题 | 作为 MCP 错误返回给调用方 |
| `DIAL_FAILED` / `RESOLVE_FAILED` / `TIMEOUT` | 提供侧 | 拨号失败 | 本地 RST，不回退 |
| `BUSY` | 提供侧 | 并发上限 | 稍后重试 |

---

## 10. 安全要点与实现注意

- 私钥不离开进程所在设备；派生的 X25519 私钥只在内存。密钥文件权限不是 0600 时拒绝启动。
- relay 必须核对 `OpenBody.from` 等于会话身份、`to` 等于自己，必须不改写 `open` 的任何字节，必须在本地校验与控制面答复都通过之后才向目的节点开流；它只信任来自已认证 relay 会话的答案，不自己做选路或策略判定；控制面不可达时只用已缓存的答案，未命中回 `CONTROL_NOT_READY`。
- agentserver 发给节点的每条控制消息都在 `Signed` 信封里，节点验签、核对收件人与时间、按版本号防回放；relay 转交的节点消息以会话身份标明来源，后端只接受来自已认证 relay 会话的 `NodeMessage`，且 `identity` 必须是该 relay 报过在线的节点。
- 三段式的分工不可互换：ingress 不做授权判断、不知道出口；控制面的预检只是提前拒绝，不替代提供侧；提供侧不信任 `RelayInfo` 与 `Ack.responder`，只信签名、证书与自己的策略。
- 所有公钥比较与签名验证用常数时间实现（Go 的 `ed25519.Verify` 与 `subtle.ConstantTimeCompare`）。
- nonce 缓存有界：每个 `from` 至多 10 万条，超出时对该 `from` 回 `BUSY`。`issued_at` 窗口保证缓存只需保留 10 分钟。
- 大小上限在解码之前检查（LP 长度），避免先分配再拒绝。
- 握手未完成的连接不占用业务资源；按 IP 限速。
- 令牌、私钥、`chars`（stdin 内容）不进日志；审计日志记录 argv 时按配置脱敏。
- 节点与 relay 之间的 Noise 会话是 CDN 面前唯一的保护，任何在 transport 层明文携带应用数据的「优化」都不允许。
- 将来若加节点间端到端加密，通过协议次版本协商与新增字段实现，v1 不预留开关。
- Go 实现要点：`golang.org/x/crypto/ed25519` 已并入标准库 `crypto/ed25519`，`Ed25519ctx` 用 `ed25519.Options{Context: ctx}`；Noise 用 `github.com/flynn/noise`，`DHKey` 用派生的 X25519 密钥对；yamux 用 `github.com/libp2p/go-yamux/v5`。

---

## 11. 实现检查清单

agentd：

- [ ] 密钥文件读写、Ed25519 到 X25519 派生、`agentd key show` 两种名字；多实例：`-i` / `AGENTD_INSTANCE` 选实例目录，socket 与服务单元按实例命名，TUN 互斥
- [ ] 三种 transport 的 Dialer，`auto` 回退，TLS 校验，绑定物理接口
- [ ] relay 证书的获取（well-known、`Welcome.relays`）、验签与缓存；与 relay 的 Noise_IK 握手（含 join 载荷）、分帧、Rekey、会话寿命、状态机与退避
- [ ] 控制流：流 1 的打开；`Signed` 信封的验签、收件人与时间窗口、版本单调；`Welcome` / `Update` 的应用、`Pull`
- [ ] `Advertise`（含按角色的 `policy_sources`，自管角色附生效策略）、热更新重发；`PolicyUpdate` 的应用、本地 deny 叠加、`PolicyApplied`
- [ ] 分流表判定（最具体匹配）、`StreamOpen` 构造与签名（`to` = relay、`task.executor`）、Ack 处理（`NO_RULE` 的版本比较、`responder` 记录）、首段数据流水线与回退
- [ ] 成员证书：接收、续期、随 `StreamOpen` 附带、验证与吊销记录
- [ ] 提供侧清单 B、nonce 缓存、策略、协议复核、拨号、关闭语义映射、空闲超时
- [ ] executor：参数校验、去重与附着、进程管理、`TaskResult` 签名、输出渲染
- [ ] submitter：`TaskResult` 验签、超时与「结果未知」、MCP 映射
- [ ] service 节点：HTTP/1.1 服务端连接 over 流、反向代理、ssh 透传
- [ ] 决策日志字段：trace_id、域名来源、协议、分流表判定、`responder`、状态码、耗时

agentserver（控制面，后端）：

- [ ] relay 会话的 transport 端点与 Handler；XHTTP 会话表、重排、GC；未认证连接限速；admin API
- [ ] Noise_IK 响应方（relay 会话）、校验顺序、会话替换
- [ ] relay 注册、relay 证书按 (relay, workspace) 用 workspace 密钥签发与续签、指派；`RelayLookup` 应答（`node`、`join`、`stream`：选路 → 角色 → 预检、`cert`）；`NodeMessage` 的处理与 `Deliver` 的下发；`Signed` 信封的签名；变更时的 `RelayInvalidate`；`WorkspaceCerts`；`RelayPresence` 汇总；`RelayReport` 改派
- [ ] 目录、令牌（哈希、一次性、时间戳记忆）、名字唯一性、角色上限；路由表与分流表渲染（按节点、去掉目的）；`Welcome` 裁剪；`Update` 合并与节流
- [ ] 分组与中央策略：渲染、哈希比对、`PolicyUpdate` 下发与 `PolicyApplied` 跟踪；自管节点上报策略的存储；预检判定；边缘判定
- [ ] 组与 workspace 密钥、成员证书签发与续期、吊销推送
- [ ] ACME：每 workspace 通配证书、续期、`cert_pending` 状态、`publish_dns`
- [ ] 状态库、备份、密钥加密存放

agentrelay（数据面与节点接入）：

- [ ] 443 按 SNI 分流（节点会话 transport、well-known、edge）；80 跳转；UDP 3478 STUN
- [ ] relay 会话：Noise_IK 发起方、`RelayLookup` / `RelayAnswer`、`NodeMessage` / `Deliver`、`RelayPresence`、TTL 缓存与 LRU、`RelayInvalidate`、`WorkspaceCerts`、`RelayCert`，后端不可达时的缓存保留与 `CONTROL_NOT_READY`
- [ ] hub：节点会话的握手（`node` / `join` 查询、`WRONG_RELAY`）、替换、保活、在线状态
- [ ] control：控制流的终结、`Welcome` 送达、节点消息转交、后端消息送达
- [ ] forwarder：清单 A（本地校验 → `stream` 查询 → 在线 → 转发）、`NO_RULE` 带版本、转发与 Ack 透传、`relay` 填充
- [ ] edge：TLS 终结（后端下发的证书，内存持有）、按后端答案判定访问者、反向代理、头注入、连接池

集成测试（`internal/sim`）：

- [ ] 四节点、一个控制面、一个 relay 在一个进程里：握手与加入（经 relay 转后端）、`Welcome` 签名与验签、目录推送、分流表推送、relay 查询与缓存失效
- [ ] tcp 流经 egress：正常、SNI 不符、策略拒绝、目标离线回退、Ack 超时
- [ ] task 流：正常、重试同 `call_id`、重放同 nonce、参数非法、输出签名被篡改
- [ ] 会话替换、后端重启后 relay 与节点的恢复、分流表过旧时由 `NO_RULE` 触发的 `Pull` 与重判、后端不可达时 relay 的缓存行为
- [ ] 恶意 relay 模型：改 `body`、伪造 `from`、把任务送给别的 executor、把服务流送给别的节点、伪造 `TaskResult`、伪造或回放 `Welcome` / `PolicyUpdate` / `Update`，全部被提供侧、submitter 或节点的验签拒绝；恶意后端模型：伪造不了任何节点签名

## 12. 状态机

实现时每个实体一个显式的状态变量，所有转移都在这里列出；没有列出的事件在该状态下一律忽略并记日志。表的列是：当前状态、事件、动作、下一状态。

### 12.1 节点在 workspace 中的生命周期

节点侧（持久化在实例目录的 `config.yaml` 与 `state/`；一台设备上的多个实例各自独立走这张表）：

| 状态 | 事件 | 动作 | 下一状态 |
| --- | --- | --- | --- |
| `Unjoined`（有密钥，没有 workspace 配置） | `agentd join <链接>` | 解析链接，写入 `workspace.public_key`、`workspace.relay.url`、`workspace.domain`、`metadata.name`；按 workspace 取 relay 证书并验签；建会话，`ClientHello` 带令牌 | `Joining` |
| `Joining` | `ServerHello{OK}` | 持久化目录里的名字与角色上限 | `Member` |
| `Joining` | `ServerHello{TOKEN_*, NAME_TAKEN, BAD_NAME, IDENTITY_IN_USE, WORKSPACE_MISMATCH}` | 报错，删除刚写入的 workspace 配置 | `Unjoined` |
| `Joining` | transport 失败、超时 | 退避重试，最多 5 次 | `Joining` / `Unjoined` |
| `Member` | 会话就绪（12.2） | 收签名的 `Welcome`；策略与证书的接收；数据流可用 | `Member`（在线） |
| `Member` | 会话断开 | 退避重连；进行中的流按 12.4 处理 | `Member`（离线） |
| `Member` | `Notice{RENAMED}` / `Notice{ROLES_CHANGED}` | 更新名字、角色上限；超出上限的本地角色停用并告警 | `Member` |
| `Member` | `Notice{REMOVED}` 或 `ServerHello{NOT_A_MEMBER}` | 停止重连，关闭会话与所有流，保留密钥 | `Removed` |
| `Member` | `agentd leave` | 发送 `Notice{MESSAGE}` 不需要；关闭会话，删除 workspace 配置与 `state/`，保留密钥 | `Unjoined` |
| `Removed` | `agentd join <新链接>` | 同 `Unjoined` 的 join | `Joining` |

agentserver 侧（目录里每个成员）：

| 状态 | 事件 | 动作 | 下一状态 |
| --- | --- | --- | --- |
| （无） | relay 转来的加入请求通过 | 写目录；令牌作废；答复 relay（节点信息与签名的 `Welcome`）；向其他成员推 `Update`；重渲染受管节点的策略 | `Registered/Offline` |
| `Registered/Offline` | relay 的 `node` 查询（握手）或 `RelayPresence` 上线 | 答复节点信息与签名的 `Welcome`；推在线状态 | `Registered/Online` |
| `Registered/Online` | `RelayPresence` 下线，或 relay 会话断开 | 推离线状态；受管策略与证书续发暂停 | `Registered/Offline` |
| `Registered/*` | `agentserver node rename / set-roles` | 改目录；推 `Update`；对该节点发 `Notice{RENAMED / ROLES_CHANGED}`；推 `RelayInvalidate`（relay 重新查询） | 不变 |
| `Registered/*` | `agentserver node remove` 或节点 `leave` | 发 `Notice{REMOVED}`（若在线）并关闭会话；目录移除；推 `Update.removed_members`；停止续发证书并推吊销；向 relay 推 `RelayInvalidate{removed}`；重渲染 | `Removed`（历史记录） |

### 12.2 会话（节点侧，一条到 relay 的会话）

| 状态 | 事件 | 动作 | 下一状态 |
| --- | --- | --- | --- |
| `Idle` | 启动、退避到期或换 relay | 校验目标 relay 的证书（无效则换下一个）；按 12.3 建 transport | `Connecting` |
| `Connecting` | transport 就绪 | 发 Noise 消息 1（首次加入带令牌），启动 `HANDSHAKE_TIMEOUT` | `Handshaking` |
| `Connecting` | transport 失败 | 记一次 transport 失败（供 `auto` 切换）与 relay 失败计数 | `Backoff` |
| `Handshaking` | `ServerHello{OK}` | 建 yamux；开流 1，写 `StreamOpen{CONTROL}`，启动 `CONTROL_OPEN_TIMEOUT` | `ControlOpening` |
| `Handshaking` | `ServerHello{SERVER_BUSY}` / `CONTROL_NOT_READY` | 按 `retry_after_seconds` 等待 | `Backoff` |
| `Handshaking` | `ServerHello{WRONG_RELAY}` | 记下附带的 relay 证书，关闭连接 | `Idle`（连新 relay） |
| `Handshaking` | `ServerHello{NOT_A_MEMBER}`、`TOKEN_*` 等加入失败 | 交给 12.1 | `Stopped` / `Idle` |
| `Handshaking` | `ServerHello{VERSION_MISMATCH}` | 提示升级 | `Stopped` |
| `Handshaking` | 解密失败（relay 密钥与证书不符）、超时 | 记 relay 失败计数；换下一个 relay | `Backoff` |
| `ControlOpening` | `Ack{OK}` | 发 `Advertise`，等待 `Welcome` | `Ready` |
| `ControlOpening` | Ack 错误或 `CONTROL_OPEN_TIMEOUT` | 关闭连接 | `Backoff` |
| `Ready` | 收到 `Signed` 消息 | 验签、收件人、时间窗口、版本单调，通过则应用，否则丢弃并告警 | `Ready` |
| `Ready` | yamux 保活超时、连接错误、解密失败、控制流被关闭 | 关闭连接；数据流全部视为 RST（12.4） | `Backoff` |
| `Ready` | `Notice{SHUTDOWN}` | 关闭连接，按 `retry_after_seconds` 等待 | `Backoff` |
| `Ready` | 会话年龄到 `SESSION_MAX_AGE` 软上限且无活跃流，或到硬上限 | 先建新会话再关旧会话 | `Connecting`（新实例） |
| `Ready` | `Update.assigned_relay` 变化 | 关闭当前会话 | `Idle`（连新 relay） |
| `Ready` | 节点被 `REMOVED` / `leave` | 关闭 | `Stopped` |
| `Backoff` | 退避到期 | 退避按 `RECONNECT_BACKOFF` 增长；会话曾就绪满 60 秒则归零；同一 relay 连续失败 3 次则换 `Welcome.relays` 里的下一个并在就绪后发 `RelayReport` | `Idle` |

relay 侧每条节点会话：`Accepted → AwaitHello（5 秒超时 → 关闭）→ Resolving（`node` / `join` 查询或缓存，`RELAY_LOOKUP_TIMEOUT`）→ Authenticated（报在线；接受数据流与流 1）→ ControlReady（流 1 已开，`Welcome` 已送达）→ Closed（报离线）`；`Authenticated` 时若同一身份已有会话，按 3.6 替换旧会话。

### 12.3 transport 连接

每种 transport 的单条连接：

| 状态 | 事件 | 动作 | 下一状态 |
| --- | --- | --- | --- |
| `Idle` | 会话请求建立 | TCP 连接 + TLS（`TRANSPORT_DIAL_TIMEOUT` 内） | `Dialing` |
| `Dialing` | TCP / TLS 完成 | WebSocket、HTTP Upgrade：发升级请求；XHTTP：发 GET（下行）并准备上行 | `Upgrading` |
| `Dialing` | 失败、超时 | 记 transport 失败 | `Failed` |
| `Upgrading` | 101（WS / Upgrade）或 GET 收到 200 且响应头到达（XHTTP） | 校验子协议（WS）；把字节流交给会话层 | `Ready` |
| `Upgrading` | 非 101 / 非 200、子协议不符、超时 | 记 transport 失败 | `Failed` |
| `Ready` | 读写错误、对端关闭、读截止超时 | 通知会话层 | `Closed` |
| `Ready` | 会话层要求关闭 | WS 发 Close 帧；XHTTP 结束 POST 并关闭 GET | `Closing` → `Closed` |

XHTTP packet-up 的上行子状态（节点侧）：`Idle →（有待发数据）Batching（≤ `XHTTP_MAX_POST`，≥ `XHTTP_MIN_POST_INTERVAL`）→ Posting → Idle`；服务端会话：`Created（首个 GET 或 POST）→ Paired（两半都到）→ Closed`，`Created` 停留超过 `XHTTP_SESSION_GC` 即回收。

`transport: auto` 的选择器：

| 状态 | 事件 | 动作 | 下一状态 |
| --- | --- | --- | --- |
| `Trying(t)` | 会话在 t 上握手成功 | 失败计数清零 | `Pinned(t)` |
| `Trying(t)` | transport 失败（握手完成前） | 计数加一；达到 3 则切到序列里的下一个 | `Trying(t)` / `Trying(next)` |
| `Pinned(t)` | 连续 3 次 transport 失败 | 切到下一个 | `Trying(next)` |

### 12.4 流（tcp）

发起方（ingress，或 relay 的 edge 向服务节点开流）：

| 状态 | 事件 | 动作 | 下一状态 |
| --- | --- | --- | --- |
| `OpenSent` | 写出 `StreamOpen`（含证书）与首段数据；本地保留首段副本；启动 `ACK_TIMEOUT` | — | `AckWait` |
| `AckWait` | `Ack{OK}` | 丢弃首段副本；记录 `responder`；启动双向拷贝 | `Established` |
| `AckWait` | `Ack{NO_RULE}` 且 Ack 里的 `rules_version` 比分流表新 | `Pull`；收到新 `Welcome` 后按新表重判这条连接：`via` 则重开一次，`direct` 则直连回放，`reject` 则 RST | `OpenSent`（新流）/ 直连 / `Closed` |
| `AckWait` | `Ack{TARGET_OFFLINE, CONTROL_NOT_READY}`，或 `Ack{NO_RULE}` 且版本不比分流表新，且 `fallback: direct` 且目的地不是 fake-IP / 服务域名 | 直连原始地址，回放首段副本 | `Closed`（流）/ 直连 |
| `AckWait` | 其他 Ack 错误、超时 | RST 本地连接，记决策日志 | `Closed` |
| `Established` | 本地读到 EOF | yamux `CloseWrite()` | `HalfClosedLocal` |
| `Established` | 收到 FIN | 本地 `CloseWrite()` | `HalfClosedRemote` |
| `Established` / `HalfClosed*` | 本地错误或收到 RST | `Reset()` / 关闭本地连接 | `Closed` |
| `Established` / `HalfClosed*` | 空闲超时（tls / http 300 秒；ssh 无） | `Reset()`，关闭本地连接 | `Closed` |
| `HalfClosedLocal` | 收到 FIN | 启动 `DRAIN_AFTER_FIN` | `Draining` |
| `HalfClosedRemote` | 本地 EOF | 同上 | `Draining` |
| `Draining` | 排空或 5 秒到期 | 释放 | `Closed` |
| 任意 | 会话断开 | 视为 RST | `Closed` |

接收方（egress / 服务节点）：

| 状态 | 事件 | 动作 | 下一状态 |
| --- | --- | --- | --- |
| `OpenReceived` | 读到 `StreamOpen` | 清单 B 的 1 到 7；首段数据进有界缓冲（16 KiB） | `Verifying` |
| `Verifying` | 签名、`to`（与 `task.executor`）、证书、身份通过 | 策略判定（发起者、动作） | `Authorizing` |
| `Verifying` / `Authorizing` | 失败 | `Ack{错误}` + `Reset()`，丢弃缓冲 | `Closed` |
| `Authorizing` | 策略允许 | 拨号（`EGRESS_DIAL_TIMEOUT`）；源站方向字节可先行转发 | `Dialing` |
| `Dialing` | 拨通 | 协议复核（6.4）通过后写出缓冲；`Ack{OK}` | `Established` |
| `Dialing` | 拨号失败、超时、协议复核失败 | `Ack{DIAL_FAILED / RESOLVE_FAILED / TIMEOUT / PROTOCOL_MISMATCH}` + `Reset()` | `Closed` |
| `Established` 及之后 | 同发起方的半关闭、RESET、空闲、排空规则 | 映射见 4.4 | … |

relay（中继的一条流）：`Pending（收到 Open，清单 A：本地校验 → 控制面查询或缓存 → 在线）→ Forwarding（两腿都开，字节对拷）→ Closed`；清单 A 失败在 `Pending` 直接回 Ack 错误并 RST；任一腿 RST 则另一腿 RST；任一腿 FIN 则另一腿 `CloseWrite()`，两腿都 FIN 后释放。

### 12.5 任务（task）

executor 侧，按 `(from, call_id)`：

| 状态 | 事件 | 动作 | 下一状态 |
| --- | --- | --- | --- |
| `Received` | 读到 `StreamOpen{task}` | 清单 B 的 1 到 7 | `Verified` / `Rejected` |
| `Verified` | 缓存里有同键的完成结果 | `Ack{OK}`，重发缓存的 `TaskResult` | `Done` |
| `Verified` | 同键正在执行 | `Ack{OK}`，附着到进行中的执行 | `Attached` |
| `Verified` | 同键但 `name` / `arguments` 不同 | `Ack{BAD_REQUEST}` | `Rejected` |
| `Verified` | 新调用 | 解析 `arguments` 与 `cmd`（7.4、设计文档 5.6） | `Parsed` / `Rejected`（`INVALID_ARGUMENTS`、`UNSUPPORTED_TOOL`） |
| `Parsed` | 策略判定 | 允许则检查并发上限 | `Authorized` / `Rejected`（`POLICY_DENIED`、`BUSY`） |
| `Authorized` | 启动进程成功（`exec_command`）或找到会话（`write_stdin`） | `Ack{OK}`；写入 stdin；等待 `yield_time_ms` | `Running` |
| `Authorized` | 启动失败 | `Ack{OK}` 后发 `TaskResult{is_error}`（执行层错误） | `Done` |
| `Running` | 进程退出 | 收集输出，渲染，签名 `TaskResult`，`CloseWrite()`；写缓存；通知附着者 | `Done` |
| `Running` | `yield_time_ms` 到期、进程仍在 | 返回带 `session_id` 的 `TaskResult`；会话保留 | `Done`（会话进入 12.5 的会话状态机） |
| `Running` | 流被 RST（会话断开等） | 进程继续；结果到达时写缓存 | `Running`（无流） |
| `Attached` | 原执行完成 | 发同一份 `TaskResult` | `Done` |
| `Done` | `TASK_DEDUP_TTL` 到期 | 删缓存 | `Expired` |

unified exec 会话（executor 侧，`session_id`）：`Created（exec_command 启动进程）→ Running → Exited（进程退出，最后一次输出未取走前保留）→ Reaped（输出取走后或空闲超过限制、或超过 `max_sessions` 时最旧者）`。会话属于创建它的 `from`，`write_stdin` 只能来自同一 `from`。

submitter 侧，按 `call_id`：

| 状态 | 事件 | 动作 | 下一状态 |
| --- | --- | --- | --- |
| `Pending` | MCP / CLI 调用到达 | 生成 `call_id`，构造并签名 `Open`，开流 | `AckWait` |
| `AckWait` | `Ack{OK}` | 启动 `yield_time_ms + 30 秒` 计时 | `ResultWait` |
| `AckWait` | Ack 错误 / `ACK_TIMEOUT` | 作为 MCP 错误返回 | `Failed` |
| `ResultWait` | `TaskResult` 验签通过 | 渲染给调用方 | `Done` |
| `ResultWait` | 验签失败、超时、流 RST | 返回「结果未知」并附 `call_id` | `Unknown` |
| `Unknown` | 调用方以同一 `call_id` 重试 | 新 nonce、新时间戳，重开流 | `AckWait` |

### 12.6 服务（service）

agentserver 侧，每个已注册服务：

| 状态 | 事件 | 动作 | 下一状态 |
| --- | --- | --- | --- |
| （无） | `Advertise` 里出现且名字合法、未占用 | 分配 fqdn；若 workspace 证书已就绪则直接 `Ready` | `Registered` → `CertPending` / `Ready` |
| `CertPending` | 通配证书签发完成并下发到 relay | 推 `Update` | `Ready` |
| `Ready` | 节点的会话下线 | edge 对该服务回 `TARGET_OFFLINE`；成员访问收到 Ack 错误 | `Ready`（节点离线） |
| `Ready` | 节点的 `Advertise` 不再包含它，或节点被移除 | 从服务表删除，推 `Update.removed_services`，向 relay 推 `RelayInvalidate` | `Removed` |
| `CertPending` / `Ready` | 证书续期 | relay 内存里整体替换，状态不变 | 不变 |

### 12.7 成员证书

持有方（成员节点）：`Issued（Welcome / Update 收到）→ Valid → RenewDue（剩余 < MEMBERSHIP_RENEW，等待续发）→ Valid（收到新证书，替换同 (member, issuer) 的旧证书）/ Expired（过期，不再附带）`。被移出组时收不到续发，自然过期。

验证方（提供侧节点）：对每份附带的证书，`签发者等于某条规则的 public_key → 签名有效 → member == from → workspace 一致 → 未过期且 issued_at 不在未来 → (member, issuer) 不在吊销记录` 全部通过才计入身份集合；吊销记录保留到 `until`。

agentserver：每个 (成员, 签发者) 一条记录，`Active（按 MEMBERSHIP_RENEW 周期续发）→ Revoked（离组、离开 workspace 或组删除：推 revoked_memberships，until 取最后一张证书的 expires_at）`。

### 12.8 受管策略（PolicyUpdate）

节点侧（每个提供侧角色各一份）：

| 状态 | 事件 | 动作 | 下一状态 |
| --- | --- | --- | --- |
| `LocalOnly`（该角色 `policy_source: local`） | 收到 `PolicyUpdate` | 丢弃，回 `PolicyApplied{applied: false}` | `LocalOnly` |
| `Unapplied`（`server` 模式，尚无下发） | 收到 `PolicyUpdate{v}` | 校验，原子替换，叠加本地 deny，回 `PolicyApplied{v, true}` | `Applied(v)` |
| `Unapplied` | 有请求到达 | 只有本地 deny 生效，其余拒绝 | `Unapplied` |
| `Applied(v)` | 收到 `PolicyUpdate{v' > v}` | 同上 | `Applied(v')` |
| `Applied(v)` | 配置切回 `local` | 丢弃下发策略，回 `PolicyApplied{applied: false}` | `LocalOnly` |

agentserver 侧，每个受管节点：`Rendered(v)（哈希变化）→ Sent（推送）→ Applied(v)（收到 PolicyApplied）`；`Sent` 10 秒未确认重发一次，再失败告警；节点重连时重新进入 `Sent`。

### 12.9 relay 与后端（relay 会话与缓存）

relay 侧：

| 状态 | 事件 | 动作 | 下一状态 |
| --- | --- | --- | --- |
| `Disconnected` | relay 会话就绪 | 清空全部缓存（断开期间可能漏掉 `RelayInvalidate`）；发 `RelayPresence` 重报全部在线节点 | `Connected` |
| `Connected` | 节点握手、开数据流或 edge 缺证书，且缓存未命中 | 发 `RelayLookup`（同键并发合并），等 `RELAY_LOOKUP_TIMEOUT` | `Connected` |
| `Connected` | `RelayAnswer` | 按 `ttl_seconds` 写入缓存（`join` 不缓存）；回答等待中的握手或流；`node` 答案里的 `Welcome` 留给该会话的控制流 | `Connected` |
| `Connected` | 节点在控制流上发消息 | 装进 `NodeMessage` 转给后端 | `Connected` |
| `Connected` | `Deliver{identity, signed}` | 节点在线则写进其控制流，否则丢弃 | `Connected` |
| `Connected` | 节点上线 / 下线 | 发 `RelayPresence` | `Connected` |
| `Connected` | `RelayInvalidate{workspace, removed}` | 清该 workspace 的条目（`workspace` 为空则清全部）；关闭 `removed` 节点的会话 | `Connected` |
| `Connected` | `WorkspaceCerts` / `RelayCert` | 替换内存里的证书 | `Connected` |
| `Connected` | 缓存条目到期 | 删除，下次使用时重新查询 | `Connected` |
| `Connected` | 查询超时或会话断开 | 等待中的查询按不可达处理；排队的节点消息超时丢弃；证书到期不再续；退避重连后端 | `Disconnected` |
| `Disconnected` | 节点握手或开数据流且缓存命中 | 用缓存条目（不过期），照常放行或转发；握手时没有新 `Welcome` 可送，节点保留上一份 | `Disconnected` |
| `Disconnected` | 缓存未命中 | 握手回 `ServerHello{CONTROL_NOT_READY}`，流回 `Ack{CONTROL_NOT_READY}` | `Disconnected` |

agentserver 侧，每个已注册 relay：`Registered → Connected（relay 会话就绪：推 RelayCert 与各 workspace 的证书，收 RelayPresence 更新在线状态并为在线节点重新 Deliver Welcome；之后按需应答查询、处理 NodeMessage、Deliver 发给节点的签名消息，目录、路由表、服务、策略或证书变更时推 RelayInvalidate）→ Disconnected（会话断开：该 relay 上的节点全部标为离线；超过宽限期则把它的 workspace 改派给别的 relay 并通知节点，MVP 单 relay 时只告警）`。

### 12.10 P2P 直连（预留）

节点对某个对端的直连状态：`Idle → Requested（发 P2PConnect）→ Punching（收到 P2PInvite，探测 5 秒）→ Connecting（选定地址对，QUIC + Noise 握手）→ Ready（新流优先走它）→ Idle（断开或失败，退避后可重试）`；`Requested` 收到 `P2P_DISABLED / P2P_NOT_ALLOWED` 直接回 `Idle` 并在退避期内不再请求。

---

## 附录 A：一次 exec_command 的完整消息

laptop（submitter）让 office（executor）执行 `lark-cli msg send --to ops --text hi`。

1. laptop 在会话上开流 ID 3（流 1 是控制流），写入 LP `StreamOpen`：

```
open.body = OpenBody {
  kind: KIND_TASK
  workspace: "home.agentsrv.example.com"
  from: <laptop 公钥>
  to:   <relay 公钥>
  issued_at: 1762560000
  nonce: <16 字节>
  task.executor: <office 公钥>
  task.call: FunctionCall {
    call_id: "c_01"
    name: "exec_command"
    arguments: "{\"cmd\":\"lark-cli msg send --to ops --text hi\",\"workdir\":\"/Users/me/work\",\"yield_time_ms\":10000}"
  }
}
open.sig = Ed25519ctx(laptop 私钥, "agentd/open/v1", open.body)
```

`certs` 附上 pc 组和 home workspace 签给 laptop 的成员证书，然后 `CloseWrite()`。

2. relay：过清单 A：本地校验通过（`to` 是自己）；向控制面查 `stream{home, laptop, TASK, executor: office}`（或命中缓存），答复 `OK, EXECUTOR, target: office, rules_version: 7`（控制面已确认 laptop 有 submitter 上限、office 有 executor 上限且为 `server` 模式、中央策略允许 laptop 对 office 执行任务）；office 的会话在线。向 office 的会话开流 ID 2，写入 `StreamOpen{open 原样, relay{from_name: "laptop", rules_version: 7, trace_id, relayed_at}}`，`CloseWrite()`。

3. office：清单 B 通过（`to` 是自己所连的 relay，`task.executor` 是自己），pc 组证书有效，身份集合为 {laptop, pc, home}；`(laptop, "c_01")` 不在缓存；解析 `cmd` 为 `["lark-cli","msg","send","--to","ops","--text","hi"]`，`argv[0]` 按 basename 与规则比较，命中策略 `(pc, allow, ["lark-cli","msg"])`，执行路径取自规则；写 LP `Ack{OK, trace_id, responder: <office 公钥>}`；启动进程，等待 10 秒或进程结束。

4. relay 把 `Ack` 原样转给 laptop。

5. 进程 0.8 秒后退出，退出码 0，输出 `sent\n`。office 写 LP `TaskResult`：

```
body = TaskResultBody {
  call_id: "c_01"
  from: <office 公钥>
  to:   <laptop 公钥>
  issued_at: 1762560001
  final: true
  output: FunctionCallOutput {
    output_text: "Wall time: 0.8000 seconds\nProcess exited with code 0\nOutput:\nsent\n"
    output: "sent\n"
    wall_time_seconds: 0.8
    exit_code: 0
  }
}
sig = Ed25519ctx(office 私钥, "agentd/task-result/v1", body)
```

然后 `CloseWrite()`。结果进入 `(laptop, "c_01")` 缓存 10 分钟。

6. laptop 用 `task.executor` 的公钥验签，向 MCP 调用方返回文本 `output_text` 与 `structuredContent`，关闭流。

## 附录 B：一条 TLS 连接的完整消息

浏览器访问 `https://course.ucas.edu.cn`。workspace 路由表里 `(group:pc, [tls, ssh], suffix:ucas.edu.cn) → dorm` 只在 agentserver 上；laptop 的分流表里对应的是 `(suffix:ucas.edu.cn, [tls, ssh]) → via`，它不知道出口是 dorm。

1. laptop 的 TUN 收到到 fake-IP 的 443 连接，嗅探到 SNI `course.ucas.edu.cn`，与映射一致。在会话上开流 ID 5，写入 LP `StreamOpen`：

```
open.body = OpenBody {
  kind: KIND_TCP
  workspace: "home.agentsrv.example.com"
  from: <laptop 公钥>
  to:   <relay 公钥>
  issued_at: 1762560100
  nonce: <16 字节>
  tcp: TcpOpen { proto: PROTO_TLS, domain: "course.ucas.edu.cn", port: 443 }
}
open.sig = Ed25519ctx(laptop 私钥, "agentd/open/v1", open.body)
```

紧接着写入已缓存的 ClientHello 字节（约 1.8 KB），本地另留一份。

2. relay：过清单 A：本地校验通过（`to` 是自己）；向控制面查 `stream{home, laptop, TCP, tls, course.ucas.edu.cn, 443}`（或命中缓存），控制面按路由表选出 `dorm`，确认 laptop 有 ingress 上限、dorm 有 egress 上限，dorm 为 `local` 模式且其上报的策略允许 laptop 以 tls 访问 `suffix:ucas.edu.cn`，答复 `OK, EGRESS, target: dorm, rules_version: 7`；dorm 的会话在线。向 dorm 开流，转发 `StreamOpen(+relay)` 与随后的字节。

3. dorm：清单 B 通过（`to` 是自己所连的 relay，域名不是自己的服务，按 egress 处理）；策略 `(laptop, allow, tls, [{ kind: suffix, value: ucas.edu.cn }, { kind: suffix, value: ucas.ac.cn }])` 对发起者、协议、域名、端口命中；拨号 `course.ucas.edu.cn:443`（校园网解析）；缓冲到达的 ClientHello；拨通后解析 ClientHello，SNI 等于 `domain`；把缓冲写给源站；写 LP `Ack{OK, responder: <dorm 公钥>}`。

4. relay 转发 `Ack`。laptop 收到 `OK`，丢弃本地留存的首段副本，在决策日志里记下这条连接由 dorm 服务，之后两侧只做字节对拷。

5. 浏览器关闭连接：laptop 读到 EOF，`CloseWrite()`；dorm 收到 FIN，对源站 `CloseWrite()`；源站回 FIN，dorm `CloseWrite()`；双向 FIN 后 5 秒释放流。
