# agents / agentd 架构审计

历史审计说明：本文的行号与 Xray 集成建议对应审计时的架构快照。后续已确认改用 agents 自管认证、连接目录和业务流，XHTTP/WSS 只作承载；当前设计见 [架构方案](../agents-agentd-architecture.md) 和 [本地配置](../agentd-config.md)。

日期：2026-10-17

审计对象：`agents-agentd-architecture.md`、`agents-agentd-research.md`、`agents-agentd-alignment.md`、`agents-agentd-user-cases.md`

审计性质：设计审查；仓库当前没有实现代码、数据库迁移、协议定义或联调测试。

## 审计结论

设计的方向基本正确：它保留了 cloudflared 的 Tunnel/Connector/Connection/Ingress 分层，用 AgentRegistration 补足稳定设备身份，并借鉴 Headscale 的注册、能力审批和期望状态传播。租户、服务分享和 TLS 域名出口属于本产品自己的扩展，文档也没有把它们错误地称为 Cloudflare/Tailscale 兼容协议。

当前方案还不能作为实现基线。核心数据面建立在多个未经验证的 Xray 假设上，撤销和离线语义存在逻辑缺口，浏览器认证 broker、设备身份、配置应用状态机和数据结构约束还没有达到可以安全实现的精度。建议先把 P0 项全部变成可重复的实验和协议，再进入 P1 多租户实现；否则很容易得到“能转发流量但不能证明授权边界”的系统。

首轮 Xray PoC 已执行，详见 [poc/xray-reverse/README.md](../../poc/xray-reverse/README.md)：Xray 原生 Reverse 在 WS、XHTTP `stream-one` 和 WSS 上都能转发 HTTP；但 `RemoveUser` 不会关闭既有流或 Reverse worker，删除提供方用户后既有通道仍可继续承载请求；同一 Reverse 路径还能访问未配置的第二目标，说明 hostname/port/Workspace 授权不能放在原生 Reverse 中。真实 FrontDoor、XHTTP `stream-up`/`packet-up`、PolicyGate 和固定源码 commit 的严格复现仍未完成。

最近补充的 gateway/edge 分层和 P0 修复方案解决了设计表达上的歧义，但没有消除实现风险：`agents-gateway` 现在负责 Serve 的公网认证和 capability 签发，`agents-edge` 负责连接目录、域名选路和流转发；Exit 场景仍由访问方 agentd 直接接入 Edge。下表是当前状态：

| 项目 | 当前状态 |
|---|---|
| gateway → edge → provider agentd 的 Serve 路径 | **设计已明确，未实现** |
| Edge 的 domain-only PolicyGate | **设计已明确，未实现** |
| FlowLease、双向 capability、流级撤销 | **设计已明确，Xray 集成未验证** |
| 同一 provider Connection 承载 Serve/Egress 逻辑流 | **设计已确定，流级隔离/撤销未实现** |
| 原生 Reverse 的基础承载（WS/WSS/XHTTP stream-one） | **PoC 已通过** |
| RemoveUser 关闭既有流 | **已证明不成立，必须使用 FlowGateway/worker 重建** |
| XHTTP stream-up/packet-up、真实 FrontDoor 粘性 | **未验证** |
| OIDC/PKCE/host-only 服务会话 | **未实现** |
| bearer scope/rotation、`via` 唯一安装语义、数据库组合约束、配置签名/回滚 | **未实现或未定策略** |

## 与上游的对齐判断

| 方面 | 审计判断 |
|---|---|
| cloudflared 资源层次 | **基本对齐**。持久 Tunnel、一次运行的 Connector、多条 Connection、按顺序匹配的 IngressRule 和同 Tunnel 副本的等价能力都表达清楚（架构文档 §4、§8）。 |
| cloudflared 运行时 | **尚未对齐到可运行语义**。Connector 重连、连接排空、连接恢复、Edge 连接归属和配置 ACK 的协议没有定义；Xray 的连接数量和生命周期不能直接替代 cfd 的 supervisor 语义。 |
| Headscale 注册/身份 | **生命周期借鉴，认证模型按 cfd 简化**。Tunnel/Connector 可以使用 cfd 式 bearer 凭据；AgentRegistration 不宣称硬件绑定或不可复制的设备身份。只有当 `via` 要求精确选择某个物理安装时，才需要额外的设备密钥/挑战证明。 |
| Headscale 能力审批/策略传播 | **原则对齐**。宣告、批准、授权、期望/应用/在线状态分层是合理的；签名快照、DataPlaneLease、60 秒失联策略是自研语义，不能从 Headscale 资料直接推出。 |
| Headscale 数据面 | **有意不对齐**。本产品所有业务经过 agents-edge，不提供 Tailscale 的三层地址、P2P 或 DERP；这可以成立，但必须作为明确的可用性、延迟和 Edge 单点取舍。 |
| Cloudflare Access / oauth2-proxy | **只有意图对齐**。源站 JWT 二次验证的思路合理，但每服务 host-only 会话和中央登录兑换 broker 是新组件，不能把 oauth2-proxy 的认证子请求当成完整资源授权。 |
| Xray | **关键实现尚未成立**。XHTTP/WSS、VLESS Reverse、Mux、PolicyGate、活动流撤销和多 `core.Instance` 隔离只完成了源码可行性调查，没有完成调用链验证。 |

## P0：实现前必须解决的问题

### P0-1：混合 Serve/Egress 的 Xray 数据面没有证据证明可行

原草案试图让同一 Connector 的 Reverse 池同时承载 Serve 和 Egress，并用 Mux 目标字段分流（原架构文档 §13）。当前修订保留同一物理承载连接，但要求每条逻辑流有 purpose-specific handler、FlowCapability 和 FlowLease；仍依赖 Xray Handler/FlowGateway 取得可信的入站身份、原始目标、ClientHello，并把业务流交给正确的 handler；也没有证明 reverse handler 能按会话关闭。

这是产品的核心路径，不是普通适配细节。若外部 access-client 能构造保留服务别名、伪造目标字段或落入默认 outbound，就会形成跨租户访问或把服务发布面变成出口代理。必须先做最小 PoC：两种传输（XHTTP、WSS）、两种业务并发、任意目标 fuzz、默认 blackhole、取消/超时/慢消费者和身份映射。若共享池无法形成强隔离，首版应拆成 Serve/Egress 两套 reverse 身份或两套 runtime，而不是继续依赖约定字段。

### P0-2：撤销和控制面失联语义自相矛盾

文档要求授权撤销关闭已有 SSE/WebSocket/下载/TLS 流，并在控制面失联时不超过策略租约继续接收业务（架构文档 458-462 行）。但 Edge 在失联时只能看到旧的策略快照；它无法得知刚发生的 `revoked_at`。因此“主动撤销的秒级生效”和“失联时仍能处理撤销”不能同时成立，除非每个业务流都带有短期、不可续期的授权租约，或有独立的撤销通道。

需要把语义改成可计算的上界：区分已知截止时间、控制面可达时的主动撤销、控制面失联时的最大暴露时间；为每个长流定义检查点和强制关闭方式。必须测量 p50/p99，而不是只调用 `RemoveUser`；如果 Xray 不能关闭旧 reverse 流，应把按 Workspace 重建 runtime 作为明确的可用性代价和兜底实现。

### P0-3：XHTTP/WSS 的会话归属和 FrontDoor 协议未定义

XHTTP 可能把上行、下行和 packet 请求分成多个 HTTP 请求；WSS 依赖 Upgrade 和长连接。文档提到“上下行归属是硬约束”和“需要粘性分发”，但没有定义会话 ID、owner 注册、断线恢复、HTTP/2 流控、代理缓冲、取消、超时、最大请求体以及外部负载均衡的路由规则（架构文档 403-405、474 行）。

首版即使只有一个 Edge，也需要用真实 FrontDoor/反向代理跑通这些边界；否则后续加 Edge 时无法保持同一 XHTTP 会话。验收应覆盖 stream-up/packet-up、HTTP/2 RST、WSS 半关闭、重连、长时间空闲、慢消费者、并发和过载。

### P0-4：Serve 的登录和每服务会话 broker 还只是设计意图

架构把 oauth2-proxy 定位为身份适配器，再自行实现中央登录、一次性兑换 code 和每个服务的 host-only Cookie（架构文档 273-287 行）。这条链需要 PKCE、state/nonce、回跳 allowlist、一次性 code 防重放、Cookie 加密和轮换、CSRF、登出、时钟偏差和受信认证头边界；oauth2-proxy 的 `/auth` 成功不能替代这些约束。

在没有浏览器自动化测试和跨 Workspace Cookie 测试前，P2 的 Serve 不能宣称安全。应先固定一个身份适配协议和信任边界：哪些请求只能来自 loopback/mTLS，哪些头在 Edge 入口被删除，签发的服务会话如何绑定 `PublishedRoute` 和 Workspace。

## P1：高风险设计缺口

### P1-1：AgentRegistration 的 bearer 语义和 `via` 精确选择需要明确

注册步骤用高熵 Token 创建 AgentRegistration，再换取 Xray 工作凭据（架构文档 190-206 行；对齐审查 65 行）。这与 cloudflared 使用 Tunnel bearer credential 的模型一致，本身不是必须改成 Headscale 的设备协议。未解决的地方是：Token 被复制后，另一台机器可以冒充同一 AgentRegistration；如果 `via: agentd1` 语义要求唯一的一台物理安装，这会造成连接归属歧义。

因此有两个合法选择： (a) 采用 cfd 式 bearer 语义，把 AgentRegistration 定义为可复制的逻辑 profile，`via` 只表示该 profile 的当前 Connector，并补齐 scope、轮换、泄露处理和审计；(b) 若产品必须保证 `via` 对应唯一安装，再为 AgentRegistration 增加设备公私钥、挑战签名和轮换。无论选择哪种，TunnelCredential、AgentRegistration、Connector 和 DataPlaneLease 的职责必须分开，不能把 bearer token 误称为硬件身份。

### P1-2：租户隔离没有落成可执行的数据库和编译约束

文档要求组合外键、缓存和连接目录带 Workspace ID（架构文档 424-434 行），但 API 和实体仍允许 `AccessGrant.resource_id`、`PublishedRoute.tunnel_id`、`EgressRoute.exit_tunnel_id`、`exit_agent_registration_id` 通过应用代码关联。没有 DDL、跨 Instance 约束、事务边界和负向查询测试，容易出现“对象各自有效但组合属于不同 Workspace”的混淆代理。

需要在 schema 层强制 `(instance_id, workspace_id, resource_id)` 组合引用，所有资源查询由认证上下文注入 scope；把策略编译成不可变快照时再次验证 scope，并为“W1 凭据访问 W2 路径/规则/内部目标”建立数据库和数据面双重测试。`AccessPolicy` 的 deny 优先级、`AccessGrant` 并集与强制拒绝的组合也必须写成确定的决策表。

### P1-3：PublishedRoute、IngressRule 和兜底规则的归属不够精确

`IngressRule` 被定义为 Tunnel 级对象，而 `PublishedRoute` 又保存一组 `ingress_rule_ids`；同一个 Tunnel 可以承载多个 hostname，文档还要求每条配置最后有兜底规则（架构文档 78-94、269-271 行）。目前不清楚兜底是每个 Tunnel、每个 PublishedRoute 还是每个编译快照，也不清楚同一 hostname 的多 path 如何阻止落入另一个服务的规则。

应选择一个规范模型：保留 cfd 的 Tunnel 级有序 ingress，并让 PublishedRoute 只引用经验证的 hostname/规则范围；或者把服务规则编译成 route-owned matcher，禁止跨 PublishedRoute 回退。Edge 与 agentd 只消费同一份编译结果，统一 Host/path/Unicode/百分号规范化和 revision，避免两端各自匹配。

### P1-4：远程配置的状态机、签名和回滚协议不完整

文档提出 desired/approved/applied/healthy、revision、generation、ACK、outbox 和签名快照（架构文档 438-452 行），但没有定义 ACK 的内容、应用失败如何回滚、旧快照如何拒绝、签名信任根如何轮换、连接重放如何防止，也没有 agentd/Edge 的具体 watch/heartbeat API。

建议把状态机和协议单独固化：`desired → approved → issued → applied → healthy → retired`，每步持有 resource generation 和 policy revision；应用必须幂等，旧 generation 只能拒绝，健康检查必须证明实际 Xray handler/route 已启用；签名快照需要 `kid`、有效期、受众、nonce/版本和密钥轮换。只有 `healthy` 的配置才能激活 PublishedRoute/EgressRoute。

### P1-5：单进程和多 `core.Instance` 不是租户隔离

首版 `agents run` 同时包含 control、edge、console，且每个 Workspace 的 Xray core 仍共享 Go 进程（架构文档 54、74、397-403 行）。Xray 的全局状态、插件错误、内存增长或单租户流量峰值可能影响所有 Workspace，control 与 data plane 也共享故障域。

应在首版明确部署边界：至少把 control/console 与 Edge/worker 分进程，禁止 Edge 直接持有数据库管理员能力；对每个 runtime 设置 CPU、内存、连接、缓冲和并发上限。若不能证明多个 core 的全局状态隔离，应使用一个受控 core 或每租户独立 worker 进程，不把 `core.Instance` 称为 OS 级隔离。

### P1-6：源站和出口的目标校验仍缺少规范化算法

Egress 已考虑 SNI、CONNECT、ECH、CNAME 和受限地址，但没有固定 IDNA、大小写、尾点、IPv4/IPv6 文本、IPv4-mapped IPv6、CNAME 深度、解析结果到拨号的绑定算法（架构文档 314-372 行）。`authority` 模式还允许未验证内层 SNI，必须明确它的安全承诺和适用范围。

应把 canonical destination 定义成可测试的结构：规范域名、端口、协议、解析结果和最终拨号地址一次性绑定；禁止数字 IP 变体、loopback/link-local/metadata 地址和 DNS rebinding；exact/suffix 只按 DNS label 边界匹配。Serve 的 `--url` 也要限制 scheme、端口、重定向和私网目标，避免远端配置把 agentd 变成 SSRF 或内网扫描器。

### P1-7：单 Edge、单控制节点和故障恢复边界没有形成产品承诺

文档明确首版单 Edge，但没有定义控制面、Edge、PostgreSQL、证书 worker、Connector 重启时的 SLO、排空、重连和恢复顺序。cloudflared 的多 Edge 连接和同 Tunnel 副本提供了可用性语义；当前方案只在数据模型层保留了这些名词。

应把单 Edge 写成 v1 非目标，给出故障时的明确行为和恢复上界；至少定义 Connector 指数退避、连接排空、发布状态、证书/密钥备份恢复、数据库迁移和升级回滚。若要提供高可用，必须先解决 XHTTP 会话 owner 和 Sticky/转发协议，不能仅在前面加负载均衡。

### P1-8：TUN 和本地代理的身份、路由及失败关闭还不够具体

HTTP/SOCKS 默认 loopback 是合理的，但共享给其他本机账号时的认证、Unix socket 权限、进程崩溃后的 TUN 路由清理、DNS/FakeDNS 映射、IPv6、控制链路排除和系统直连泄漏没有协议化（架构文档 374-382 行）。TUN 首版只支持一个 Workspace，也需要明确 profile 与进程的唯一对应关系。

P3 之前应完成 Linux 端到端测试：非 TLS/UDP/ICMP 明确拒绝，控制地址不会进 TUN，agentd 退出后路由恢复，FakeDNS 映射不能被本地应用伪造，DNS 失败时不回退到家庭直连；本地代理的凭据不能被任意同机进程读取。

### P1-9：秘密、签名和时钟信任根未定义

文档提到 Token 哈希、工作凭据加密和签名快照，但没有说明 KMS/密钥文件权限、JWT 算法和 `kid`、Issuer/Audience、密钥轮换、时钟同步、快照撤销和泄露响应。AccessGrant、服务 JWT、DataPlaneLease 和 VLESS UUID 的生命周期也没有统一的秘密分级。

应建立密钥层级与轮换表：bootstrap、设备密钥、Tunnel 运行凭据、Access JWT、配置快照签名分别由谁签发、保存、轮换和撤销；所有令牌都绑定 purpose、Workspace、资源、generation 和有效期。时钟偏差必须有上限，超过上限时 fail closed。

## P2：实现规划和运营缺口

1. **控制 API 不完整。** 当前 API 清单缺少注册批准、设备心跳、Connector/Connection 状态、Lease 领取/续租、配置 watch、ACK/health、浏览器 code 兑换和证书状态接口（架构文档 480-502 行）。应先定义协议，而不是从资源 CRUD 反推运行时行为。
2. **发布/共享缺少滥用控制。** 匿名 Web 发布和 TLS 出口都需要请求、连接、带宽、并发、上传大小、日志保留和速率限制；现在只有租户配额的原则，没有 public share、SSRF、出口滥用和 DDoS 的可执行限制。
3. **审计和可观测性需要事件模型。** 访问审计字段是良好起点，但需要 correlation ID、决策原因、配置 revision、Connector/Edge owner、流关闭原因、敏感 Host/SNI 脱敏、不可抵赖的管理审计和保留周期。
4. **资源删除和恢复语义缺失。** NameReservation 有墓碑，但 Tunnel、AgentRegistration、Workspace、证书、邀请、AccessGrant、审计数据的软删/硬删、备份恢复和重新绑定没有定义。
5. **状态与错误码需要固定。** `pending_dns`、`pending_certificate`、`pending_approval`、`offline`、`draining`、`revoked`、`stale` 等状态应有可枚举转换和用户可见错误；不能把策略拒绝、出口离线、源站 502 和控制面失联混成同一 503。

## 建议的修订后基线

1. **先固定三条协议。** (a) AgentRegistration 的设备证明和轮换；(b) control 到 Edge/agentd 的 desired/applied/healthy/lease 协议；(c) Edge 到 Xray/反向通道的 purpose、目标和流关闭协议。
2. **先拆安全域，再谈复用。** P0 阶段分别验证 access-client、Serve reverse、Egress reverse；只有证明 target namespace、身份映射和撤销都隔离，才允许共用 Reverse 池。
3. **让 policy compiler 成为唯一决策源。** 数据库资源先做 scope/组合外键校验，再编译不可变快照；Edge 和 agentd 不各自解释 YAML，统一使用同一 revision 和 canonical destination。
4. **把撤销写成上界。** 对新流、长流、已知 expires_at、主动 revoke、控制面失联分别定义最大允许时间，并将 runtime 重建作为可观察的强制撤销手段。
5. **把部署边界写实。** 首版可以只有一个 Edge，但 control、Edge、worker、PostgreSQL、证书 worker 的权限、故障域和恢复顺序必须明确；`core.Instance` 不能当作租户隔离承诺。

## 发布门槛

- **P0 退出条件：** XHTTP/WSS + VLESS Reverse 的双向大流、Serve/Egress 并发、任意目标拒绝、跨 Workspace 负向测试、Connector/Lease 撤销、长流关闭、FrontDoor 粘性和无默认 outbound 回退全部有自动化证据。
- **P1 退出条件：** 设备密钥/Token 轮换、复合外键和策略编译、OIDC/PKCE/host-only Cookie、目标 canonicalization/SSRF 防护、runtime 资源隔离、故障恢复和单 Edge 行为完成验收。
- **P2 退出条件：** 配额/速率限制、审计与指标、备份恢复、迁移/回滚、TUN 失败关闭和运维 runbook 完整。

在上述门槛通过前，文档可以作为方向性架构，但不应把“对齐 cloudflared/headscale”写成已验证的互通或安全等价性。
