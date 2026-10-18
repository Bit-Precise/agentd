# agents / agentd 调研记录

用途更新：本文保留固定上游版本的证据。VLESS/Reverse 调研不再表示产品选用它们；当前已确认 agents 自管认证、连接和业务流，XHTTP/WSS 仅作传输适配。见 [架构方案](../agents-agentd-architecture.md) 和 [本地配置](../agentd-config.md)。

日期：2026-10-17。仅调研公开文档、当前 cloudflared 工作区和开源代码；没有运行服务、登录外部账号或进行网络联调。配套方案见 [架构设计](../agents-agentd-architecture.md)。

**源码基线**

| 项目 | 本次查阅 revision | 用途 |
|---|---|---|
| cloudflare/cloudflared | `8e090e5bfa7a53e824fb2d7eb276f8ab08337b80`，与调研时 cloudflared 工作区 HEAD 一致 | 客户端实体、凭据、注册、ingress |
| XTLS/Xray-core | `0f127f934c6d7c10e4bb6acbe98033db9e5fd922` | VLESS Reverse、认证、sniffing、路由、Go API |
| juanfont/headscale | `fc97593bcea76c92fb3ad41a5b95076684ddc85a` | 用户与节点身份、注册、策略、出口审批 |
| oauth2-proxy/oauth2-proxy | `bea3f04bf87b93f5354f392fe2216a88e6031350` | 身份头、Cookie 配置 |

revision 用于重现本次调查，不是生产依赖版本推荐。实现阶段选发布版本并通过兼容性测试。

**R1. cloudflared 的运行身份不是永久设备身份**

[client/config.go](https://github.com/cloudflare/cloudflared/blob/8e090e5bfa7a53e824fb2d7eb276f8ab08337b80/client/config.go) 在配置初始化时生成随机 Connector ID；同一进程的连接参数共享该 ID。Tunnel ID 和 TunnelSecret 则来自持久化凭据。

结论：Connector 表示一次运行，不能让域名绑定一个重启即变化的 Connector ID。对齐审查进一步将所有 agentd 的永久名字放入 AgentRegistration（见 R23）；Tunnel 保留逻辑隧道身份。稳定 Agent 命名不是 cfd 自带的设备管理功能。

**R2. cloudflared 使用隧道凭据与独立控制流注册**

[connection/connection.go](https://github.com/cloudflare/cloudflared/blob/8e090e5bfa7a53e824fb2d7eb276f8ab08337b80/connection/connection.go) 定义 AccountTag、TunnelSecret、TunnelID 和 Token 编码；[connection/control.go](https://github.com/cloudflare/cloudflared/blob/8e090e5bfa7a53e824fb2d7eb276f8ab08337b80/connection/control.go) 用它们注册连接，并处理本地配置上报。

结论：继承 Tunnel 的身份/配置语义；通过管理 API 完成 Xray 工作凭据的适配，不宣称 VLESS 自带 cloudflared 注册字段。

**R3. ingress 是服务映射的基础**

[ingress/rule.go](https://github.com/cloudflare/cloudflared/blob/8e090e5bfa7a53e824fb2d7eb276f8ab08337b80/ingress/rule.go) 定义 hostname、path、service、originRequest。[公开路由文档](https://developers.cloudflare.com/tunnel/concepts/routing/) 区分外部域名入口与本地服务目标。

结论：使用 PublishedRoute + IngressRule，避免另设重复的 Site/Service 抽象。

[ingress/ingress.go](https://github.com/cloudflare/cloudflared/blob/8e090e5bfa7a53e824fb2d7eb276f8ab08337b80/ingress/ingress.go) 按顺序 first-match，并拒绝带路径的源站 URL。首版继承这些规则，不把自动路径改写或 EgressRoute 排序冒充为 cfd ingress 语义。

**R4. Replica 的含义与负载均衡分开**

[Tunnel availability and failover](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-availability/) 描述同一 Tunnel 的多个 cloudflared 副本用于可用性；副本机制不提供用户可选的轮询/哈希流量调度。

结论：同 Tunnel 副本应提供等价能力。不同出口网络用不同 Tunnel，由 EgressRoute 选择。

**R5. Cloudflare Access 支持源站验证授权 JWT**

[Validate JWTs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/) 描述源站校验 Access token 的签名、issuer、audience 等。

结论：Serve 可以使用标准签名断言，让 agentd 二次验证 Edge 的授权结果；TLS Egress 中不能插入 HTTP 断言。

**R6. Headscale 的设计范围主要是单个 tailnet**

[README](https://github.com/juanfont/headscale/blob/fc97593bcea76c92fb3ad41a5b95076684ddc85a/README.md) 明确说明项目针对较窄的单 tailnet 范围。

结论：不能直接将 Headscale 的 User 视作完全隔离的 Workspace，更不能假定它已提供“一个用户加入多个租户、每租户不同角色”的完整 RBAC。我们的 Membership 与租户隔离需要单独实现。

**R7. Headscale 区分个人与服务节点，并提供两类注册**

[Registration methods](https://headscale.net/stable/ref/registration/) 区分用户持有的 personal node 和由标签表达身份的服务节点；支持浏览器批准和预授权 key 注册。对应源码文档为 [registration.md](https://github.com/juanfont/headscale/blob/fc97593bcea76c92fb3ad41a5b95076684ddc85a/docs/ref/registration.md)。

结论：借鉴交互/非交互注册，以及个人资源/团队资源的生命周期分离。不能把服务进程永远依附于一个员工的浏览器会话。

**R8. Headscale 出口使用双向批准与访问策略**

[Routes](https://headscale.net/stable/ref/routes/) 描述出口先宣告，再由控制端批准，并可用策略限制谁能使用。其具体对象是 IP 路由和三层出口。

结论：我们借鉴宣告、审批、授权三者分离，目标替换为 TLS 域名和端口，不复制 `0.0.0.0/0` 路由语义。

**R9. OIDC 用户必须使用稳定主体标识**

[OIDC 文档](https://headscale.net/stable/ref/oidc/) 与 [users.go](https://github.com/juanfont/headscale/blob/fc97593bcea76c92fb3ad41a5b95076684ddc85a/hscontrol/types/users.go) 使用 provider identifier 表达 issuer/subject 的组合。

结论：User 是全局身份，Membership 是 Workspace 关系，邮件域名不能自动赋予租户成员资格。

**R10. Headscale policy 的默认策略不能照搬**

[Policy](https://headscale.net/stable/ref/policy/) 说明省略 ACL/grants 时可能采用允许所有的默认行为。

结论：我们的出口路由默认拒绝；Web 默认有效 Workspace 成员，匿名公开必须明确设置。采用版本化策略，但不照搬其默认可达性。

**R11. Xray 已有 VLESS 原生反向代理**

[VLESS reverse 文档](https://xtls.github.io/document/level-2/vless_reverse.html)、[inbound 实现](https://github.com/XTLS/Xray-core/blob/0f127f934c6d7c10e4bb6acbe98033db9e5fd922/proxy/vless/inbound/inbound.go)、[outbound 实现](https://github.com/XTLS/Xray-core/blob/0f127f934c6d7c10e4bb6acbe98033db9e5fd922/proxy/vless/outbound/outbound.go) 显示：内网端主动建立 Reverse 命令连接，公网端将其注册为反向出口，业务会话用已有 Mux 处理。

结论：复用原生数据面。forward 与 reverse 分配独立用途的账号；不能把 reverse-only 用户当普通代理访问用户。

**R12. XHTTP 与 WebSocket 提供传输，不提供租户授权**

[XHTTP 官方说明](https://github.com/XTLS/Xray-core/discussions/4113) 描述分离上下行和多种传输模式；[WebSocket 文档](https://xtls.github.io/config/transports/websocket.html) 描述 WebSocket 传输配置。

结论：上下行归属是多 Edge 部署的硬约束。HTTP 路径和连接升级结果不能替代 VLESS 身份和 Workspace 授权。

查阅版本的 [XHTTP listener](https://github.com/XTLS/Xray-core/blob/0f127f934c6d7c10e4bb6acbe98033db9e5fd922/transport/internet/splithttp/hub.go) 支持本机明文 HTTP/1.1 和 h2c，可作为统一 TLS FrontDoor 的内部后端；这仍需流式反代联调。

**R13. Xray 现有 sniffing 不等于强制 TLS 授权网关**

[dispatcher/default.go](https://github.com/XTLS/Xray-core/blob/0f127f934c6d7c10e4bb6acbe98033db9e5fd922/app/dispatcher/default.go) 显示：routeOnly 使用 RouteTarget，实际 Target 可保持原值；sniffing 超时/失败后仍进入路由；部分 PickRoute 错误会走默认 outbound。

[TLS sniffer](https://github.com/XTLS/Xray-core/blob/0f127f934c6d7c10e4bb6acbe98033db9e5fd922/common/protocol/tls/sniff.go) 解析可见 ClientHello 与 SNI，存在长度和分片处理边界。

结论：增加 Go 侧 TLS PolicyGate，明确默认拒绝、实际目标校验、超时和缓冲预算。复用 SDK 不意味着不需要授权执行代码。

[features/outbound/outbound.go](https://github.com/XTLS/Xray-core/blob/0f127f934c6d7c10e4bb6acbe98033db9e5fd922/features/outbound/outbound.go) 导出 Handler 与 Manager 接口，可以作为 Go 侧适配入口；仅确认接口存在，尚未验证完整授权/反向转发链路。

**R14. Go API 连接的 deadline 需要适配**

[core/functions.go](https://github.com/XTLS/Xray-core/blob/0f127f934c6d7c10e4bb6acbe98033db9e5fd922/core/functions.go) 暴露 core.Dial；[cnc/connection.go](https://github.com/XTLS/Xray-core/blob/0f127f934c6d7c10e4bb6acbe98033db9e5fd922/common/net/cnc/connection.go) 的 deadline 方法在查阅版本中直接返回。

结论：Serve 首版通过本机受限 SOCKS5 入口得到真实 socket 语义；直接操作 Link 的组件显式管理取消和关闭。

**R15. 删除 VLESS 用户不等于完成会话撤销**

[VLESS inbound](https://github.com/XTLS/Xray-core/blob/0f127f934c6d7c10e4bb6acbe98033db9e5fd922/proxy/vless/inbound/inbound.go) 包含 RemoveUser/RemoveReverse，而反向 handler Close 的行为有限。

结论：撤销流程必须通过活动流测试，必要时重建隔离 runtime。不能只完成用户表删除就报告所有旧访问已失效。

**R16. oauth2-proxy 确认身份，资源授权由 agents 完成**

[Integration](https://oauth2-proxy.github.io/oauth2-proxy/7.11.x/configuration/integration/) 描述认证子请求与身份头；[固定版本配置说明](https://github.com/oauth2-proxy/oauth2-proxy/blob/bea3f04bf87b93f5354f392fe2216a88e6031350/docs/docs/configuration/overview.md) 描述 Cookie domain、前缀和头部行为。

结论：使用 host-only 会话、受信认证头和独立资源授权，避免把共享父域 Cookie 当成租户隔离机制。中央登录与服务 origin 会话需要专门实现与验收。

**R17. TLS 透传的两个标准边界**

[RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html) 定义 ECH；启用时中间节点不能依赖读取真实 SNI。[RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html) 定义 TLS 服务身份匹配，通配符不能跨多级标签。

结论：严格 SNI 模式不能对 ECH 作虚假承诺；每个 Workspace 的服务域名需要对应层级的证书。

**R18. TUN 是本机接入能力，不自动改变产品为 VPN**

[Xray TUN 文档](https://xtls.github.io/en/config/inbounds/tun.html) 说明平台支持、系统路由和防流量环路配置。

结论：允许 TUN 捕获本机流量，数据面仍限制在获准 TLS 会话。首版 Linux 验证，其他平台另测；无子网宣告、节点地址分配或通用三层互联。

**R19. Workspace 更接近 Cloudflare Account 的成员边界**

[Accounts, zones, and profiles](https://developers.cloudflare.com/fundamentals/concepts/accounts-and-zones/) 说明用户可属于多个 Account；[Members and permissions](https://developers.cloudflare.com/fundamentals/manage-members/) 将成员权限拆成 actor、role 和 scope。

结论：借鉴 User + Membership + 租户资源作用域。Workspace 不是 DNS Zone，用户指定的四种角色与 instance admin 是本产品定义，不是 Headscale 或 Cloudflare 的同名内置角色。

**R20. 同一 cfd 隧道承载不同业务类型**

[connection/quic_connection.go](https://github.com/cloudflare/cloudflared/blob/8e090e5bfa7a53e824fb2d7eb276f8ab08337b80/connection/quic_connection.go) 在同一连接对象中按请求类型分发 HTTP/WebSocket 和 TCP。

结论：共用承载连接、按业务会话处理符合 cfd 的分层方向，但首版先将 serve/egress 按 purpose 隔离，避免把原生 Mux target 当作授权边界。我们用 VLESS Reverse + Mux 替换具体封装；跨 purpose 复用的完整授权链路仍需验证。cfd 通常维护四条边缘连接，不能据此声称 Xray 会维持完全相同的数量和生命周期。

**R21. Cloudflare One 有指定 Tunnel 出口的公开设计**

[Egress through Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/traffic-controls/egress-policies/egress-cloudflared/) 描述访问端流量经过 Gateway 策略后，由 hostname route 选择 Tunnel，并从部署 cloudflared 的网络出口访问目标。

结论：TLS 域名出口可以参考这个服务分工。我们的 Xray 接入、SNI PolicyGate、强制端到端目标 TLS 和默认拒绝行为是独立实现，并不复用其 Gateway/WARP 线协议。

**R22. 首版选择 cfd 的远端管理方向**

[Locally-managed tunnels](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/) 对比本地配置与服务端集中保存的远端配置。[connection/control.go](https://github.com/cloudflare/cloudflared/blob/8e090e5bfa7a53e824fb2d7eb276f8ab08337b80/connection/control.go) 可见本地配置模式的上报分支。

结论：本产品第一版仅让 control 成为发布、出口与访问策略的权威；本地命令提交配置请求，不直接绕过租户权限。不是完整复制两种配置模式。

**R23. Headscale Node 与 cfd Connector 的生命周期不同**

[Headscale node.go](https://github.com/juanfont/headscale/blob/fc97593bcea76c92fb3ad41a5b95076684ddc85a/hscontrol/types/node.go) 包含持久化 Node ID、设备密钥、GivenName、用户/标签归属及期限等信息。它不是每次网络重连都新建的临时连接 ID。

结论：以 AgentRegistration 借鉴持久注册/名称职责，覆盖纯访问端和提供方。cfd 的 Tunnel/Connector/Connection 继续处理逻辑隧道和运行连接。注册记录不包含 Overlay IP、发现协议和三层路由；其具体认证协议与 Headscale 不兼容。

**尚未通过实验确认的内容**

- 在固定发布版本里，XHTTP 两种模式与 WebSocket 的 VLESS Reverse 组合。
- Go outbound 扩展取得可信用户上下文与调用反向 handler 的准确生命周期。
- Connector 精确撤销和多个 core.Instance 的关闭、资源隔离行为。
- SNI 读取遇到多 TLS record、慢速/大 ClientHello 的兼容性与拒绝边界。
- 中央 oauth2-proxy 登录配合每服务 host-only 会话的浏览器行为。
- 多节点 XHTTP 会话归属与跨节点 CONNECT 转发。

这些是首阶段验证任务，不是已经实现的能力。
