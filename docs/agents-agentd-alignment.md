# agents / agentd 与 cfd、Headscale 的对齐审查

基线更新：下文保留旧 Xray/VLESS Reverse 方案的对齐记录。现已确定由 agents 管理认证、连接目录和业务流，XHTTP/WSS 仅提供承载；本地 `config.yaml` 支持 ingress/serve/egress 组合。当前规范以 [架构方案](agents-agentd-architecture.md) 和 [本地配置](agentd-config.md) 为准。

身份模型最新决策采用 [单 Workspace SA 与 Hydra Device Flow](https://github.com/Bit-Precise/agents/blob/main/docs/identity-and-device-flow.md)。它是本产品的目标设计，不宣称与 Headscale 用户/服务节点或 Cloudflare 凭据兼容；下文旧的统一 User 访问身份描述不覆盖 SA。注册和配置变更已确定无需人工审批，按当前权限与策略自动接受或拒绝；下文旧的能力审批、管理员批准及相关对齐结论均已被此决策取代。该增量尚未实现。

日期：2026-10-17。依据为 [调研记录](agents-agentd-research.md) 中的固定源码版本、Cloudflare 官方文档与 Headscale 官方资料。对照对象为更新后的 [架构方案](agents-agentd-architecture.md)。本次是设计与证据审查，没有运行互通测试。

**结论**

核心隧道资源和生命周期以 cfd 为基准；持久 AgentRegistration、注册、身份分离、能力审批与策略分发借鉴 Headscale；多租户角色和 TLS 域名服务是本产品定义；数据面使用 Xray。不能称为两套上游的完整复刻，也不承诺 Cloudflare/Tailscale 客户端兼容。

**逐项映射**

| 设计项 | 对照依据 | 本方案 | 判定 |
|---|---|---|---|
| 持久化 Tunnel | cfd Tunnel UUID、名称、凭据 | 相同资源生命周期；增加 Workspace 归属 | 对齐并扩展租户作用域 |
| Connector | cfd 启动生成随机 ID | 一次运行，重启产生新 ID | 对齐 |
| Connection | cfd 一个 Connector 多条边缘连接 | 多条逻辑反向承载连接，具体 worker 由 Xray 管理 | 语义对齐，数量/实现不同 |
| Replica | 同 Tunnel 凭据启动多个 cfd | 显式加入同 Tunnel，提供等价能力 | 对齐；不等同于可配置负载均衡 |
| Route 与 ingress | 域名定位 Tunnel；hostname/path 匹配源站 | PublishedRoute + 有序 IngressRule | 对齐；资源 ID/策略关联是管理扩展 |
| ingress 匹配 | cfd first-match、最终兜底 | 相同；源站保留原请求路径 | 对齐 |
| 共用隧道承载不同业务 | cfd 同连接对象分发 HTTP/WS/TCP | 同一 provider Connector 承载控制、Serve、Egress 逻辑流；按 capability/handler 隔离 | 物理连接复用；流级授权和撤销待实现 |
| 控制与数据分离 | cfd 管理 API/连接控制；Headscale 控制服务器 | control 管业务事实；edge 承载流量 | 原则对齐；服务端拆分是自研 |
| 用户与成员关系 | Cloudflare Account 成员/角色/范围 | 全局 User + Workspace Membership | 概念对应；不是 Headscale User=Workspace |
| instance admin、四种角色 | 用户需求 | 自定义 RBAC | 产品设计，不是上游原生角色 |
| 永久注册身份 | Headscale Node 的持久身份与名称 | AgentRegistration 覆盖所有 agentd，包括纯访问端 | 生命周期借鉴；不复制 IP、发现和 MachineKey/NodeKey 协议 |
| 注册 | Headscale 浏览器批准/预授权 key | 相同两种交互方向，作用域限定 Workspace/Tunnel | 原则对齐；不复用 Noise/注册线协议 |
| 提供方认证 | cfd TunnelSecret 直接用于注册 | 注册身份与 Tunnel 运行授权经控制面换取 Xray 工作凭据 | 权限分层对齐，握手与生命周期有意改变 |
| 出口能力 | Headscale 宣告与控制端批准 | agentd 宣告 + Workspace 管理员批准 | 原则对齐；目标从 IP 路由变为域名/端口 |
| 出口选择 | Cloudflare One hostname route 指定 Tunnel；Headscale 可选出口节点 | EgressRoute 选择指定 Agent 及其获准 Tunnel Binding | 服务分工借鉴；按 Agent 固定出口是本产品策略 |
| 默认权限 | 上游行为并不完全相同 | Web 默认成员、出口无规则则拒绝 | 用户确认的产品策略 |
| 服务授权 | 用户案例要求 | AccessGrant 支持匿名、实例用户、Workspace 成员组；每条有独立起止/撤销时间，按并集判断 | 产品扩展；只授予服务访问，不改变资源归属或 Membership |
| 出口规则授权 | 用户 Case 3 与限时授权要求 | 同一 AccessGrant 模型绑定 EgressRoute 的 egress.use；只接受已认证用户/成员组 | 产品扩展；与 Web 分享授权不互换，不提供匿名出口 |
| 配置管理 | cfd 支持 local/remote 两类 | 首版 remote-authoritative | 对齐其中一种，非完整功能兼容 |
| 策略分发 | Headscale 向客户端分发网络/策略状态 | 版本快照、ACK、更新传播 | 原则借鉴；SSE、签名、租约、自定义 schema 为本产品实现 |
| 离线与撤销 | 不能由上游名义推导统一保证 | 设定失效预算、活动流清理，待实测 | 明确的新语义，不声称与上游相同 |
| 数据拓扑 | Headscale 控制的 Tailscale 可直连或 DERP | 所有业务经 agents-edge；无 P2P | 按产品范围有意不同 |
| 客户端入口 | cfd access / Cloudflare One Client 与提供方分开 | agentd 内访问角色与提供角色分别认证 | 角色方向对齐，统一二进制是产品选择 |
| TUN/网络模型 | Headscale/Tailscale 是三层网络 | TUN 仅本机捕获；对外只处理获准协议 | 有意不同，满足 L7 产品范围 |
| OAuth2、服务 JWT | Cloudflare Access 的身份与应用授权 | oauth2-proxy 身份适配 + agents 资源策略 + 内部断言 | 思路借鉴；非 Access API/token 兼容 |

**本轮已修正的表述与设计细节**

1. Workspace 对应的是租户资源/成员边界，更接近 Cloudflare Account；不把 Headscale User 或 DNS Zone 当租户。
2. 修正稳定名字仅绑定 Tunnel 的缺口：增加 AgentRegistration 保存所有 agentd 的持久身份与名称，包括不提供任何服务的访问客户端。Tunnel 和 Connector 继续分别表示逻辑隧道与运行实例。
3. PublishedRoute 可关联同一 hostname 下多个路径 ingress，保留 cfd 按顺序匹配与最终兜底的规则。
4. 首版去掉自动路径改写的承诺。cfd 源站 URL 不支持路径，不将 path 匹配混同于 path 重写。
5. 明确首版集中管理配置。本地 YAML 和 `serve` 是期望状态输入，不能绕过 Workspace 审批和授权。
6. DataPlaneLease、签名快照、60 秒失联策略及每 Workspace Xray 实例标为我们的实现选择，避免将其表述成上游已有保障。
7. 首版允许 serve/egress 复用同一 provider Connector 承载连接；通过 purpose-specific capability、handler 和 FlowLease 隔离，无法证明子流隔离时再退回独立 worker。

用户案例进一步明确：服务授权的对象可为匿名访问者、单个用户或 Workspace 用户组，每条授权有独立期限且可同时存在。AccessGrant 取代互斥的公开/成员/指定用户顶层模式。隔离约束禁止未授权的跨租户管理/隧道访问，但不阻止资源拥有方显式授予某个服务的访问权。不能将“所有 Web 访客必须是资源 Workspace 成员”作为前置全局检查。主体使用 User ID/Workspace ID，邮箱和用户名只用于解析和邀请。授权截止时间不由 Cookie、隧道凭据刷新或控制面失联宽限延长。

**本轮补齐的身份模型缺口**

此前将稳定 FQDN 绑定 Tunnel，无法同时覆盖“所有 agentd 有名字”与“纯 access 客户端不需要服务 Tunnel”。本轮按用户原始要求补齐 AgentRegistration，不把这个缺口留给实现阶段处理。

```text
AgentRegistration（持久注册与名称，借鉴 Headscale Node）
├── ClientSession（用户作为访问方的登录会话）
└── AgentTunnelBinding（批准它运行指定 Tunnel）
    └── Connector（本次提供方运行，沿用 cfd 生命周期）
        └── Connection（承载连接）

Tunnel（持久逻辑隧道）也关联上述 Binding / Connector。
```

这个身份不分配网络 IP，不保存对等发现信息，不引入 VPN。首版注册凭据是高熵 bearer Token，语义接近 cloudflared 的 Tunnel credential：它证明可使用该逻辑注册身份，不证明不可复制的硬件身份。只有当 `via` 要求唯一物理安装时，才需要额外的设备密钥/挑战证明。Headscale 使用自己的设备密钥与协议，我们不宣称密码学实现相同。

指定 `via: agentd1...` 时，按 AgentRegistration 选择它的获准 Tunnel 和当前 Connector；不能因为同 Tunnel 有其他副本就换到另一台指定之外的 Agent。需要出口池时应显式定义，不与当前单 Agent 名称语义混用。

**仍需实验确认的边界**

- 同一反向池的两类业务是否正确分流，外部访问客户端是否无法进入保留的 Serve 目标。
- Xray Go 适配能否稳定取得可信主体、区分 Connector/Connection，并在撤销时关闭旧流。
- 单 Workspace runtime 重建是否真正释放旧通道，且不影响其他 Workspace。
- XHTTP 会话与 Edge 节点归属、流式反代、取消和超时。
- ECH/无 SNI/分片 ClientHello 的接受范围、拒绝行为和实际目标校验。
- oauth2-proxy 登录与资源授权衔接，以及跨 Workspace Cookie/回跳隔离。

源码与文档证据足以支撑当前架构方向，不能替代以上功能、安全与互通验收。
