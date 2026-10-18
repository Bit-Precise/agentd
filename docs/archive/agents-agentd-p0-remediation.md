# agents / agentd P0 问题修复方案

历史方案说明：本文记录对原生 Reverse PoC 的补救设计及风险。当前已确认不让 Xray Reverse/用户表承担产品会话和授权，改由 agents 管理连接与流；本文中的流级准入、目标绑定及撤销原则继续适用，Xray handler/worker 修补不再是必选实现。当前规范见 [架构方案](../agents-agentd-architecture.md) 和 [本地配置](../agentd-config.md)。

这份方案针对 PoC 已确认的两个问题：

1. Xray `RemoveUser` 不会关闭已经建立的 Reverse/Mux 流。
2. Xray 原生 Reverse 不执行 hostname、port、Workspace 或服务用途授权。

原生 Reverse 只能作为承载层，不能作为 agents 的授权执行层。

## 1. 撤销：从用户表撤销改为流级撤销

### 1.1 两层撤销

撤销必须分成两步：

```text
撤销事件
  ├─ admission revoke：阻止新 VLESS/业务流
  └─ flow revoke：关闭已经建立的业务流
```

`RemoveUser` 只执行第一步，不能再把它报告成完整撤销。

### 1.2 每条业务流的记录

Edge 在授权成功、准备进入 Reverse 之前创建 `FlowLease`：

```text
FlowLease {
  flow_id
  workspace_id
  principal_id              # user 或 anonymous
  purpose                   # serve / egress
  resource_id               # PublishedRoute 或 EgressRoute
  tunnel_id
  connector_id
  policy_revision
  canonical_destination     # egress 必填；serve 使用 opaque service target
  issued_at
  expires_at                # 不得晚于 AccessGrant.expires_at
  cancel                    # Edge 侧取消句柄
  upstream_cancel           # agentd 侧取消句柄
}
```

`FlowLease` 必须放在 Edge 的内存流表中，并以 `flow_id` 关联 agentd 侧的活动流表。HTTP 请求、WebSocket、SSE、下载和每个 TLS TCP 会话都必须有自己的记录；不能只记录底层 VLESS 连接。

### 1.3 建立、续期和关闭

```text
Edge
  1. 验证 ClientSession、AccessGrant、PolicyRevision
  2. 创建 FlowLease
  3. 选择已批准的 Connector
  4. 向 agentd 发送服务端签发的 FlowCapability
  5. agentd 验证 capability 后创建本地流
  6. 任一侧撤销时，双向发送 cancel，并关闭两个方向的 Link/Conn
```

`FlowCapability` 至少绑定：`flow_id`、Workspace、purpose、resource、Tunnel、Connector、目标、policy revision、签发者、`iat` 和 `exp`。签名和重放校验在 agentd 侧完成；客户端不能自行构造该 capability。

新流先经过 Edge 的 admission check，再进入 Reverse。撤销时先把资源标为 `revoked`，停止新流，然后遍历 `FlowLease` 调用取消句柄。已知的 `expires_at` 由 Edge 和 agentd 本地 watchdog 强制执行，不依赖后台清理任务。

### 1.4 Xray 适配的优先顺序

按以下顺序实现，不能从 `RemoveUser` 直接跳到“已撤销”：

1. **首选：外层 Flow Gateway。** Edge/agentd 的 Go 网关拥有每条业务流的 `context.CancelFunc` 和真实 socket，Xray 只负责 VLESS/XHTTP/WSS 承载；撤销由网关关闭流。
2. **次选：Xray Handler 适配。** 如果 outbound Handler 能稳定拿到 `transport.Link` 的生命周期，就为每条流包一层可取消 Link，并把 `FlowLease` 注入 context；必须证明上下行和 Mux 子流都能关闭。
3. **兜底：重建隔离 worker。** 若原生 Reverse/Mux 不暴露子流关闭能力，则按 purpose 或 Workspace 重建 worker/runtime。重建是强制撤销，需记录中断原因和恢复时间。

不能把关闭底层共享 Reverse 连接作为普通撤销手段，否则会误伤其他资源；只有在 worker 与被撤销资源一一隔离时才能这样做。

### 1.5 控制面失联时的保证

主动 `revoked_at` 只有在撤销事件能到达 Edge 时才能即时传播。失联时必须公开一个可计算的最大暴露时间：

```text
max_exposure = min(flow.expires_at - now, flow_lease_ttl)
```

Flow lease 不得无限续期；控制面失联超过策略快照或 lease 上限后，Edge 拒绝新流，agentd 关闭旧流。这样能保证上界，但不能声称“断网时仍可秒级感知新的 revoke”。

## 2. 目标授权：原生 Reverse 前增加 PolicyGate

### 2.1 关键原则

外部客户端提供的 VLESS target、SOCKS 目标、CONNECT authority 和 SNI 都是不可信输入。它们只能作为候选目标，不能直接成为拨号目标或 Workspace 授权依据。

数据流必须变成：

```text
access-client
  → Edge VLESS admission
  → PolicyGate（身份、用途、资源、目标、revision）
  → signed FlowCapability
  → purpose-specific handler on the provider connection
  → agentd 再次校验
  → 固定目标拨号 / 固定服务源站
```

### 2.2 Serve 与 Egress 的逻辑流隔离

PoC 已证明共用未经改造的原生 Reverse 路径时，目标字段可以把流送到未配置目标。因此首版可以复用同一个 provider Reverse transport，但不能复用原生 target 作为授权边界：

```text
reverse-provider UUID → 同一 Connector 的双向承载连接
  ├─ serve Flow → serve handler / opaque service target
  └─ egress Flow → egress handler / signed canonical destination
access-client UUID     → 只能进入 Edge PolicyGate
```

物理承载连接复用本身不是安全边界；安全边界是服务端签名的 purpose namespace、FlowCapability、handler 和 FlowLease。一个 provider Connector 可以同时承载 Serve/Egress 逻辑流，但在无法证明子流隔离、目标校验和撤销时，必须退回独立 worker。

### 2.3 Serve 目标

Edge 不把客户端可控的 hostname/path 直接交给 bridge。授权后生成不可猜的内部目标，例如：

```text
svc/<published-route-id>/<ingress-rule-id>/<revision>
```

只有受信 Edge 能生成该目标，并在 `FlowCapability` 中签名。agentd 只接受签名且未过期的 service target，再按同一 revision 的 Ingress 编译结果选择本地源站；未知 alias、错误 Workspace、错误 revision 一律拒绝。

源站 URL 不从业务流中读取。它来自已批准配置，且由 agentd 对 scheme、host、port、重定向和受限地址重新校验。

### 2.4 Egress 目标

Edge 先把客户端输入规范化为：

```text
canonical_destination = {
  idna_lowercase_domain,
  port,
  protocol,
  route_id,
  revision
}
```

然后依次检查：

1. ClientSession 和 `egress.use` AccessGrant；
2. EgressRoute 的 exact/suffix、端口和协议；
3. Workspace/Instance 约束和显式 deny；
4. 指定 AgentRegistration、TunnelBinding、Connector；
5. provider agentd 的本地安全目标检查是否允许按该 canonical domain 发起连接；解析结果不作为用户可见路由对象，也不进入 AccessGrant 主键。

agentd 在实际拨号前再次验证同一份签名 capability，并使用 capability 中绑定的 canonical destination。不能只把原始 SNI 或 Mux target 传给 agentd 后再让它自行猜测。

TLS 业务字节保持原样；capability 通过受信的内部控制/流建立元数据传输，不能插入目标 TLS payload。

### 2.5 失败路径

以下情况都必须进入 blackhole/reject：

- 没有 FlowCapability；
- capability 过期、重放或签名错误；
- Workspace、purpose、Tunnel、Connector、route 或 revision 不一致；
- 客户端目标和 canonical destination 不一致；
- SNI/CONNECT 不匹配；
- 没有规则、规则被拒绝、Connector 离线或 agentd 本地复核失败。

不能 fallback 到默认 outbound、Edge 直连、另一个 Workspace 或未批准的 Connector。

## 3. 推荐的首版边界

首版应明确采用以下取舍：

```text
Xray = 传输和连接承载
Flow Gateway = 流生命周期和撤销
PolicyGate = 身份、Workspace、purpose 和目标授权
agentd = capability 二次校验和最终拨号/源站连接
```

如果 Xray Handler 无法提供可靠的子流关闭和 capability 传递，就不要继续扩大原生 Reverse 的职责；使用独立 worker 或一个受控的内部流网关，直到撤销和目标隔离能够被自动化测试证明。
