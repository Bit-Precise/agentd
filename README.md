# agents / agentd

agentd 的首个可运行开发版本。agents 管理认证、连接与业务流；修改版 XHTTP 只负责 HTTP 承载。本阶段优先实现 XHTTP `packet-up`，WSS 延后。

目录和职责参考本机 cloudflared 的固定版本 `8e090e5bfa7a53e824fb2d7eb276f8ab08337b80`：命令入口、配置、连接、运行编排和 supervisor 分开。没有引入 cloudflared 的云端 API、QUIC 或 Xray Reverse。

```text
cmd/agentd/          CLI：run、config validate、version
config/             三角色 YAML 严格解析与校验
credentials/        预置注册凭据、批准快照、文件权限及进程锁
connection/         agents 握手、权威身份、yamux 流与取消
transport/xhttp/    修改版 packet-up；纯 net/http，无 Xray 运行时依赖
policy/             IDNA、域名/端口匹配、allow/deny
policygate/         有界 TLS ClientHello 检查与原字节重放
ingress/            本地 HTTP CONNECT、SOCKS5
orchestration/      本地配置与批准范围交集、Serve/Egress、局部撤销
supervisor/         角色运行、断线退避重连、退出
stream/             双向复制、半关闭和错误取消
integration/        本机 Edge fixture 与三角色端到端测试
```

**构建与验证**

需要 Go 1.27，与参考的 cloudflared 工具链保持一致；CI 固定 Go 1.27.2。模块路径为 `github.com/bit-precise/agentd`。

```sh
go mod download
make agentd
bin/agentd config validate --config examples/agentd/config.yaml
make test lint
make race
go test -mod=readonly -v ./integration -run TestAgentdThreeRolesOverModifiedXHTTP
```

GitHub Actions 按 cloudflared 的 9 个常规目标构建 Linux、macOS、Windows 产物，普通提交提供 artifact，`v*` tag 提供 GitHub Release 和 SHA256SUMS。矩阵、本地交叉构建命令及平台边界见 [构建与发布](docs/build-and-release.md)。

集成测试自动创建 loopback TLS Edge、HTTP 源站、HTTPS 目标和临时状态目录；同时运行三角色，验证 Serve、HTTP CONNECT、SOCKS5、目标证书保持不变、未匹配拒绝与服务撤回。测试完成后关闭监听与进程内任务，不需要外部账号或 CDN。

**运行 agentd**

配置格式见 [规范](docs/agentd-config.md) 和 [示例](examples/agentd/config.yaml)。当前 transport 使用：

```yaml
transport:
  type: xhttp
  mode: packet-up
  endpoint: https://connect.instance1.example.com/agent
  # caFile: ./development-ca.pem  # 可选私有 CA，不提供跳过证书校验开关
```

运行前，控制端或操作者需在 `agent.stateDir/credentials.json` 预置凭据和批准快照。Linux/macOS 目录权限为 0700、凭据文件为 0600；Windows 校验私有 DACL，不能仅依赖 chmod。一个本地 profile 只能由一个进程占用。以下展示字段，不是可以投入使用的凭据：

```json
{
  "version": 1,
  "workspace": "workspace1",
  "agentId": "CONTROL_ASSIGNED_AGENT_ID",
  "providerToken": "PROVISIONED_PROVIDER_TOKEN",
  "accessToken": "PROVISIONED_ACCESS_TOKEN",
  "approval": {
    "revision": 1,
    "expiresAt": "REPLACE_WITH_AN_ABSOLUTE_RFC3339_EXPIRY",
    "services": {"demo1": "http://127.0.0.1:8080"},
    "egress": [{"domain": {"exact": "oa.com"}, "ports": [443], "protocol": "tls"}],
    "deny": []
  }
}
```

ingress 需要 accessToken，serve/egress 需要 providerToken。Edge 必须实现 [agents 会话协议](connection/README.md)，验证 Token 并根据其可信注册表生成 Principal；不能直接把客户端 Hello 当作身份。批准快照和本地配置必须同时允许对应服务/目标，不能仅修改 YAML 扩权。

```sh
bin/agentd run --config /path/to/config.yaml
```

Linux/macOS 的 SIGINT/SIGTERM、Windows 的 Ctrl+C 关闭监听、连接和流。Linux/macOS 的 SIGHUP 重新读取配置，当前支持已启动 provider 的 Serve 映射及 Egress 限制更新；Windows 修改配置需重启。本地收紧会取消正在拨号和已连接的相关流。身份、监听、ingress 和 transport 变化，以及初次启用原本未启动的 provider，需重启。新增能力仍必须匹配既有批准快照，不会因重载获得授权或续期。注册凭据不写入日志。

**本阶段已经实现的边界**

- XHTTP 使用长 GET 下行、带序号的短 POST 上行。逐请求认证、会话绑定、重排/去重、缓冲与并发上限、deadline、取消、关闭都由本包实现。它是修改版线协议，**不兼容全部原生 Xray XHTTP 配置**，未实现 stream-one/stream-up。见 [承载说明](transport/xhttp/README.md)。
- 会话认证之后使用成熟的 yamux 多路复用；access 候选流与已授权 provider 流分开。每流有期限、并发上限、独立取消与半关闭，不能用访问角色发起提供方流。
- Serve 每个流只承载一个 HTTP 请求，支持流式响应和升级；它只连接批准的固定源站，校验服务 Host，剥离平台保留身份/Cookie，过滤源站的保留 Cookie 和 Domain Cookie。
- Egress 只接受批准范围与本地范围的交集，DNS 查询结果固定后再拨号；默认拒绝 loopback、link-local/metadata、multicast 和未指定地址，允许已批准域名解析到企业私网。测试通过可信注入拨号器使用 loopback 目标。
- HTTP/SOCKS 仅监听 loopback、未匹配目标拒绝，不自动直连。本阶段本机代理信任可访问该端口的本机进程，尚无按本机用户隔离的代理认证；部署范围是可信单用户开发环境。
- 外层 TLS + HTTPS 回源采用既定的受信 CDN 模型，没有额外的内层加密。

**尚未交付的功能**

本阶段不是完整生产版本。仓库中的 Edge 是集成测试 fixture，不是可部署的多租户 agents-control/gateway/edge 产品。OIDC 注册、审批 API、签名快照分发、生产路由目录、服务端单活仲裁、跨节点、浏览器登录和生产指标尚未实现。

批准文件目前由受信操作者预置；它不是已经实现的签名控制面。FlowCapability 签名验证留给会话授权回调，本机 fixture 通过可信策略验证。会话/流有绝对截止时间，尚无在线租约续期；到期主动关闭并按既有有效凭据重连，批准快照到期需重新取得批准。

TUN 配置可校验，但 `run` 明确拒绝启用 TUN；内核接入、DNS/FakeDNS 接管与退出恢复后续实现。WSS 延后。真实 CDN 的缓存、流式响应、超时、限额、回源身份和 session 粘性尚未验收，不能由本机 HTTP/1.1 与 HTTP/2 测试推导。

代码来源及许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
