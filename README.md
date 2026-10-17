# agents / agentd

一个可自托管的服务发布与 TLS 域名出口系统。`agents` 提供控制 API、浏览器控制台、服务入口和单节点 Edge；`agentd` 在设备上组合运行 ingress、serve、egress。设备主动连接服务端，无需开放公网入站端口。

当前可以完成创建 Workspace/用户、设备注册与批准、服务访问、指定 Agent 出口、限时授权和撤销。这仍是开发版本：登录使用本产品用户 Token，尚未接入 OIDC，也不兼容 Cloudflare Tunnel、Headscale/Tailscale 或原生 Xray 的线协议。

```text
浏览器 ── 服务鉴权 / gateway ──┐
                               ├─ agents Edge ── provider 会话 ── agentd ── 本地源站
应用 ── agentd ingress ─────────┘                                    └─ TLS 目标
                控制台 / control API ── state ── SQLite 或 PostgreSQL
```

## 快速开始

需要 Go 1.27（CI 固定 1.27.2）、Python 3（打包与本地示例）。SQLite 使用 pure-Go `modernc.org/sqlite`，两个二进制均可 `CGO_ENABLED=0` 构建。

```sh
go mod download
make all
bin/agents init --config .run/agents.yaml
bin/agents serve --config .run/agents.yaml
```

默认入口为 `http://localhost:8080/console/`，仅监听 loopback。`init` 在私有状态目录生成管理员 Token 文件，只输出文件位置；使用该 Token 登录控制台。完整的注册、批准、Serve 与 Egress 联调步骤见 [本地运行手册](docs/local-development.md)。不要提交管理员 Token、注册密钥或生成的状态目录。

控制台创建 Workspace、成员与注册密钥后，设备执行：

```sh
bin/agentd config validate --config /path/to/agentd.yaml
bin/agentd enroll --config /path/to/agentd.yaml --key-file /private/path/enrollment.key
# 管理员在控制台核对并批准该设备的期望配置。
bin/agentd run --config /path/to/agentd.yaml
```

注册保存独立的控制/访问/提供方凭据。已注册 profile 不会被 enroll 覆盖；用户身份、设备身份和获准能力分别检查。一个设备可以同时发布本地服务、提供出口，并作为客户端访问其他获准出口。

## 工程结构

客户端参考 cloudflared 的 supervisor、连接与运行编排分层；后端参考 Headscale 的命令入口、持久注册、状态管理、策略与数据库职责拆分，使用本项目自己的实体和 API。没有复制其网络协议或整个服务端。[来源说明](THIRD_PARTY_NOTICES.md)

| 目录 | 当前职责 |
|---|---|
| `cmd/agents`、`control` | init/serve、HTTP API、Token/浏览器会话、CSRF、服务登录兑换 |
| `control/types`、`control/state` | Workspace、成员、设备、批准、路由、授权、决策与变更通知 |
| `control/db` | SQLite/PostgreSQL、显式 schema、组合约束、事务与 revision 条件更新 |
| `control/assets` | Go embed 中文控制台；无外部脚本或 npm 构建依赖 |
| `edge` | 权威身份绑定、连接目录、精确提供方选择、流与撤销 |
| `cmd/agentd`、`controlclient` | enroll/run、批准配置轮询与期望配置提交 |
| `config`、`credentials` | 三角色 YAML、受保护凭据、profile 进程锁 |
| `connection`、`transport/xhttp` | agents 会话/流协议、yamux、修改版 packet-up 承载 |
| `policy`、`policygate` | 域名/端口策略、有界 ClientHello 解析与原字节重放 |
| `ingress`、`orchestration`、`supervisor` | HTTP/SOCKS、源站/出口拨号、局部收紧、重连与控制面监督 |
| `control/servertest`、`integration` | 真实 HTTP API/Edge/agentd 联调及底层回归 |

## 配置、部署与验证

- [服务端配置](examples/agents/config.yaml)：HTTPS 入口、数据库与私有状态。
- [客户端配置](examples/agentd/config.yaml) / [本机配置](examples/agentd/local.yaml)：三角色独立启用。
- [配置说明](docs/agentd-config.md)、[运行手册](docs/local-development.md)、[构建发布](docs/build-and-release.md)。
- [后端实现说明](docs/backend-implementation.md)：当前代码的 Headscale 职责映射、实体、状态机、API 与请求路由。
- [架构设计](docs/agents-agentd-architecture.md) 与历史审查包含长期目标；当前实现以 README、运行手册和代码为准。旧 Reverse PoC 不替代当前架构的验收。

```sh
make test lint
make race
go test -mod=readonly -race ./control/servertest ./edge ./integration
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

常规测试使用临时 SQLite、loopback HTTP/TLS 目标和临时凭据，无需外部账号/CDN。CI 单独启动 PostgreSQL 验证迁移、持久化、revision 冲突和租户约束。发布保留 Linux/macOS/Windows 的 9 个目标，每个包同时包含 `agents` 和 `agentd`；交叉编译不等于对应设备已完成真机验证。

## 认证与当前边界

- 控制台 Token 换取 HttpOnly 会话；Cookie mutation 校验 CSRF/Origin。服务使用独立 host-only 会话与一次性兑换，仍逐次检查授权。Token 仅创建时展示，数据库保存其哈希。
- 一个 `agents` 进程维护 SQL 状态与内存连接/流目录。SQLite/PostgreSQL 可切换，当前全量事务快照不是多控制节点架构；不提供多 Edge 迁移。
- 服务访问连接批准的固定源站；Egress 精确选择 Agent，检查域名/SNI和拨号地址，不回落到 Edge、其他 Workspace 或客户端直连。
- 修改版 XHTTP 为长 GET 下行与有序短 POST 上行；有认证、去重、背压、取消与预算。未实现 WSS、stream-one/stream-up，未宣称原生 Xray 全协议兼容或通过真实 CDN 验收。
- 采用受信 CDN + HTTPS 回源，不额外套内层 TLS。生产需实际 DNS、证书、回源身份与缓存配置；不自动申请 ACME。
- 本地 HTTP/SOCKS 仅监听 loopback，信任可访问端口的本机进程，尚无按本机用户隔离的代理认证。TUN 配置可解析，但运行时明确拒绝；内核/DNS 接管未实现。
- 批准配置在线轮询；本地收紧、撤销、失联与流到期关闭相关资源。长流续期重新授权，并有硬期限；重连不重放业务。详见 [Edge](edge/README.md) 和 [connection](connection/README.md)。
- 在线 Agent 的控制/访问/提供方 Token 临近到期时自动延长期限，保持原 TokenID/hash；这是续期，不是秘密轮换。离线超过 Token 有效期（30 天）仍需新注册密钥与新 profile，原身份恢复尚未实现。用户可在控制台为自己重签 Token，管理员可为其他用户重签；旧 Bearer 失效，已有浏览器会话仍按原期限有效。
- 尚无 OIDC、完整公钥签名快照/FlowCapability、自动秘密轮换、生产指标告警、平台安装器与生产容量承诺。可运行联调不等于生产加固完成。
