# agentd

设备端的服务发布与 TLS 域名出口客户端。一个进程可以组合运行 `ingress`、`serve`、`egress` 三种角色，使用修改版 XHTTP 连接服务端。

服务端 Control、Edge、Console 已迁至独立仓库 **[Bit-Precise/agents](https://github.com/Bit-Precise/agents)**，其部署、Helm chart 和组件镜像在那里维护。本仓库只构建和发布 agentd 客户端。

## 使用

在 agents 控制台创建 Workspace 并加入成员，然后在设备上执行：

```sh
go mod download
make agentd
bin/agentd config validate --config /path/to/config.yaml
bin/agentd login --config /path/to/config.yaml   # 浏览器中确认 Workspace 与运行身份
bin/agentd run --config /path/to/config.yaml
```

无人值守设备改用服务账号的注册密钥：`bin/agentd enroll --config /path/to/config.yaml --key-file /private/path/enrollment.key`。

注册和配置变更没有人工审批：Control 按运行主体的角色上限和 Workspace 策略自动校验设备声明，通过即生效，越权或冲突直接拒绝并说明原因。Ingress 的 HTTP CONNECT / SOCKS 将获准的 TLS 域名请求送至指定远端出口；Serve 按名称连接本地固定 HTTP 服务；Egress 取本地规则与控制面限制的交集。未匹配的流量不会回落直连。

- [生产配置示例](examples/agentd/config.yaml) / [本机配置示例](examples/agentd/local.yaml)
- [客户端配置](docs/agentd-config.md)
- [实体、状态机与关系](https://github.com/Bit-Precise/agents/blob/main/docs/model.md)（当前实现的权威说明）
- [User / Service Account 与 Hydra Device Flow 目标设计](https://github.com/Bit-Precise/agents/blob/main/docs/identity-and-device-flow.md)（待实现）
- [完整服务端及本机联调手册](https://github.com/Bit-Precise/agents/blob/main/docs/local-development.md)
- [构建与发布](docs/build-and-release.md)

## 仓库结构

参考 cloudflared 的职责分层：

| 目录 | 责任 |
|---|---|
| `cmd/agentd` | 注册、配置验证、进程运行与信号 |
| `config`、`credentials` | 本地配置、私有凭据、profile 锁 |
| `supervisor`、`orchestration` | 角色生命周期、控制面监督、生效配置与本地规则交集 |
| `ingress`、`policy`、`policygate` | HTTP/SOCKS、域名策略、TLS ClientHello 检查 |
| `connection`、`transport/xhttp` | agents v3 会话/流协议、可续短租约、HTTP 承载 |
| `api`、`controlclient` | 注册 wire contract 与控制 API 客户端；服务端复用同一 SDK |
| `integration` | 客户端三角色及传输回归 |
| `packaging`、`scripts` | 平台安装包与发布校验 |

服务端是单向依赖客户端 SDK 的独立 Go module；agentd 不依赖服务端、SQLite 或 PostgreSQL。服务端固定 SDK 版本，协议变更需联合验证两仓库。

## 验证与兼容性

```sh
make test lint
make race
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

协议 v3 支持有界短租约续期，凭据文件为 v2；取消审批后需与 agents 服务端同时升级，不能与旧版本混用。详见 [connection](connection/README.md) 与 [XHTTP](transport/xhttp/README.md)。

当前实现 HTTP CONNECT/SOCKS 与 TLS 域名出口；TUN 运行时明确拒绝，WSS 尚未实现。个人设备用 `agentd login` 接入（OAuth Device Flow，在浏览器确认 Workspace 与本人/服务账号身份）；无人值守设备用服务账号的注册密钥执行 `agentd enroll`。

目标设计在同一二进制增加 Hydra Device Flow：用户在浏览器完成 OIDC 后选择有权限的 Workspace，再选择本人或该空间的 Service Account；SA 仅 maintainer 及以上可选择/管理，不能登录控制台。限定 Workspace 和主体的 OAuth access token 只用于一次设备注册兑换，权限和配置自动校验通过即签发各 Agent 独立凭据（取消审批的部分已实现）。SA 固定属于一个 Workspace，可以对应多个 Agent；无人值守注册密钥将只绑定 SA。Device Flow 尚未改变上述现有命令。真实 CDN 部署仍需验证长响应、缓存、请求预算和回源配置。

发布矩阵与 GitHub CLI 对齐：Linux 四种架构的 tar.gz/DEB/RPM、macOS 两种架构的 ZIP 和 universal PKG，以及 Windows 三种架构的 ZIP/MSI；共 21 个产品，加校验和文件共 22 个公开资产。签名、安装验证及本地 FIPS 构建说明见[发布说明](docs/build-and-release.md)。
