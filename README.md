# agentd

设备端的服务发布与 TLS 域名出口客户端。一个进程可以组合运行 `ingress`、`serve`、`egress` 三种角色，使用修改版 XHTTP 连接服务端。

服务端 Control、Edge、Console 已迁至独立仓库 **[Bit-Precise/agents](https://github.com/Bit-Precise/agents)**，其部署、Helm chart 和组件镜像在那里维护。本仓库只构建和发布 agentd 客户端。

## 使用

在 agents 控制台创建 Workspace、成员和注册密钥，然后在设备上执行：

```sh
go mod download
make agentd
bin/agentd config validate --config /path/to/config.yaml
bin/agentd enroll --config /path/to/config.yaml --key-file /private/path/enrollment.key
bin/agentd run --config /path/to/config.yaml
```

管理员批准设备声明的服务与出口能力后，provider 自动接入。Ingress 的 HTTP CONNECT / SOCKS 将获准的 TLS 域名请求送至指定远端出口；Serve 按名称连接本地固定 HTTP 服务；Egress 取本地规则与控制面批准范围的交集。未匹配的流量不会回落直连。

- [生产配置示例](examples/agentd/config.yaml) / [本机配置示例](examples/agentd/local.yaml)
- [客户端配置](docs/agentd-config.md)
- [完整服务端及本机联调手册](https://github.com/Bit-Precise/agents/blob/main/docs/local-development.md)
- [构建与发布](docs/build-and-release.md)

## 仓库结构

参考 cloudflared 的职责分层：

| 目录 | 责任 |
|---|---|
| `cmd/agentd` | 注册、配置验证、进程运行与信号 |
| `config`、`credentials` | 本地配置、私有凭据、profile 锁 |
| `supervisor`、`orchestration` | 角色生命周期、控制面监督、批准与本地规则交集 |
| `ingress`、`policy`、`policygate` | HTTP/SOCKS、域名策略、TLS ClientHello 检查 |
| `connection`、`transport/xhttp` | agents v2 会话/流协议、可续短租约、HTTP 承载 |
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

协议 v2 支持有界短租约续期，不能与旧 v1 服务端混用。详见 [connection](connection/README.md) 与 [XHTTP](transport/xhttp/README.md)。

当前实现 HTTP CONNECT/SOCKS 与 TLS 域名出口；TUN 运行时明确拒绝，WSS 尚未实现。用户认证目前由 agents 提供 Token/浏览器会话，未接入外部 OIDC。真实 CDN 部署仍需验证长响应、缓存、请求预算和回源配置。

标准构建产出 Linux 裸二进制、DEB/RPM，macOS TGZ/PKG，以及 Windows EXE/MSI；另有 Linux amd64 FIPS 构建。签名与 FIPS 模块要求以[发布说明](docs/build-and-release.md)为准，不声称继承 Cloudflare 的代码签名或产品认证。
