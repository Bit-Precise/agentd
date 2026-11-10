# agentd

agentd 把分散在各处的机器组成一个 workspace：按域名把流量交给指定的出口节点、把本机 HTTP / SSH 服务发布给成员（或公网），并让 AI agent 通过 MCP 在别的节点上执行受策略约束的命令。设计见 [docs/design.md](docs/design.md)，线上协议见 [docs/protocol.md](docs/protocol.md)。

| 组件 | 作用 |
| --- | --- |
| `agentd` | 节点守护进程与 CLI（macOS、Linux、Windows）。角色：ingress（SOCKS5 / HTTP CONNECT / `agentd connect` / TUN）、egress、service、executor、submitter（MCP） |
| `agentrelay` | 数据面：节点唯一连接的服务端。终结节点会话与控制流、按控制面的答案转发流、为 HTTP 服务终结 TLS（edge） |
| `agentserver` | 控制面：目录、路由表、策略渲染与预检、成员证书、relay 证书、ACME，admin API 与 Web 控制台 |
| Web 控制台 | 由 `docs/agentserver-openapi.yaml` 生成：类型与客户端（openapi-typescript + openapi-fetch），资源、表单与操作由脚本从同一份文档推导，编译进 agentserver |
| Helm chart | `deploy/helm/agentd`：agentserver、可选 PostgreSQL、一个或多个自注册的 relay |

## 本机试用

需要 Go 1.27、curl；Web 控制台另需 Node 24 与 pnpm。

```sh
make web                      # 可选：生成并编译控制台（不做也能跑，控制台页面会提示未编译）
deploy/local/up.sh            # PostgreSQL + agentserver + agentrelay，数据在 .dev/
source .dev/env.sh

bin/agentserver workspace create home --relay relay-local
bin/agentserver route add -w home --from workspace --proto tls --domain suffix:example.com --to dorm
bin/agentd --home .dev/laptop join "$(bin/agentserver token create -w home --name laptop --roles ingress,submitter)"
bin/agentd --home .dev/dorm   join "$(bin/agentserver token create -w home --name dorm --roles egress,executor)"
```

在 `.dev/laptop/config.yaml` 打开 ingress（如 `socks5: { enabled: true, port: 17891 }`）与 submitter，在 `.dev/dorm/config.yaml` 打开 egress 与 executor 并写上允许 laptop 公钥的策略（`bin/agentd --home .dev/laptop key show` 查看公钥；全部字段见 [docs/agentd-config.yaml](docs/agentd-config.yaml)），然后：

```sh
bin/agentd --home .dev/dorm run &
bin/agentd --home .dev/laptop run &
curl --socks5-hostname 127.0.0.1:17891 https://example.com/      # 经 relay 由 dorm 出口
bin/agentd --home .dev/laptop task exec dorm -- uname -a          # 在 dorm 上执行（受 dorm 的策略约束）
bin/agentd --home .dev/laptop peers                               # 目录：复制公钥写进策略
```

控制台在 http://127.0.0.1:7800 ，令牌是 `$AGENTSERVER_ADMIN_TOKEN`。`deploy/local/down.sh` 停止服务。

## 部署到 Kubernetes

```sh
helm install agentd deploy/helm/agentd \
  --set domain=agentsrv.example.com \
  --set relays[0].name=relay-1 --set relays[0].domain=relay-1.agentsrv.example.com
```

安装后的说明（取 admin 令牌、端口转发控制台、DNS 指向 relay）会由 chart 打印。生产环境把 relay 的 `tls.mode` 设为 `acme` 或 `file`，并在 `agentserver.dnsProviders` 配置 Cloudflare 或 DNSPod 以签发受信任的 workspace 通配证书；`deploy/helm/agentd/ci/production-values.yaml` 是一份完整示例。镜像由 CI 推到 `ghcr.io/bit-precise/agentd/{agentserver,agentrelay,agentd}`：每次推送 main 更新 `edge` 标签，仓库里的 chart 默认就用它；发布版的 chart 固定为对应版本的镜像。

## 节点

```sh
agentd join '<加入链接>'          # 用 workspace 公钥校验 relay，令牌换取成员身份，写 ~/.agentd/config.yaml
agentd service install           # 用户级服务：LaunchAgent / systemd --user / 计划任务
agentd status | peers | routes   # 经本机 socket 查看守护进程
agentd mcp                       # stdio MCP server；或直接连守护进程的 http://127.0.0.1:<port>/mcp
ssh -o ProxyCommand='agentd connect %h %p' box.home.agentsrv.example.com
```

一台机器可以跑多个实例（各属一个 workspace）：`agentd -i work join …`，实例目录是 `~/.agentd/instances/work`。私有部署用 `AGENTD_EXTRA_ROOTS=<ca.pem,…>` 追加信任的 CA；证书总是校验，没有跳过校验的开关。

## 开发

```sh
make test        # 全部测试；PostgreSQL 用内嵌的二进制（或设置 AGENTD_TEST_DATABASE_URL）
make gen         # 重新生成 protobuf 与 admin API 代码
make dist        # 交叉编译 linux / darwin / windows × amd64 / arm64
make helm-lint
```

`internal/sim` 在一个进程里跑 agentserver、agentrelay 与多个 agentd，覆盖加入、经出口的 TLS、策略拒绝、远程任务、MCP 与经 edge 的 HTTP 服务。

## 发布与签名

推送 `v*` 标签触发 `.github/workflows/release.yml`：Linux 上交叉编译全部二进制；macOS 二进制在 macOS runner 上用组织的 Developer ID Application 证书签名（hardened runtime、安全时间戳），每个架构的 ZIP 交给 notarytool 公证，再由 Gatekeeper 确认公证票据；Windows 的 `.exe` 用 Azure Artifact Signing 签名（GitHub OIDC 登录 Azure，不存凭据，带 RFC 3161 时间戳），签完逐个校验签名与时间戳。最后产出 `agentd_<版本>_{linux,darwin,windows}_{amd64,arm64}` 压缩包、chart 包与 `SHA256SUMS`，发布到 GitHub Release，chart 推到 `oci://ghcr.io/bit-precise/charts`；带 `-` 的标签（如 `v0.1.0-rc.1`）发成预发布。

签名用的证书、公证密钥与 Azure 参数是 Bit-Precise 组织级的 secrets 与 variables，两个签名任务跑在仓库的 `release-signing` environment 里，该 environment 只放行 main 与 `v*` 标签。在 main 上手动运行这个 workflow 会走完构建、签名、公证与打包而不发布，用来检查签名配置；CI 的 `macOS signing (dry run)` 任务在每次推送与 PR 上用一次性的自签名身份跑同一个签名脚本（`scripts/release/sign-macos.sh`）。

## TUN 模式（macOS、Linux、Windows）

浏览器和 ssh 不做任何代理配置即可走分流：

```sh
sudo agentd elevator install      # macOS、Linux：每台设备一次，特权助手只服务当前用户
agentd elevator install           # Windows：在管理员 shell 里运行，注册系统服务并取得 wintun.dll
# 在实例配置里打开 roles.ingress.tun.enabled: true，然后重启 agentd
agentd status                     # tun 一节显示设备、物理接口、DNS 计数
```

elevator 创建 TUN 设备（Linux 的 `agentd0`、macOS 的 utun、Windows 的 wintun 适配器）、接管路由与系统 DNS，把设备交给非特权的 agentd（Windows 上由 elevator 转发数据包）。分流表判为交给 relay 的域名与服务域名由内置 DNS 答 fake-IP（198.18.0.0/15、2001:2::/48），其他流量按 SNI 嗅探后直连或转发，QUIC 对这些域名丢弃以回退 TCP。`tun.capture: fakeip` 只接管 fake-IP 段、不碰默认路由。agentd 退出时 elevator 恢复路由与 DNS。三个平台都由 CI 在 GitHub 的 runner 上用真实设备做端到端测试。

## 尚未实现

- P2P 直连：协议 v1 只预留了编号（协议 2.6），报文格式需要先在协议里定下来（设计文档阶段 5）。
- 边缘登录（`user:` / `usergroup:` 主语）与多个 agentserver 副本（阶段 5）。
