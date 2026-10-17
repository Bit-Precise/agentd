# agents / agentd 运行手册

本手册使用真实控制 API、数据库、控制台和 Edge，不使用测试 fixture。localhost HTTP 是明确的 loopback 开发模式，对外部署必须使用 HTTPS。

下面命令默认从源码仓库根目录运行。使用已解压的发布包时跳过构建，将 `bin/agents`、`bin/agentd` 换为 `./agents`、`./agentd`；包内同样提供 examples 和运行手册。

## 1. 构建与初始化服务端

```sh
go mod download
make all
bin/agents init --config .run/agents.yaml
bin/agents serve --config .run/agents.yaml
```

Windows 使用对应 `.exe`。默认控制台为 `http://localhost:8080/console/`，接入端点为 `http://localhost:8080/agent`；管理员 Token 位于 `.run/state/agents/admin.token`，SQLite 位于同目录的 `agents.db`。

`init` 只输出文件位置，不显示 Token、不覆盖已有配置或密钥。只在自己的终端/编辑器中查看 Token 并登录，不把它放进 URL、命令参数、截图或工单。管理员不隐式绕过业务授权。

在控制台创建 `demo` Workspace；创建者自动成为该 Workspace 的 owner。使用其他用户运行设备时，先将其加入成员列表。创建注册密钥，选择该用户及 `ingress/serve/egress`，先不勾自动批准，设定有限期限与一次使用。完整密钥仅展示一次，可下载为文件。

把下载内容保存为 `.run/state/agents/demo.enrollment.key`。该目录由 init 建立为私有目录。Linux/macOS 文件权限设为 0600；Windows 要求仅当前账号、SYSTEM/Administrators 的私有 DACL，不能靠 Unix chmod mode 替代。

## 2. 注册、批准与运行 Agent

另开终端启动源站：

```sh
mkdir -p .run/origin
printf 'hello through agents\n' > .run/origin/index.html
python3 -m http.server 8090 --bind 127.0.0.1 --directory .run/origin
```

准备客户端 profile：

```sh
cp examples/agentd/local.yaml .run/agentd.yaml
chmod 600 .run/state/agents/demo.enrollment.key  # Linux/macOS
bin/agentd config validate --config .run/agentd.yaml
bin/agentd enroll --config .run/agentd.yaml --key-file .run/state/agents/demo.enrollment.key
```

Workspace 必须与注册密钥一致，instance/endpoint 必须与服务端 serverURL/edgeURL 一致。端口变化时两侧一起修改。

在控制台审核 `local-agent` 声明的 `hello → http://127.0.0.1:8090` 和 `example.com:443` 出口范围，然后批准：

```sh
bin/agentd run --config .run/agentd.yaml
```

enroll 保存持久注册 ID 与独立控制/访问/提供方 Token 到 `.run/state/agentd/credentials.json`。重复注册不会覆盖现有身份。pending 不代表业务可用；首次联调先批准再 run。

## 3. 验证 Serve

服务页面出现 `hello.demo.localhost`。首次批准新服务会创建有期限的本 Workspace 成员授权；已有服务授权不会因重载/重新批准而恢复默认全员。

用浏览器打开控制台提供的服务链接并完成服务登录跳转，应看到 `hello through agents`。服务使用自己的 host-only 会话，中央控制台 Cookie 不发送到源站。

如果系统不解析 `*.localhost`，在本机 hosts 中将 `hello.demo.localhost` 指向 `127.0.0.1`。也可明确为该服务添加短期匿名授权后执行下列检查；命令不会自动公开服务：

```sh
curl --noproxy '*' --resolve hello.demo.localhost:8080:127.0.0.1 http://hello.demo.localhost:8080/
```

没有匿名授权的非浏览器请求需要有效用户身份，401/403 不等于隧道故障。授权可以面向单用户、Workspace 或匿名访客，匿名仅适用于服务。删除所有有效授权不会退回全员访问。

## 4. 验证指定出口

创建出口路由：Workspace `demo`、Agent `local-agent`、精确域名 `example.com`、端口 443、TLS。再给运行该 profile 的用户或 demo 成员添加有限期出口授权。

```sh
curl --noproxy '' --proxy socks5h://127.0.0.1:1080 https://example.com/
curl --noproxy '' --proxy http://127.0.0.1:8088 https://example.com/
```

出口所在网络需能访问该网站，客户端继续验证网站原证书。创建路由、注册设备或打开 egress 都不会自动获得使用权。重定向到其他域名的新 TLS 连接仍需相应路由与授权。

未匹配请求被拒绝；Edge 不会改选其他 Agent；provider 再次核对批准与本地范围。loopback/link-local/metadata 等地址默认禁止，不能靠 DNS 将获准域名改指本机任意服务。

## 5. 更新、撤销与生命周期

- Linux/macOS 修改现有 provider 的 Serve/Egress 配置后发 SIGHUP。先收紧本地，再提交 desired；POST 失败会重试。Windows 修改后重启。监听、身份、transport 或最初未启动角色的变更需重启。
- 扩权进入 `pendingApproval`，原先获准的交集可继续运行；管理员核对新配置后批准。局部收紧/撤销使用独立流取消，不靠杀死所有共享连接。
- agentd 约每 2 秒刷新批准；认证 401/403 立即停止，连续网络失联超过约 30 秒或批准到期时停止角色。请求本身有超时，这些数值不是生产 SLO。
- 每条流受授权、策略与会话期限约束；短租约续期重新授权，失败则关闭，还有流/会话硬上限。重连不迁移旧流、不重放业务。最终期限见 [Edge](../edge/README.md) 与 [connection](../connection/README.md)。
- Token、注册密钥、授权各自有期限。在线 Agent 的 Token 剩余不足 7 天时可续为 30 天，保持 TokenID/hash，并不替换秘密。离线超过 30 天后需要新注册密钥、新名称/profile；原身份恢复尚未实现。
- 控制台用户页可更新本人 Token，管理员也可为其他用户重签。完整新 Token 仅展示一次，旧用户 Bearer 立即失效；已有浏览器会话仍按原到期时间生效。禁用用户与重签 Token 是不同操作。
- agents 停止会关闭连接目录与活动流；重启恢复 SQL 中注册身份与策略，Agent 重新连接。浏览器内存会话需要重新登录。

## 6. HTTPS、CDN 与数据库

[生产示例](../examples/agents/config.yaml) 使用 HTTPS。可执行 `agents init --development-http=false --server-url ... --edge-url ... --listen ... --tls-cert ... --tls-key ...` 初始化。证书与 DNS 由部署者提供；控制域、connect 域与服务域都需匹配，不自动申请 ACME。

CDN 属于信任边界，必须 HTTPS 回源。禁用认证/服务响应缓存，透传所需头和查询参数，认证回源来源，确保同一 packet-up 的 GET/POST 到同一 owner。WAF、长连接期限、流式响应和费用需针对实际 CDN 验收。

默认 SQLite，也可设置 `database.type: postgres` 与 DSN。pgx 和 pure-Go SQLite 无外部 SQLite 动态库依赖。DSN 若含秘密应保护配置文件；YAML 不执行环境变量插值。

更换数据库类型或 DSN 不会自动迁移原有身份、注册与授权。两种后端需要各自备份恢复，当前没有跨数据库导入迁移工具。

后端分为 `control/types → control/state → control/db`；HTTP/浏览器 broker 在 `control`，连接和流在 `edge`。这借鉴 Headscale 的职责分层，未引入其协议、API 或数据库 schema。每类实体有 SQL 表和组合约束，但当前在单进程维护状态快照，以事务和 revision 条件更新持久化；多个 agents 共享数据库不等于高可用。

先停服再备份 SQLite 与私有状态；运行时直接复制数据库文件不是一致性备份。PostgreSQL 的权限、备份、恢复和连接容量需部署验收。

## 7. 验证与尚未交付功能

```sh
go test -mod=readonly -race ./control/servertest ./control/state ./control/db ./edge
go test -mod=readonly -race ./integration ./connection ./transport/xhttp
```

CI 的 PostgreSQL 任务设置 `AGENTS_TEST_POSTGRES_DSN`，运行 `TestPostgresPersistenceAndConstraints`。测试创建独立随机 schema 并清理，不删除公共 schema；测试账号需要 CREATE schema 权限。未提供 DSN 时仅该测试跳过，常规 SQLite 测试仍执行。

数据面测试不依赖公网目标，通过可信注入拨号器访问本机 TLS 服务；不意味着生产开放任意 loopback 出口。“在线”表示已认证且版本匹配的连接，不代表每个源站都已主动探测。

尚未交付：OIDC、完整公钥签名快照/能力体系、TUN、WSS、分布式控制/Edge、自动证书、生产指标告警、平台安装器与生产容量承诺。
