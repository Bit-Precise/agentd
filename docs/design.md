# agentd 设计文档

- 状态：v0.18 草案，已有可运行实现
- 日期：2026-11-09
- 范围：评估原始方案，并给出可以直接开工的初步设计；标注「待定」的地方汇总在第 10 节；历次评审与反馈的处理见第 12 节；SSH 可行性研究见附录 A
- 配套：协议规范 `docs/protocol.md`（线上格式、状态机、校验顺序、常量），protobuf 定义 `proto/agentd/v1/wire.proto`，agentd 实例配置参考 `docs/agentd-config.yaml`，agentserver admin API 定义 `docs/agentserver-openapi.yaml`

修订记录

| 版本 | 日期 | 变化 |
| --- | --- | --- |
| v0.1 | 2026-11-08 | 初稿：评估原始方案，relay 作为对等 agentd，节点间 Noise 端到端加密，`.agentd` 假 TLD，域名加 CIDR 路由 |
| v0.2 | 2026-11-08 | 按反馈重做：控制面独立为 agentserver；只转发 TLS 流量和任务；域名识别以 sniffing 为先、fake-IP 兜底；路由规则集中在 agentserver 且只有域名级；真实域名加 ACME 证书；任务就是 Codex 的 tool call；承载为 XHTTP / WebSocket / HTTP Upgrade；不做 UDP |
| v0.3 | 2026-11-08 | 按独立评审修正：TUN 下 UDP 本机直通并用 QUIC 嗅探阻止绕路；特权助手与用户态主进程拆分；executor 不经 shell 执行、策略改为 argv 前缀；流头部由发起节点签名；service 改为 HTTP 反向代理；WebSocket 为默认承载；任务输出格式对齐 Codex 实际代码；DoH/ECH 对策；Ack 失败回退；Challenge 握手；证书状态机；提供侧一律默认拒绝；运维条目；路线图重排 |
| v0.4 | 2026-11-08 | 按第二轮反馈修正：身份改为 WireGuard 式的 X25519 静态密钥对，节点与 agentserver、节点与节点之间各跑一层 Noise_IK，取消自定义的签名头部；服务证书与私钥只在 agentserver，由它作为 HTTPS 边缘终结 TLS；支持 SSH（`tcp` 流的 `proto: ssh`）；明文 HTTP 明确不支持；carrier 改名 transport，helper 改名 elevator；补写会话多路复用模型与来自 Xray 的流拼接经验；策略的「谁」改为对端公钥；节点可配置是否接受 agentserver 下发的配置；删除与本机旧项目相关的待决问题 |
| v0.5 | 2026-11-08 | 按补充反馈明确两件事：实例的两个等价名字（`agentd://<公钥>` 与 `agentd://<workspace 域名>/<实例名>`，实例名按主机名规则，默认取 hostname）；实例接入 agentserver 的完整流程（令牌、加入链接、握手载荷、目录登记、后续连接、改名换机吊销） |
| v0.6 | 2026-11-08 | 按第三轮反馈：agentserver 转发前校验授权（目标上报的 `accept_from` 与可选的 workspace ACL）；去掉节点间的 Noise 加密层，只保留签名：身份密钥改为 Ed25519，`Open` 与任务请求由发起方签名、输出由 executor 签名，与 agentserver 的 Noise 握手用派生的 X25519 密钥；恢复首段数据流水线 |
| v0.7 | 2026-11-08 | 策略模型重做：每个节点用 `policy.source` 在本地与 agentserver 之间选择策略的权威来源，`server` 模式下由 agentserver 经控制通道下发、本地 deny 仍作刹车；节点执行的统一是 (公钥集合, action, target)；agentserver 上用主体（实例、实例组、workspace、已登录用户、public）书写并渲染成每个节点的公钥策略；判定改为显式 deny 优先；删除独立的 workspace ACL（由中央策略取代）；对照 Tailscale、Cloudflare Access、Nebula、Teleport 等相关工作 |
| v0.8 | 2026-11-08 | 权限引擎评估后的决定：节点侧不设自定义的目标组，本地策略直接写字面 target（域名模式加协议、argv 前缀、服务名）；目标组（域名集合）只在 agentserver 上定义并在渲染时展开；撤回「提供侧命名资源」的提议，`ask` / `audit` 动作与 `until` / 速率条件暂不做 |
| v0.9 | 2026-11-08 | 不采用 Cedar；身份分四级：节点、组、workspace、agentserver 各一对 Ed25519 密钥，组与 workspace 的密钥由 agentserver 保管并签发短期成员证书，证书由成员随 `StreamOpen` 出示，接收方据此把组或 workspace 公钥算进请求方身份；渲染不再展开成员，`trust_server_directory` 取消；为 P2P 预留 transport 名字、会话角色、信令编号与「授权与路径无关」的约束 |
| v0.10 | 2026-11-08 | 补充 P2P 直连方案：节点自选是否加入（`p2p.enabled`，默认关闭）；agentserver 作会合点交换候选地址与打洞邀请；QUIC 上的直连会话照跑 Noise_IK 与 yamux；流的放置与回退；安全、隐私与可观测性；协议规范 2.6 预留消息名、编号与探测报文格式 |
| v0.11 | 2026-11-08 | 控制面与数据面分开部署：agentserver 只做控制面（目录、分组与证书、规则与策略、ACME、relay 指派、P2P 会合），新程序 agentrelay 做数据面（节点的数据会话、转发预检与拼接、HTTP 服务边缘、STUN）；每个节点一条控制会话加一条数据会话；relay 用控制面下发的快照工作，控制面不可达时继续转发；服务证书私钥下发到 relay 内存；MVP 每 workspace 一个 relay。协议规范新增第 12 节：节点生命周期、会话、transport、流、任务、服务、成员证书、受管策略、relay 快照、P2P 的状态机 |
| v0.12 | 2026-11-08 | 按对术语表的逐条反馈重做服务端划分与若干概念。节点只连 relay：一条会话，流 1 是到 agentserver 的加密控制隧道（隧道内再做一次 Noise_IK），agentserver 成为只对 relay 可达的管理平台，relay 凭 agentserver 签发的 relay 证书被节点认可；取消 relay 快照，relay 按需向控制面查询并缓存答案；取消 `accept_from`，策略是唯一的授权抽象，自管节点随 `Advertise` 上报生效策略供预检；路由规则改为路由表（源、协议、域名、目的），ingress 只收去掉目的的分流表，三段式转发（ingress 判断、控制面选路与预检、目的节点验签与执行），`Open.to` 统一为下一跳，任务目标在 `task.executor`，新增 `Ack.responder`，删除 `RULE_TARGET_MISMATCH` 与 `NOT_ACCEPTED`；域名集合推迟到后续；一台设备可运行多个实例；transport 术语补 `p2p`；补写成员证书与密码学用法的说明 |
| v0.13 | 2026-11-08 | 控制流改为在 relay 终结、agentserver 做后端：去掉控制隧道与隧道内的第二次握手，节点的控制消息由 relay 以会话身份转交（`NodeMessage`），agentserver 发给节点的控制消息一律签名（`Signed` 信封，上下文 `agentd/control/v1`）由 relay 送达（`Deliver`）；握手与加入由 relay 向后端查询（`node` / `join`），删除 `NodeAdmitted` 与 `SESSION_CONTROL`；relay 看得到控制内容但伪造不了 |
| v0.14 | 2026-11-08 | 新增实例配置参考 `docs/agentd-config.yaml`（字段分组、地址与条目一律结构化）；按配置评审收紧策略形态：去掉 `peers` 与 `--pin`，规则的 `who` 只写公钥（节点、组或 workspace 的）或 `*`；角色下的规则列表叫 `policies`，每条是 (public_key, action, target)，`public_key` 是一把公钥或 `*`；策略来源 `policy_source` 下放到每个提供侧角色；egress 规则的 `proto` 改为单个协议；服务的 `access` / `allow_from` 并入 service 规则，`*` 对 HTTP 服务含公网访问者；`agentd peers` 只用于查看目录以复制公钥；所有配置文件以 k8s 风格的 `apiVersion` / `kind` 开头；relay 配置归属 workspace（`workspace.relay`）；去掉 `accept_push`，分流表与目录总是接受；去掉 `key_file`，私钥固定在实例目录的 `node.key`；去掉 relay 的 `tls.insecure_skip_verify`，所有 transport 都是 TLS 且总是校验；去掉 executor 的 `programs` 表，能执行的程序就是 allow 规则里的 `argv[0]`，执行路径取自规则；服务列表叫 `servers`；嗅探跳过表改名 `sniff.skip_ports` 并去掉 5432；去掉服务的 `mode: tcp`（非 HTTP 的 TLS 透传），服务只有 http 与 ssh 两种；去掉服务的 `target.tls` 与 `host_header`，目标只能是明文 HTTP、固定保留原始 Host；实例名放在 k8s 风格的 `metadata.name` |
| v0.15 | 2026-11-08 | 节点的信任根改为 workspace 公钥：加入链接的 `key` 与配置的 `workspace.public_key` 都是它；发给成员的控制消息、该 workspace 的 relay 证书（按 relay × workspace 签发，relay 的 well-known 按 workspace 返回）与 workspace 成员证书都由 workspace 密钥签（agentserver 保管并代签）；agentserver 自己的密钥只用于 relay 会话，节点不需要知道它。配置：`sniff` 改名 `sniffing`；TUN 的 DNS 配置并入 `tun.dns`（`override_system`、`upstream`），去掉 fake-IP 模式开关与代理模式下的 DNS 监听；域名模式写成 `{ kind, value }` 对象；日志改为 `log.decision.enabled / path` 与 `log.audit.enabled / path`，executor 的审计日志路径移到这里。新增 agentserver admin API 的 OpenAPI 定义 `docs/agentserver-openapi.yaml`（workspace、令牌、节点、组、路由表、策略、服务、证书、relay），agentserver 配置加 `admin_token_env`，CLI 补 policy / service / status |
| v0.16 | 2026-11-09 | 按首个实现对齐：agentserver 的状态库改为 PostgreSQL（`database.url` / `url_env`，迁移内嵌，私钥用 `state_key_env` 派生的 AES-256-GCM 密封）；relay 可自注册：`ClientHello.relay`（`RelayRegistration`：名字、URL、transport、STUN），公钥未登记时 `join_token` 是 relay 注册令牌（admin API `/relays/tokens` 签发一次性令牌，或 `relay_join_token_env` 给出长期引导令牌）；agentserver 在 relay 会话端点旁提供 `GET /.well-known/agentserver`（身份与 transport 路径），relay 的 `control.public_key` 为空时经校验过的 TLS 取得；agentserver 的 `key_file` 可省略（密钥密封在状态库），`tls.mode` 为 `acme`（TLS-ALPN-01，缓存在状态库）、`file`（文件变化时重载）或 `selfsigned`（状态库里的开发 CA，`ca_out` 导出）；admin 监听同时提供 Web 控制台（由 OpenAPI 文档生成）；agentrelay 配置加 `url`、`key_env`、`control.ca_file`、`control.transport`、`control.join_token_env`；ACME 用 `golang.org/x/crypto/acme` 加 Cloudflare DNS-01，不依赖 lego；agentd 用 `AGENTD_EXTRA_ROOTS` 追加信任的 CA 文件（仍总是校验证书），本地 API 在所有平台（含 Windows 10+）都是 unix socket，路径过长时放到用户缓存目录；TUN、elevator 与 P2P 尚未实现 |
| v0.17 | 2026-11-09 | 实现 TUN 模式（阶段 2，macOS 与 Linux）：elevator 以 root 运行（`sudo agentd elevator install` 装成 LaunchDaemon 或 systemd 系统单元，只服务安装者的 uid，按 unix socket 的对端凭据校验，同一时刻只交给一个实例），在 `/var/run/agentd-elevator.sock` 上收 `open` 请求，创建设备并用 SCM_RIGHTS 把描述符交给非特权的 agentd，agentd 断开即恢复路由与 DNS；Linux 设备 `agentd0` 用 IFF_NO_PI 纯 IP 帧，接管用 `0.0.0.0/1` 与 `128.0.0.0/1` 两条路由，agentd 自身的套接字绑定物理接口的源地址，elevator 加 `from <源地址> lookup 5200` 策略路由让它们走原默认路由，DNS 走 systemd-resolved（`resolvectl dns/domain ~.`）或改写并恢复 resolv.conf；macOS 用 utun、同样两条路由，自身套接字用 `IP_BOUND_IF`，DNS 用 scutil 改写主服务的 `State:/Network/Service/<id>/DNS` 并在退出与换网时恢复；agentd 自身的域名解析直接问上游，不经内置 DNS；网络切换由 elevator 每 5 秒检测并推给 agentd，agentd 换绑并重连 relay；QUIC Initial（v1、v2）解密取 SNI，命中转发或服务域名的丢弃；Windows 的 TUN（wintun）仍在阶段 4 |
| v0.18 | 2026-11-09 | TUN 补齐 Windows 并改进 macOS：Windows 的 elevator 是系统服务（`agentd elevator install` 在管理员 shell 里注册，下载并按 SHA-256 校验 wintun 0.14.1 放到 agentd.exe 旁），socket 的 ACL 只允许安装者的 SID；wintun 会话不能跨进程传递，所以 elevator 持有适配器并在 socket 上以 `[类型][u16 长度][载荷]` 帧转发数据包，agentd 自身套接字用 `IP_UNICAST_IF` 绕过 TUN，适配器用 netsh 配地址、路由与 DNS，关闭即删除；macOS 的 DNS 接管改为在动态存储里写主服务的 `Setup:` DNS（DHCP 来的 `State:` DNS 会被绑定到物理接口，查询不进 TUN），退出时写回或删除；elevator 退出前等待会话完成恢复，agentd 停止时先释放设备再拆协议栈；新增 `tun.capture: all | fakeip`，fakeip 只把 fake-IP 段路由进 TUN、不接管默认路由；TUN 端到端测试在 GitHub 的 Linux、macOS、Windows runner 上跑真实设备 |

目录

1. [概述](#1-概述)
2. [评估与决定](#2-评估与决定)
3. [核心概念与术语](#3-核心概念与术语)
4. [整体架构](#4-整体架构)
5. [角色设计](#5-角色设计)
6. [域名、寻址与路由](#6-域名寻址与路由)
7. [协议与传输](#7-协议与传输)
8. [安全模型](#8-安全模型)
9. [配置、CLI 与运维](#9-配置cli-与运维)
10. [待决问题](#10-待决问题)
11. [实施路线](#11-实施路线)
12. [评审与反馈的处理](#12-评审与反馈的处理)
- [附录 A：SSH 可行性研究](#附录-assh-可行性研究)

---

## 1. 概述

agentd（agent daemon）把用户分散在不同网络里的设备和 AI agent 连成一个按域名寻址的私有网络。每个 agentd 实例属于一个 workspace，按角色提供或消费能力；一台设备可以跑多个实例，分别加入不同的 workspace。服务端分成两个分开部署的程序：控制面 agentserver 是管理平台，维护 workspace、成员目录、分组与证书、路由表和策略，只对 relay 可达；数据面 agentrelay 是节点唯一连接的服务端，维持节点的长连接，终结控制流并与后端 agentserver 交换消息，在节点之间转发连接和任务。

它要解决两个问题：

- 用户的多台设备处于不同内网（家、学校、公司），彼此不能直接访问，也没有稳定的公网地址。
- AI agent（如 Claude Code、Codex）只能操作它所在的机器，用不到其他机器上的工具、登录态和网络位置。

agentd 不是 cloudflared 或 Tailscale 那样的三层组网工具。访问和路由全部基于域名：经 agentd 网络转发的对象只有「带 SNI 的 TLS 连接」「SSH 连接」和「任务」，规则里没有 IP 和 CIDR，唯一出现 IP 的地方是 ingress 内置 DNS 为需要转发的域名分配的 fake-IP。

身份模型照搬 WireGuard：每个节点一对 Ed25519 静态密钥，私钥不离开设备，授权策略引用对端公钥；agentserver 维护公钥到人类可读名字的目录。每个实例因此有两个等价的名字：`agentd://<公钥>` 和 `agentd://<workspace 域名>/<实例名>`（3.1）。节点与 relay 之间跑 Noise_IK 握手（用同一把密钥派生的 X25519 密钥）；agentserver 发给节点的控制消息都带该 workspace 密钥的签名；节点之间不加密，只对每次开流的头部和任务内容签名（为什么同时需要握手与签名见 7.3）。relay 转发前验签，并向控制面查询「这条流该去哪、发起方能不能用目标」，提供侧再验签一次并执行本地策略。组、workspace、agentserver 和每个 relay 各有自己的密钥对；组与 workspace 的密钥由 agentserver 保管，用来给成员签发随请求出示的成员证书（6.8）；workspace 密钥还签发给成员的控制消息和 relay 证书，是成员唯一钉住的信任根。

示例 workspace `home`，控制面域名 `agentsrv.example.com`（下文所有设计都以它为例）：

| 设备 | 节点名 | 角色 | 提供或消费的能力 |
| --- | --- | --- | --- |
| 笔记本 | `laptop` | ingress、submitter | 浏览器的 TLS 流量和 ssh 命令经 ingress 进入网络；AI agent 通过 MCP / CLI 下发任务 |
| 学校宿舍台式机 | `dorm` | egress | 作为出口访问校园网，如 course.ucas.edu.cn，也可作为 SSH 跳板进校园网主机 |
| 家中台式机 | `homepc` | service | 以 `https://nas.home.agentsrv.example.com` 暴露本机 127.0.0.1:8080 的 NAS 网站；以 `homepc.home.agentsrv.example.com:22` 暴露本机 sshd |
| 公司台式机 | `office` | executor | 接收任务，执行 lark-cli 等只在公司机器上可用的工具 |
| 服务器 A | 无（不是节点） | agentserver（控制面，管理平台） | workspace、目录、分组与成员证书、路由表与策略、证书签发、relay 指派；只对 relay 与管理员可达，可以放在内网 |
| 公网服务器 B | 无（不是节点） | agentrelay（数据面） | 节点唯一连接的服务端：维持节点的会话，终结控制流，转发 `tcp` 与 `task` 流，充当 HTTP 服务的 HTTPS 边缘；与控制面分开部署，可多实例，可放在 Cloudflare 后面 |

四条典型链路：

1. 浏览器访问 course.ucas.edu.cn：`laptop` 的 ingress 从 TLS ClientHello 里嗅探出域名，查分流表得知它要交给下一跳而不是直连，签名后在会话上开流交给 relay；ingress 不知道也不需要知道出口是谁。relay 验签后向控制面查询（答案有缓存）：控制面先按路由表选出出口 `dorm`，再用 dorm 的策略预检 laptop；relay 据此把流转给 `dorm`。`dorm` 先验签，再按策略校验发起者、协议与域名，最后在校园网内发起真实连接。TLS 在浏览器和校园网站之间端到端，中间没有人解密；relay 看到的是「laptop 要访问 course.ucas.edu.cn:443，出口是 dorm」和一段 TLS 密文。
2. 浏览器访问 https://nas.home.agentsrv.example.com：ingress 嗅探到工作区服务域名，把连接交给 relay；relay 用控制面下发的 `*.home.agentsrv.example.com` 证书终结 TLS，带上「来自 laptop」的身份，以 HTTP/1.1 经 `homepc` 的会话送到 `homepc`，`homepc` 反向代理到本机 127.0.0.1:8080。浏览器看到权威 CA 签发的合法证书；证书由 agentserver 签发，私钥只在 agentserver 与 relay 的内存里。
3. `ssh homepc.home.agentsrv.example.com`：`~/.ssh/config` 里 `ProxyCommand agentd connect %h %p`，ingress 打开一条 `proto: ssh` 的流并签名，relay 向控制面确认 homepc 的策略接受来自 laptop 的连接后转发，`homepc` 验签、按策略放行后接到本机 22 端口。TUN 模式下不配 ProxyCommand 也可以：内置 DNS 把该域名解析成 fake-IP，连接进来后按映射得到域名。
4. 笔记本上的 AI agent 调用 submitter 暴露的 MCP 工具：任务是一个 Codex 形态的 tool call（`exec_command`），整个 `function_call` 连同目标 `office` 由 `laptop` 签名；relay 验签，向控制面确认 office 的策略接受来自 laptop 的任务后转发；`office` 再验签、校验本地策略后执行，输出由 `office` 签名返回。relay 能看到任务的内容，但不能伪造或篡改任何一方的消息；agentserver 不在数据路径上。

非目标（MVP 明确不做）：

- 不分配虚拟 IP，不经 agentd 网络转发任意 IP 协议或 UDP。TUN 模式下本机的 UDP 原样直通，不黑洞。
- 不转发明文 HTTP，也不转发 TLS 与 SSH 以外的 TCP 协议。
- 不做多人组织管理（用户、组、审批流），MVP 面向单个用户的多台设备，但 agentserver 本身是多租户的。
- 不做移动端。

---

## 2. 评估与决定

结论：原始方案的方向正确，可以按它做。角色划分、workspace 隔离、所有节点主动出站连接中心、按名字寻址，都是对的。v0.1 指出了原方案没有回答的六个问题，v0.2 按反馈逐一定了下来，v0.3 按独立评审补上了机制层面的漏洞，v0.4 按第二轮反馈把身份与加密改成成熟做法、把服务边缘挪到 agentserver 并加入 SSH，v0.6 按第三轮反馈去掉节点间加密、只保留签名，并让 agentserver 在转发前校验授权，v0.7 重做策略模型（来源二选一、分组渲染成公钥策略），v0.11 把控制面与数据面拆成两个分开部署的程序；本节记录决定和仍需注意的风险。

### 2.1 原方案的合理之处

- 角色划分正交且贴合场景。ingress/egress 对应 Tailscale 的 exit node，service 对应 cloudflared tunnel，submitter/executor 是面向 AI agent 的新增能力，三者复用同一套传输。
- workspace 作为租户边界粒度正确。名字在 workspace 内唯一，让寻址和授权都有稳定的锚点。
- 所有节点主动出站连接中心，天然穿过 NAT 和公司、校园网的防火墙，设备上不用开任何端口。
- 只做域名级路由，让系统的每一层都只处理很少几种东西：有 SNI 的 TLS 连接、SSH 连接和任务。

### 2.2 已定的设计决定

| # | 问题 | 决定 |
| --- | --- | --- |
| 1 | TUN 只看得到 IP，怎么拿到域名 | 嗅探优先：先解析 TLS ClientHello 的 SNI，最后才查 fake-IP 映射。内置 DNS 只对工作区服务域名和分流表判为 `via` 的域名返回 fake-IP，其他域名返回真实地址（6.3、6.4） |
| 2 | 任务是什么 | 任务就是 Codex 的 tool call：`function_call` 进，`function_call_output` 出；MVP 实现 Codex 的 `exec_command` 和 `write_stdin`，输出文本格式与 Codex 发给模型的一致（7.6） |
| 3 | 节点的身份是什么 | 一对 Ed25519 静态密钥，像 WireGuard 的 peer。私钥只在本机；agentserver 维护公钥到名字的目录；策略里的「谁」直接写对端公钥或 `*`，没有别名。与 relay、agentserver 的 Noise 握手用同一把密钥派生的 X25519 密钥；节点间认证靠这把密钥对开流头部和任务内容的签名（7.3）。组、workspace、agentserver 也各有一对 Ed25519 密钥，前两者由 agentserver 保管：组密钥签组成员证书，workspace 密钥签 workspace 成员证书、发给成员的控制消息和 relay 证书，是成员唯一钉住的信任根；agentserver 的密钥只用于 relay 会话（6.8、7.3、7.5、8.2） |
| 4 | 中心能不能看到明文 | 节点与 relay 之间跑 Noise_IK，CDN 只见密文；控制流在 relay 终结，relay 读得到控制内容，但 agentserver 发出的消息都有签名、改不了。节点之间不加密：relay 能看到任务的内容和被转发连接的字节（后者是 TLS / SSH 密文），也是 HTTP 服务的 HTTPS 边缘；agentserver 不在数据路径上。两者都不能冒充节点、不能篡改签过名的头部与任务、不能把任务或服务流送到签名绑定之外的节点，因为开流头部和任务由发起方签名、输出由 executor 签名（7.5、8.1、8.4） |
| 5 | 控制面和数据面在哪，节点连谁 | 两个独立程序、分开部署：agentserver 是控制面、管理平台（目录、分组、路由表、策略、证书、relay 指派），只对 relay 可达；agentrelay 是数据面（节点的会话、流转发、HTTP 服务边缘），是节点唯一直接连接的服务端。每个 agentd 只维护一条到被指派 relay 的会话：流 1 是在 relay 终结的控制流，其余是数据流；agentserver 是 relay 的后端，发给节点的消息由它签名、relay 转交。relay 不持有目录、路由表或策略的副本，转发所需的判断按需向控制面查询并缓存答案（4.1、4.3、5.7、5.8） |
| 6 | 路由表长什么样，谁来选出口 | 路由表在 agentserver 上按 workspace 配置，每条是（源：节点、组或 workspace，协议，域名模式，目的节点 / direct / reject），只有域名级，没有 CIDR；域名集合第一期不做。路由表不下发：ingress 只收到去掉目的的分流表（协议、域名 → 直连 / 交给下一跳 / 拒绝），不知道最终目的实例；出口由控制面在 relay 查询时选出（6.5） |
| 7 | 服务用什么名字，HTTPS 证书怎么办 | 每个 agentserver 有自己的域名；workspace 默认用它的子域 `<ws>.<agentserver 域名>`，也可配自定义域名并提供 DNS 凭据；agentserver 用 ACME DNS-01 为每个 workspace 申请一张通配证书并保管私钥，下发给服务该 workspace 的 relay（只存内存），由 relay 的边缘终结 TLS（5.4、5.8、6.2） |
| 8 | 转发哪些协议 | TLS（按 SNI）和 SSH（域名来自代理请求、ProxyCommand 或 fake-IP 映射）。明文 HTTP 不支持（6.3、附录 A） |
| 9 | 谁能用谁 | 提供侧节点执行的策略统一是 (公钥, allow/deny, target)，target 是字面的域名模式加协议、argv 前缀或服务名，节点上没有目标组；显式 deny 优先、其余取 allow 的并集、默认拒绝。策略的权威来源由每个提供侧角色的 `policy_source` 二选一：`local` 用本地配置，`server` 用 agentserver 渲染并经控制通道下发的策略（本地 deny 仍作刹车）。agentserver 上的策略用主体书写（实例、实例组、workspace、已登录用户、public），渲染时主体换成节点、组或 workspace 的公钥，不展开成员；请求方用成员证书证明自己属于组或 workspace。策略是唯一的授权抽象，没有单独的接受名单：relay 转发前向控制面查询预检结果，控制面用目的节点的策略判定（受管节点是它渲染的，自管节点随 `Advertise` 上报生效策略）（5.8、6.6 到 6.8） |
| 10 | 数据面怎么穿过 CDN | transport 可选 WebSocket（默认）、XHTTP、HTTP Upgrade，都是 HTTPS 外观，能穿过 Cloudflare CDN；参考 Xray-core 的实现。不经 agentd 网络转发 UDP（7.2） |
| 11 | 角色名 server | 改叫 service |
| 12 | 权限模型 | agentd 主进程以登录用户身份运行，executor 永远不以 root 执行；TUN 由一个只管网络设备的特权助手 elevator 创建并把文件描述符交给主进程（5.2、8.5） |
| 13 | executor 怎么执行命令 | 不经 shell：解析 `cmd` 为简单命令序列，由 agentd 自己 exec，策略匹配 argv 前缀；完整 shell 只能按策略对特定调用方显式开启（5.6、8.5） |
| 14 | service 怎么转给本地目标 | relay 的边缘终结 TLS 后以 HTTP/1.1 反向代理到节点，节点再反向代理到本地的明文 HTTP 目标（保留原始 Host、加 X-Forwarded-*，不可配）；SSH 目标用 `proto: ssh`；不做非 HTTP 的 TLS 透传（5.4） |
| 15 | 实例叫什么 | 两个等价的名字：`agentd://<公钥>`（身份，base64url 43 字符）和 `agentd://<workspace 域名>/<实例名>`（可变别名，实例名按主机名规则，默认取 hostname）；同 workspace 内可用短名（3.1） |
| 16 | P2P 怎么做 | 节点自选是否加入（`p2p.enabled`，默认关闭），两端都开启才尝试；agentserver 只做会合点（候选地址、打洞邀请），数据面走 QUIC 上的直连会话，Noise、yamux、`Open`、成员证书、策略与中继路径完全相同；授权与路径无关（7.8） |
| 17 | 一台设备跑几个 agentd | 任意多个实例。每个实例属于一个 workspace，有自己的实例目录（`~/.agentd/` 或 `~/.agentd/instances/<名>/`）、密钥、配置、socket 与会话，彼此不感知；TUN、系统 DNS 这类设备级资源同一时刻只能由一个实例持有，其他实例用代理入口（4.5、5.2、9.2） |
| 18 | 一次转发谁做什么 | 三段式：ingress 只判断一条连接是直连还是交给下一跳（relay），不知道最终目的实例；控制面先按路由表或服务表选出目的实例，再用它的策略预检，relay 据此转发；目的实例先验签，再校验发起者、动作与目的地址是否符合策略，最后执行。`Open.to` 永远是下一跳，任务的目标在 `task.executor`（4.3、7.5、8.3） |
| 19 | relay 怎么拿到转发所需的数据 | 不下发快照。relay 按需向控制面查询两件事：这条流该去哪且允不允许、这个 workspace 的服务证书；答案按 TTL 缓存，控制面变更时按 workspace 清除；节点是谁、加入请求也由 relay 问后端。控制面不可达时已缓存的答案继续用、未命中的请求退避重试（5.8） |
| 20 | 节点怎么信任 relay 和控制面 | 节点只钉自己 workspace 的公钥（加入链接里的 `key`，配置里的 `workspace.public_key`），用它验三样东西：relay 证书、发给自己的控制消息、workspace 成员证书。relay 证书按 relay × workspace 签发，节点首次从 relay 的 well-known 端点按 workspace 取得，之后随 `Welcome.relays` 更新。agentserver 自己的密钥节点不需要知道（4.5、8.6） |
| 21 | 控制流在哪终结 | relay 终结控制流，agentserver 是后端。发给节点的控制消息一律由 agentserver 用该 workspace 的密钥签名（`Signed` 信封），节点用钉住的 workspace 公钥验签、核对收件人并按版本号防回放；节点发给后端的消息由 relay 以会话身份转交。备选的「控制流里再套一层到 agentserver 的隧道」不采用（4.3、7.3、7.4） |

### 2.3 仍需注意的风险

| 风险 | 说明 | 应对 |
| --- | --- | --- |
| agentserver 签发并保管服务证书私钥，relay 内存里也有一份 | 任一方被攻破都能冒充或监听该 workspace 的 HTTP 服务 | 控制面的私钥加密存放，主密钥来自环境或 KMS；relay 只在内存持有、不落盘；需要端到端保密的服务用 `proto: ssh` 承载自己的加密 |
| DoH 加 ECH 让公网域名规则被静默绕过 | 开启 DoH 的浏览器会从 HTTPS 记录拿到 ECH 配置并加密 SNI，ingress 只看到公共外层名，规则不命中，流量直连而用户无感 | 内置 DNS 剥离 HTTPS/SVCB 记录；对 Firefox 金丝雀域名返回 NXDOMAIN；TUN 模式下对已知 DoH 端点的 SNI 本地 RST；`agentd status` 统计带 ECH 扩展或公共外层名的连接（6.4） |
| 任务内容对 agentserver 可见 | 节点之间只签名不加密，agentserver 看得到 `function_call` 的参数和输出，被攻破时泄露命令与结果；HTTP 服务的明文同理 | 用户决定 MVP 接受；签名保证它不能伪造或篡改；将来需要时通过协议次版本加节点间加密，不改骨架 |
| `server` 模式下策略由 agentserver 下发 | 它被攻破时可以把受管节点的策略改宽 | 这是节点自己选择的信任；本地 deny 仍然生效，可写入刹车规则；随时可切回 `local`（6.7） |
| CDN 的限制 | Cloudflare 对代理连接有约 100 秒空闲超时、请求体大小上限、回源默认 HTTP/1.1，Bot Fight Mode 会对非浏览器 TLS 指纹出挑战；免费的 Universal SSL 只覆盖一级通配，`nas.home.agentsrv.example.com` 这种两级名字不能走橙云 | 保活 30 秒；WebSocket 为默认 transport，XHTTP packet-up 为回退；关闭 Bot Fight Mode、缓存、压缩和脚本改写；服务域名的公网记录用灰云直指 relay，或后续改单级命名；这些要实测（7.2） |
| 控制面或 relay 不可用 | agentserver 挂了：不能加入、改策略、续发成员证书，控制流上没有新消息，relay 只能转发已缓存过判断的（发起方, 目的）组合，新组合要等它恢复，成员证书约 1 小时后陆续过期；relay 挂了：该 workspace 的控制与数据都中断，直到节点连上别的 relay 或控制面改派 | 分开部署本身就是故障隔离；MVP 每个 workspace 一个 relay，多 relay 与自动改派放后续 |
| TUN 模式的兼容性 | 接管默认路由后所有本机流量进用户态栈；macOS 的 iCloud Private Relay 走 QUIC/MASQUE，被 QUIC 嗅探阻断后的回退行为未知 | UDP 直通；只对命中规则的 QUIC 阻断；Private Relay 列入阶段 2 的兼容测试 |
| 时钟依赖 | Noise_IK 第一条消息和开流签名都靠时间戳防重放：会话握手要求时间戳单调递增，开流签名要求在 5 分钟窗口内 | 与 WireGuard 相同的取舍；启动时检查与 agentserver 的时钟偏差；拒绝时在 `agentd status` 和日志里明示原因 |

---

## 3. 核心概念与术语

| 术语 | 定义 |
| --- | --- |
| agentserver（控制面，管理平台兼后端） | 一个实例服务多个 workspace：目录、分组与组密钥、workspace 密钥与成员证书、路由表、策略、服务注册、域名与证书签发、relay 注册与 relay 证书、P2P 会合、管理 API 与 CLI。节点不连它：它只和 relay 与管理员说话，回答 relay 的查询，用各 workspace 的密钥签名发给节点的控制消息；不在数据路径上。它自己的一对 Ed25519 密钥只用于 relay 会话，节点不需要知道。 |
| agentrelay（relay，数据面与节点接入） | 节点唯一连接的服务端，与 agentserver 分开部署、可多实例：维护节点的会话，终结控制流并在节点与后端之间转交消息，转发 `tcp` 与 `task` 流（本地校验后向后端查询选路与预检结果），充当 HTTP 服务的 HTTPS 边缘，提供 STUN 反射。没有持久状态，也不持有目录、路由表或策略的副本。有自己的域名和一对 Ed25519 密钥，凭 agentserver 签发的 relay 证书被节点认可。 |
| relay 证书 | agentserver 用 workspace 密钥为每个 (relay, workspace) 签的短期证书 {relay 公钥, 名字, 各 transport 的 URL, STUN 地址, workspace, 有效期}。节点只钉自己 workspace 的公钥，凭证书认服务该 workspace 的任何 relay；首次接触从 relay 的 `/.well-known/agentd?workspace=<基础域名>` 取得，之后随 `Welcome.relays` 更新（4.5、8.6）。 |
| relay 缓存 | relay 对后端答案的 TTL 缓存：「这把公钥是谁」「这条流去哪、允不允许」「这个 workspace 的服务证书」。后端变更时按 workspace 清除；后端不可达时已有条目不过期、未命中的请求退避重试。它不是数据副本，relay 不自己做选路或策略判定（5.8）。 |
| workspace | 租户和信任边界：一组互相可见、可互相访问的节点。有唯一名字（如 `home`）和一个基础域名（默认 `home.agentsrv.example.com`）。 |
| node（节点、实例） | 一个运行中的 agentd 实例。身份是一对 Ed25519 静态密钥；有两个等价的名字 `agentd://<公钥>` 和 `agentd://<workspace 域名>/<实例名>`（3.1）。一个实例属于一个 workspace、连接一个 relay；一台设备可以运行多个实例，各有自己的实例目录、密钥与连接，彼此不感知（9.2）。 |
| node key（节点密钥） | 节点的 Ed25519 静态密钥对，形态与 WireGuard 的 peer 密钥相同，公钥以 base64url 显示（43 字符）。用于给开流头部和任务签名；与 relay、agentserver 握手用由它派生的 X25519 密钥。私钥文件 0600，不离开设备。 |
| directory（目录） | agentserver 维护的 workspace 成员表（公钥、名字、角色上限、在线状态）加组列表（组名、组公钥、成员）和 workspace 公钥，推给所有成员；只用于显示和复制公钥，不参与节点的判定。 |
| group key / workspace key（组密钥 / workspace 密钥） | agentserver 为每个组和每个 workspace 保管的 Ed25519 密钥对，用来给成员签发成员证书；公钥可以直接写进策略的 `public_key`。workspace 密钥还签发给成员的控制消息和 relay 证书，其公钥是成员唯一钉住的信任根（`workspace.public_key`）（6.8）。 |
| membership cert（成员证书） | 由组或 workspace 密钥签发给成员的短期证书 {成员, 签发者, workspace, 签发与过期时间}，成员随 `StreamOpen` 出示，接收方据此把签发者公钥算进请求方的身份集合。验证方不需要任何 CA 文件：只要有规则的 `public_key` 是签发者的公钥，自管节点从 `agentd peers` 的输出复制，受管节点由下发的策略直接携带；成员自己的证书由 agentserver 随 `Welcome` 下发并自动续期（6.8）。 |
| direct session（直连会话） | 两个都开启 P2P 的节点在 UDP 打洞后建立的会话，transport 为 `p2p`（QUIC），其上同样是 Noise_IK 与 yamux，只承载数据流，没有控制流（7.8）。 |
| candidate（候选地址） | 节点可能被对端直达的 UDP 地址：本机地址、STUN 反射地址、端口映射地址；只在打洞邀请时交给通过预检的对端（7.8）。 |
| role（角色） | 节点启用的能力。消费侧：ingress、submitter；提供侧：egress、service、executor。一个节点可同时启用多个。 |
| elevator（特权助手） | 与 agentd 同一二进制、以 root 运行的小组件，只负责创建 TUN、配置路由和系统 DNS，并把 TUN 的文件描述符交给用户态的 agentd 主进程。一台设备一个，同一时刻只服务一个实例。 |
| transport（传输） | 一条物理连接的形态，向上提供可靠有序的双向字节流：节点与 relay、relay 与 agentserver 之间是 WebSocket、XHTTP 或 HTTP Upgrade，外观都是 HTTPS；节点与节点之间的直连是预留的 `p2p`（UDP 上的 QUIC，7.8）。 |
| session（会话） | 节点与 relay 之间唯一的一条连接：transport 连接上跑 Noise_IK 加密通道，里面用 yamux 多路复用出流。每个实例只有这一条；控制与数据都在它上面。 |
| control stream（控制流） | 会话里的第一条流，在 relay 终结。节点发出的消息（`Advertise` 等）由 relay 以会话身份转交后端；agentserver 发给节点的消息（`Welcome`、`Update`、`PolicyUpdate`、`Notice` 等）一律带 agentserver 的签名，relay 原样送达。relay 读得到控制内容，伪造不了。 |
| relay session（relay 会话） | relay 到 agentserver 的一条连接（Noise_IK 加 yamux），只有一条流：relay 的查询与节点消息的转交，后端的答案、发给节点的签名消息、缓存失效与证书推送。 |
| stream（流） | 会话内的一条双向字节流，有类型：`control`（每会话一条，在 relay 终结）、`tcp`（承载一条被转发的 TCP 连接，`proto` 为 `tls`、`ssh` 或 `http`）、`task`（一次 tool call）。所有类型共用节点的那一条会话；relay 把两条会话里的流拼接起来。 |
| open signature（开流签名） | 每条 `tcp` / `task` 流的第一帧 `Open` 由发起节点用自己的 Ed25519 密钥签名（任务时含整个 `function_call`）。会话的 Noise 只认证了节点与 relay，提供侧要独立于 relay 确认发起者，靠的就是这个签名：relay 转发前验一次，提供侧再验一次。流上随后的字节不再签名也不在节点间加密，靠两跳（发起方 ⇄ relay、relay ⇄ 提供侧）的 Noise 会话保护。 |
| route table（路由表） | agentserver 上按 workspace 配置的表，每条是（源：节点、组或 workspace，协议，域名模式，目的：某个 egress 节点、`direct` 或 `reject`）。只在 agentserver 上，由它在 relay 查询时选出口；不下发给节点（6.5）。 |
| ingress routes（分流表） | agentserver 按节点从路由表渲染给 ingress 的投影：（协议，域名模式）→ 直连 / 交给下一跳 / 拒绝，不含目的节点；ingress 据此决定一条连接是否交给 relay，不知道出口是谁（6.5）。 |
| domain set（域名集合） | agentserver 上命名的域名模式列表，供路由表和中央策略引用。第一期不做，路由表与策略直接写字面模式；协议里保留位置（6.5）。 |
| service（服务） | service 角色发布的命名目标：服务名、所在节点、协议（`http`、`ssh` 或 `tcp`）、本地目标地址。域名 `<service>.<基础域名>`。 |
| policy（策略） | 唯一的授权抽象，对 `tcp`、`task` 与服务访问一视同仁：(public_key, action, target)，public_key 是一把对端公钥或 `*`（任何人：对 egress、executor 与 ssh 服务就是任何成员，对 HTTP 服务还包括公网访问者），action 是 allow / deny，target 按角色是域名模式加协议、argv 前缀或服务名。提供侧节点执行它；控制面在转发前用同一份策略预检（受管节点是它渲染的，自管节点随 `Advertise` 上报生效策略）。显式 deny 优先，默认拒绝（6.6）。 |
| policy source（策略来源） | 每个提供侧角色的配置 `policy_source`：`local` 用本地文件里该角色的 `policies`，`server` 用 agentserver 渲染下发的策略，本地 deny 仍生效（6.7）。 |
| subject（主体） | agentserver 上书写策略与路由表的主语：`node:`、`group:`、`workspace`、`user:`、`public`；渲染时换成节点、组或 workspace 的公钥，`public` 换成 `*`，人类主体只在边缘生效（6.8）。 |
| task（任务） | 一次 Codex 形态的 tool call，从 submitter 发到某个 executor 并返回输出。 |

workspace 名和服务名与实例名用同一套规则（3.1）。要用 SSH 登录节点本身，就发布一个与节点同名的 `proto: ssh` 服务。

### 3.1 实例的名字：`agentd://` URI

每个 agentd 实例有两个等价的名字，都写成 `agentd://` URI：

| 形式 | 例子 | 性质 |
| --- | --- | --- |
| 密钥形式 | `agentd://0rWkXpu4m9k6cQ1yHdM2bHcV6cnM-dEfqJkT2a8RnXs` | 身份本身。authority 是节点 Ed25519 公钥的 base64url 编码（无填充，恰好 43 字符）。稳定、不可伪造、跨 workspace 全局唯一；换设备或轮换密钥就是换名字 |
| 名字形式 | `agentd://home.agentsrv.example.com/laptop` | 人类可读的别名。authority 是 workspace 的基础域名，path 是实例名。由 agentserver 的目录解析成密钥形式；换设备后同一名字可以指向新的公钥 |

- 实例名遵循主机名的规则（RFC 1123 的 label）：字母、数字和连字符，不以连字符开头或结尾，不区分大小写，统一按小写存储和比较，最长 63 字符。建议不超过 32 字符，因为 MCP 工具名 `<executor>__<tool>` 还要放进客户端的 64 字符上限（5.5）。实例名与服务名共用 workspace 内的名字空间，由 agentserver 保证唯一。加入时令牌没有指定名字的话，默认用设备的 hostname（按上述规则清洗后）。
- 等价关系：两个名字在某一时刻指向同一把公钥，就是同一个实例。密钥形式是主键，名字形式是可变的引用；目录记录名字到公钥的当前绑定和变更历史。线上协议里只传 32 字节公钥，名字形式只在配置、CLI、日志和目录里出现。
- 两种形式靠语法区分：密钥形式的 authority 恰好 43 个 base64url 字符（字母、数字、`-`、`_`），没有 `.`，没有 path；名字形式的 authority 含 `.`，path 恰好一段。选 base64url 而不是 WireGuard 的标准 base64，是因为标准 base64 的 `/` 和 `+` 不能出现在 URI 的 authority 里；配置文件里的公钥（`workspace.public_key`、策略的 `public_key`）用同一种编码。
- 组与 workspace 也有名字形式：`agentd://home.agentsrv.example.com/group/pc` 和 `agentd://home.agentsrv.example.com/`（path 为空）；它们的密钥形式同样是 `agentd://<公钥>`。`group` 因此是保留的实例名。
- 同 workspace 内可以用短名 `laptop` 代替 `agentd://home.agentsrv.example.com/laptop`。配置、CLI 和日志接受三种写法：短名、名字形式、密钥形式。日志同时打印名字和密钥的前 8 个字符，如 `laptop (0rWkXpu4…)`。
- 解析：两个方向都只靠目录（`agentd peers` 显示）；节点的判定不解析名字，策略里只有公钥。两个 workspace 的名字空间互不相关，一个节点只能解析自己 workspace 的名字。
- 用在哪里：策略的 `public_key`（公钥形式或 `*`）；任务的目的地（`agentd task exec office -- …`，MCP 工具名用短名）；流头部的 `from`、下一跳 `to` 与任务的 `executor`（线上是公钥）；加入链接（名字形式加查询参数，4.5）；`agentd key show` 与 `agentd status` 同时显示两个名字。
- 不用 `agentd://` 的东西：服务按协议命名，`https://nas.home.agentsrv.example.com`、`ssh homepc.home.agentsrv.example.com`；agentserver 与 relay 不是 agentd 实例：agentserver 没有节点可见的身份，workspace 用它的公钥表示（`workspace.public_key`，名字形式 `agentd://<ws 域名>/`），relay 用它的 HTTPS URL 与 relay 证书表示（`workspace.relay.url`）。
- 对照：Tailscale 用 `nodekey:<hex>` 加 MagicDNS 名字，WireGuard 的 peer 就是公钥；agentd 把两者都做成可互换的 URI。

---

## 4. 整体架构

### 4.1 两个服务端程序，三个平面

| 平面 | 内容 | 在哪 |
| --- | --- | --- |
| 控制面 | workspace、目录（公钥、名字、角色上限、在线状态）、分组与组密钥、workspace 密钥、成员证书、路由表、策略（中央策略与自管节点上报的生效策略）、服务注册、域名与 DNS 凭据、服务证书、relay 注册与 relay 证书、加入令牌、P2P 会合 | agentserver，持久化到 PostgreSQL。它是后端：只和 relay 与管理员说话，回答 relay 的查询，把发给节点的消息签好名交给 relay 送达 |
| 数据面与节点接入 | 节点的会话；控制流的终结与消息转发；`tcp` 流和 `task` 流的本地校验、向后端查询选路与预检、拼接；HTTP 服务的 TLS 终结与边缘反向代理；STUN | agentrelay 的 hub、control、forwarder、edge，与控制面分开部署，可多实例，只缓存后端的答案与证书 |
| 本地面 | ingress 的监听（TUN / HTTP 代理 / SOCKS5 / `agentd connect`）、内置 DNS、MCP server、CLI 用的 unix socket、elevator | 各 agentd 实例 |

agentserver 是管理平台兼后端：所有状态和所有决策（谁是成员、流该去哪、允不允许、证书、策略渲染）都在它那里，但它不碰任何数据字节，也不接受节点的连接。relay 是节点唯一的服务端：它终结节点的会话和控制流，需要后端决定的事（加入、身份、选路、预检、证书）问后端并缓存答案，agentserver 要发给节点的消息（`Welcome`、`Update`、`PolicyUpdate`、`Notice` 等）一律带 agentserver 的签名、由 relay 转交，所以 relay 读得到控制内容但伪造不了。对经它转发的流，relay 读得到带签名的头部（类型、协议、域名、端口、来源、下一跳，任务还包括目标 executor 与整个 `function_call`）和之后的字节；`tcp` 流的字节是 TLS 或 SSH 密文，`task` 流的字节是明文。它也能看到 HTTP 服务的明文，因为它就是这些服务的 HTTPS 边缘（8.4）。

### 4.2 拓扑

```
                 +----------------------------------------------+
                 |  agentserver                                 |   控制面，管理平台兼后端
                 |  directory / routes / policy / certs / admin |   只对 relay 与管理员可达
                 +----------------------+-----------------------+
                                        |  relay 会话：查询 ↑ 答案 ↓
                                        |  节点消息 ↑  签名的节点消息、失效、证书 ↓
                 +----------------------+-----------------------+
                 |  agentrelay (relay-hk)                       |   数据面与节点接入，可多实例
                 |  hub / control / forwarder / edge / stun     |   节点唯一连接的服务端
                 +--+-------------+--------------+-----------+--+
  每节点一条会话    |             |              |           |
  WS/XHTTP/Upgrade  |             |              |           |
        +-----------+             +---+          +---+       +------------------+
        |                             |              |                          |
 +------+----------+      +-----------+---+  +-------+--------+    +------------+----+
 | laptop          |      | dorm          |  | homepc         |    | office          |
 | ingress         |      | egress        |  | service        |    | executor        |
 | submitter       |      | tls+ssh:campus|  | nas -> :8080   |    | exec_command    |
 +-----------------+      +---------------+  | homepc -> :22  |    +-----------------+
                                             +----------------+
```

每个节点只有图中这一条会话，控制消息走会话里的第一条流，在 relay 终结。Cloudflare 可选地代理 relay 的域名；agentserver 可以放在内网，只要 relay 连得上它。策略里对 `*` 开放的服务，其公网访问直接到 relay 的 edge（`*.home.agentsrv.example.com:443`），不经任何节点。开启 P2P 的两个节点之间还可能有一条直连会话（7.8），只承载数据流。

### 4.3 连接模型：一条会话，控制流加数据流

每个 agentd 实例维护一条到 relay 的会话。一条物理连接（比如一条 WebSocket）上依次叠三层：

1. transport 把 WebSocket 消息、XHTTP 的上下行请求或 HTTP Upgrade 之后的裸连接抽象成一条可靠有序的双向字节流。
2. 会话层在这条字节流上跑 Noise_IK 握手（节点密钥 ⇄ relay 密钥，relay 密钥由 workspace 密钥签发的 relay 证书背书），之后所有数据都是 Noise transport 消息（ChaCha20-Poly1305，每条不超过 65535 字节）。CDN 终结了外层 TLS，所以内层必须自己加密。首次加入时加入令牌就在握手的载荷里，relay 转给后端校验。
3. 多路复用层（yamux）在解密后的字节流上开流。两侧都可以开流：节点向 relay 开流发起请求，relay 向提供侧节点开流送达请求。每条流有独立的流控窗口，支持半关闭和 RESET。

会话里的流分两类：

| 流 | 谁开 | 内容 | relay 的角色 |
| --- | --- | --- | --- |
| 控制流（流 1，每会话一条） | 节点 | `Welcome`、`Update`、`Advertise`、策略下发、成员证书、P2P 信令 | 终点：节点发来的消息转给后端，后端发给节点的消息（已签名）转交节点；在线状态由它掌握并报告给后端 |
| 数据流（`tcp`、`task`） | 节点或 relay | 一条被转发的 TCP 连接，或一次 tool call；第一帧是发起节点签名的 `Open` | 终点与拼接点：本地校验，向后端查询选路与预检结果，再向目的节点开一条对应的流并对拷 |

谁签什么：节点签自己开的流和任务输出；agentserver 用该 workspace 的密钥签所有发给节点的控制消息（信封 `Signed`，上下文 `agentd/control/v1`，带收件节点与时间），节点用加入链接里钉住的 workspace 公钥验签。节点发给后端的消息（`Advertise`、`PolicyApplied` 等）不签，由 relay 以会话身份转交，relay 对后端证明它们来自谁。这样 relay 可以终结控制流、做一切节点接入的事，却不能冒充 agentserver 改策略、改目录或编造证书；它能看到控制内容（含加入令牌），这是把它作为唯一接入点的代价（8.1）。

为什么是一条连接而不是每条被转发的 TCP 连接各开一条：提供侧节点在 NAT 后面，relay 只能通过它已经建好的连接送达请求，所以多路复用无论如何都要有；经 CDN 时每条新连接要多付一次 TLS 加 WebSocket 握手（上百毫秒），CDN 对并发连接也有限制。代价是单条 TCP 连接的队头阻塞：丢包会让会话上所有流一起等待重传。吞吐或延迟不够时可配置多条会话并把流分散到各会话上（Xray 的 XHTTP 用 `xmux` 做同样的事），MVP 先做一条。

为什么控制面和数据面分开部署、节点却只连 relay：数据面是带宽与连接数的瓶颈，要靠近用户、可以多实例；控制面是小而关键的状态，应该少暴露。节点只连 relay 让 agentserver 完全不必对节点可达，也让节点侧只有一个要维护的连接。relay 不复制控制面的数据：转发所需的判断按需向后端查询并缓存答案（5.8），agentserver 故障时已缓存的判断继续有效，新节点、新的连接组合和控制消息要等它恢复。

流的拼接按三段式进行：ingress 只判断，后端选路加预检，目的节点验签加策略加执行。

1. ingress 查分流表，判定这条连接要交给下一跳；在会话上开一条 `tcp` 流，第一帧是带签名的 `Open` 头部（类型、协议、域名、端口、发起方、下一跳 `to` = relay、时间戳、随机数，签名用发起方的 Ed25519 密钥）和发起方持有的成员证书，紧跟着可以直接发首段数据，不必等 Ack。头部里没有出口节点，ingress 不知道它。
2. relay 先做本地校验：签名有效、`from` 就是这条会话的节点、`to` 是自己、时间戳在窗口内、随机数未见过。然后向后端查询这条流（发起方、种类、协议、域名、端口，任务则是 `task.executor`），答案按 TTL 缓存：后端先按路由表或服务表选出目的节点（选不出即 `NO_RULE`），再查双方角色，再用目的节点的策略预检发起方（受管节点用中央策略，自管节点用它上报的生效策略）。最后 relay 确认目的节点的会话在自己这里在线，向它开一条对应的流，把 `Open` 与证书原样转过去。任一项失败时 relay 立即回带错误码的 Ack，不去打扰目的节点。
3. 目的节点先验签，再校验发起者、动作（协议、域名、端口或 argv）是否符合策略，最后执行并回 Ack，之后 relay 把两条流的字节对拷。

一条 TLS 连接的生命周期（浏览器访问 course.ucas.edu.cn）：

1. 浏览器查询 DNS。TUN 把发往任何地址 53 端口（UDP 和 TCP）的查询交给 ingress 内置 DNS；该域名在分流表里是「交给下一跳」，DNS 返回一个 fake-IP，同时剥离 HTTPS/SVCB 记录。
2. 浏览器连接该地址的 443 端口，进入 TUN。ingress 在 200 毫秒预算内读取首段数据，累积到完整的 ClientHello record，解析得到 SNI `course.ucas.edu.cn`，与 fake-IP 映射一致。
3. 分流表判定该域名交给下一跳。ingress 构造并签名 `Open`（`proto: tls`、域名、端口、`from: laptop`、`to: relay`、时间戳、随机数），附上成员证书，在会话上开 `tcp` 流，紧接着把已缓存的 ClientHello 发出。头部里没有出口节点。
4. relay 验签并确认 `to` 是自己；向后端查询（答案缓存 60 秒）：后端按路由表选出出口 `dorm`，确认 laptop 有 ingress 角色、dorm 有 egress 角色，用 dorm 的策略预检 laptop；relay 确认 `dorm` 的会话在线，在它上面开流，转发 `Open` 和随后的字节。
5. `dorm` 验签，`from` 或它出示的有效成员证书的签发者必须等于某条规则的 `public_key`（或有 `*` 规则），`to` 必须是自己所连的 relay；按策略 (laptop, allow, tls, suffix:ucas.edu.cn 等) 校验发起者、协议、域名与端口后放行；用本机解析器解析域名并拨号 443；回 Ack。期间到达的首段数据放在有界缓冲里（16 KiB），策略拒绝则连同流一起丢弃。
6. `dorm` 重新解析 ClientHello，SNI 必须与头部域名一致，否则 RESET；之后双向透传。任一方向关闭传递为半关闭，异常传递为 RESET。

分流表判定直连时，第 3 步改为直接拨号浏览器原本连接的 IP 和端口，回放已读字节，不经 agentd 网络。

### 4.4 关键取舍

| 取舍 | 选择 | 理由 |
| --- | --- | --- |
| 嗅探优先 vs fake-IP 优先 | 嗅探优先，fake-IP 只给服务域名和分流表判为 `via` 的域名 | 其他域名保持真实解析，程序看到真实 IP；服务域名和校园网内网域名在本地解析不到或不应直连，fake-IP 无法避免；SSH 没有 SNI，只能靠映射 |
| 转发哪些协议 | TLS 和 SSH | 域名来自 SNI 或映射，两者都带自己的加密；明文 HTTP 既没有端到端保密也没有太多需求，不做 |
| 身份用密钥对还是用户名密码 / 令牌 | Ed25519 静态密钥对 | 与 WireGuard、Tailscale 相同的「公钥即身份」；策略直接引用公钥，agentserver 只是目录；没有需要轮换和保护的长期 bearer 凭据 |
| 会话用签名挑战还是 Noise 握手 | Noise_IK 握手，静态密钥由身份密钥派生 | 把认证、前向保密、加密一次做完，CDN 只见密文；有成熟实现和分析。先例：Tailscale 的控制协议 ts2021 是 Noise_IK 跑在 HTTP Upgrade 连接里。为什么同时还要签名见 7.3 |
| 节点之间：签名还是再加一层 Noise | 只签名，不加密 | 用户的决定：目前只需要来源不可伪造，不需要对 relay 隐藏内容。签名覆盖开流头部与整个任务请求，输出由 executor 签名，relay 不能冒充、篡改或把任务送错；省掉每条流一次握手和双重加密。签名用 Ed25519ctx 带上下文字符串，对「发出去的字节」签名、对「收到的字节」验签，不需要规范化编码；时间戳加随机数防重放。将来需要隐藏内容再通过协议次版本加端到端加密 |
| 节点连谁，控制流在哪终结 | 只连 relay；控制流在 relay 终结，agentserver 是后端 | 节点侧一个连接；agentserver 不必对节点可达，可以放在内网，只和少数 relay 打交道；relay 是唯一接入点，顺手掌握在线状态。代价是 relay 看得到控制内容（含加入令牌），用 workspace 密钥签名所有发给节点的控制消息保证它不能冒充控制面。备选是在控制流里再套一层到 agentserver 的 Noise 隧道，对 relay 完全不透明，但 agentserver 要参与每个节点的会话，与「agentserver 只是管理平台」相悖，不采用 |
| 授权只在提供侧还是服务端也查 | 两层都查，用同一份策略 | 后端在转发前用目的节点的策略预检（受管节点是它渲染的，自管节点随 `Advertise` 上报），不合格的请求到不了提供侧；argv 这类细节只有提供侧知道。两层都默认拒绝，自管节点在 agentserver 被攻破时仍能自保。没有单独的「接受名单」，策略是唯一的授权抽象 |
| 策略写在节点上还是写在 agentserver 上 | 节点二选一 | 单用户几台设备时本地文件最直接；设备多或要用分组时交给 agentserver 渲染下发。两种来源执行的是同一种形态，切换不改执行代码；`server` 模式留本地 deny 作刹车 |
| 成员关系怎么到达判定点 | 成员证书随请求携带 | 备选是把成员图推给节点（状态复制、拿着旧图的窗口）或由中继附签（授权绑死在中继路径，P2P 无法用）；证书签给成员、由成员出示，中继与直连一致（6.8、7.8） |
| 控制面与数据面同进程 vs 分开部署 | 分开部署 | 数据面是带宽与连接数的瓶颈，要就近、可多实例；控制面是小而关键的状态。分开后数据面独立扩容，控制面可以只对 relay 可达；代价是 relay 的每个新判断要问一次后端 |
| relay 持快照还是按需查询 | 按需查询，答案按 TTL 缓存 | 不把目录、路由表与策略复制到 relay，不维护版本化快照与增量，选路与策略判定只有 agentserver 一处实现；代价是后端在新连接组合的路径上，不可达时只有已缓存的组合能继续 |
| 服务证书在节点还是在服务端 | 在 agentserver 签发，下发到 relay 内存 | 服务要用真实域名和权威 CA 证书，域名和 DNS 凭据本来就在 agentserver；一个 workspace 一张通配证书，服务注册即就绪；节点上不再保存公网域名的私钥 |
| 路由表在中心 vs 在 ingress，出口谁选 | 在 agentserver；ingress 只收去掉目的节点的分流表，出口由后端在 relay 查询时选出 | 一处配置，所有消费侧设备生效；ingress 只需要知道「直连还是交给下一跳」，换出口、加出口都不动消费侧；`Open.to` 只写下一跳，提供侧仍用自己的策略把关 |
| 一条物理连接多路复用 vs 每连接一条 | 一条连接 + yamux | 见 4.3 |
| WebSocket vs XHTTP 作为默认 transport | WebSocket | XHTTP packet-up 的上行是分片 POST，而提供侧节点回传给用户的下载数据正走这个方向，吞吐和重排抖动会压住该节点的所有流；XHTTP 留作 WebSocket 被阻断时的回退 |
| executor 经 shell 执行 vs 自己 exec | 自己 exec | 策略要匹配的 argv 和实际执行的命令必须是同一个东西；经 shell 则解析器与解释器不一致本身就是绕过 |
| 单进程 root vs 特权拆分 | elevator + 用户态主进程 | TUN 要 root，而 executor 必须以登录用户身份跑才看得到 lark-cli 的登录态，且绝不能以 root 执行远程命令 |

### 4.5 实例的接入流程

接入（join）把一个实例新生成的密钥登记进某个 workspace 的目录，并给它一个名字形式的名字。整个流程只依赖一个一次性令牌和 workspace 的公钥，没有账号密码，也没有长期 bearer 凭据。

```
管理员   ── agentserver token create ───────────────────────────────▶ agentserver
管理员   ◀── 加入链接 agentd://home.agentsrv.example.com/dorm?relay=…&key=…&token=… ── agentserver
管理员   ······ 带外交给设备（聊天工具、复制粘贴、二维码）······▶ 设备
实例     ── GET https://relay-hk…/.well-known/agentd?workspace=home.… ─▶ relay      （取该 workspace 的 relay 证书，用 key 验签）
实例     ── transport 连接 + Noise_IK 消息 1 {版本区间, 时间戳, 身份公钥, 令牌, 建议名字} ─▶ relay
                                                                    relay ── 加入请求 ──▶ agentserver
                                                                    校验令牌、名字、公钥；登记目录；令牌作废
                                                                    relay ◀── 节点信息 + 签名的 Welcome ── agentserver
实例     ◀── Noise_IK 消息 2 {版本, 会话 ID, joined, 两个名字, 角色上限} ─ relay
实例     ── 流 1：控制流 ──────────────────────────────────────────▶ relay
实例     ◀── Welcome（workspace 密钥签名：分流表、服务表、目录、executor 清单、relay 列表与指派）── relay
实例     ── Advertise（本机服务、executor 工具、自管时的生效策略）─▶ relay ── 转交 ──▶ agentserver
其他成员 ◀── Update（workspace 密钥签名：新成员的名字与公钥、在线）── relay ◀── agentserver
```

步骤：

1. 前提：agentserver 已有自己的 Ed25519 密钥对（只用于 relay 会话），至少注册了一个 relay，workspace `home` 已创建（有自己的密钥对、基础域名和通配证书）并指派给某个 relay，agentserver 用 `home` 的密钥给该 relay 签了 relay 证书。
2. 管理员签发令牌：`agentserver token create --workspace home --name dorm --roles egress --ttl 24h`。agentserver 检查 `dorm` 符合实例名规则且在 `home` 内未被任何节点或服务占用，生成 128 位随机令牌，只保存它的 SHA-256，绑定 (workspace, 名字, 角色上限, 过期时间)，输出加入链接：

   ```
   agentd://home.agentsrv.example.com/dorm?relay=https://relay-hk.agentsrv.example.com&key=<workspace 公钥>&token=<令牌>
   ```

   链接就是新实例的名字形式加三个参数：`relay` 是被指派 relay 的 transport 端点，`key` 是 workspace 的公钥（base64url，成员唯一的信任根：认 relay 证书、验所有控制消息和 workspace 成员证书的签名），`token` 是令牌。`--name` 可以省略，此时链接的 path 为空，名字在加入时由实例提出。链接是秘密，但 `agentd://` 不是浏览器会发到网上的协议，误贴进浏览器不会泄露给任何服务端或 CDN 日志。
3. 设备上安装 agentd，执行 `agentd join '<链接>'`（链接也可从标准输入读，避免进 shell 历史；要在同一台设备上加入第二个 workspace，就用 `agentd -i <实例名> join …` 起一个新实例，9.2）。若实例目录下的 `node.key` 不存在则生成 Ed25519 密钥对；若该实例已属于某个 workspace 则拒绝，除非加 `--replace`（先执行 `agentd leave`）；把 `workspace.public_key`、`workspace.relay.url`、`workspace.domain`、`metadata.name` 写入配置。令牌没有指定名字时用 `--name`，否则用清洗过的 hostname。
4. 认 relay：实例请求 `https://<relay>/.well-known/agentd?workspace=<基础域名>`，得到该 workspace 的 relay 证书 {relay 公钥, 名字, URL, STUN, workspace, 有效期}，用链接里的 `key`（workspace 公钥）验签。通过后建 transport 连接，以 relay 公钥派生的 X25519 公钥作为响应方静态公钥发 Noise_IK 消息 1，载荷是 {会话种类, 版本区间, 时间戳, 身份公钥, 令牌, 建议名字, workspace}。
5. 加入：relay 完成握手，校验身份公钥的派生结果等于握手静态公钥（握手本身因此证明了身份私钥的持有），把加入请求（身份公钥、令牌、建议名字、workspace）转给后端。agentserver 依次校验：令牌哈希存在、未使用、未过期、所属 workspace 与链接的 authority 一致；该公钥尚未在任何 workspace 的目录中（一把密钥只属于一个实例）；名字仍未被占用；该 workspace 指派给了这个 relay。全部通过则写入目录 (workspace, 名字, 公钥, 角色上限, 加入时间)，令牌作废，把节点信息（workspace、名字、角色上限）和签好名的 `Welcome` 交给 relay。relay 发消息 2，载荷为 {协商版本, 会话 ID, 结果 joined, 两个名字, 角色上限}，从此接受它的数据流。任一项失败则消息 2 带错误码后断开：令牌无效、令牌已使用、令牌过期、名字已占用、公钥已属于其他实例、版本不兼容、时间戳过旧、relay 不对（附带正确的 relay 证书，实例换 relay 重来）、后端不可达。
6. 实例开控制流（流 1），relay 回 Ack 并送达 `Welcome`；实例验签（workspace 公钥、收件人是自己、时间在窗口内）后发 `Advertise`（只能声明角色上限内的角色；自管的提供侧节点附上生效策略），relay 转给后端，后端经 relay 向 workspace 其他成员推签名的 `Update`。设备上 `agentd status` 显示「已加入」、两个名字和所连的 relay。
7. 之后每次连接：握手不带令牌；relay 向后端查这把公钥是谁（答案缓存），已知则建会话、放行数据流并送达新的 `Welcome`；未知（已被移除）则消息 2 回 `not-a-member` 并断开，实例停止重连并提示重新 join。后端不可达时 relay 对未缓存的公钥回 `control-not-ready`，实例退避重试。relay 的证书过期或验签失败时实例不连它，换 `Welcome.relays` 里的下一个；控制消息验签失败说明 relay 或链路有问题，实例丢弃该消息并告警。
8. 其他成员视角：收到 `Update` 后 `agentd peers` 能看到 `dorm  agentd://<公钥>`；要对它授权的提供侧节点把这把公钥写进自己规则的 `public_key`（受管节点由中央策略渲染）。

生命周期操作：

| 操作 | 命令 | 效果 |
| --- | --- | --- |
| 改名 | `agentserver node rename --workspace home dorm dorm2` | 目录更新并推送；其他节点的规则不受影响，因为规则里写的是公钥 |
| 调整角色上限 | `agentserver node set-roles --workspace home dorm egress,executor` | 目录更新，relay 的缓存失效并重新查询；超出上限的 `Advertise` 与开流立即被拒 |
| 吊销 | `agentserver node remove --workspace home dorm` | 通知 relay 关闭其会话，目录推送移除；其他节点规则里写的旧公钥仍在，但目录里查不到，`agentd status` 对这类规则告警 |
| 换设备或轮换密钥 | `node remove` 后重新 `token create --name dorm` 并在新设备 join | 新公钥、同名字；其他节点规则里写的旧公钥不再匹配，要改规则。换了设备必须重新信任，这是有意的 |
| 节点主动退出 | `agentd leave` | 经 relay 通知 agentserver 移除自己，删除本地 workspace 配置，保留密钥文件 |
| 令牌管理 | `agentserver token list \| revoke --workspace home` | 查看未用令牌，提前作废 |
| 换 relay | `agentserver workspace set-relay home relay-sg` | 签名的 `Update.assigned_relay` 推给成员，成员关闭当前会话、连新 relay；旧 relay 收到失效通知 |

失败与边界：

- 令牌出现在加入链接、Noise 消息 1 的加密载荷和 relay 转给后端的加入请求里，CDN 和任何中间人都看不到，relay 看得到；服务端只存哈希，状态库泄露也不能用它加入。
- 链接里带 workspace 公钥，首次接触就能认证 relay（凭 workspace 密钥签的证书）并验所有控制消息，不依赖「首次使用即信任」。若链接没带 `key`，`agentd join` 从 relay 的 `/.well-known/agentd?workspace=…` 取该 workspace 的 relay 证书里的签发者公钥并要求用户确认指纹（WebPKI 保护，弱于带外）。
- 设备时钟比服务端慢太多时，时间戳会被拒；错误信息指向校时。
- 同一链接第二次使用、或两台设备抢同一个令牌，后到者失败，名字不会被两把公钥共享。
- 一个实例只属于一个 workspace，一把密钥只属于一个实例；同一台设备加入第二个 workspace 就再起一个实例（`agentd -i work join …`），各有独立的实例目录、密钥、socket 与会话。同一设备上多个实例的默认名都是 hostname，加入同一个 workspace 时第二个必须 `--name`。TUN 与系统 DNS 同一时刻只能由一个实例持有（5.2、9.2）。

---

## 5. 角色设计

### 5.1 角色分类

| 类别 | 角色 | 向谁负责 | 授权方向 |
| --- | --- | --- | --- |
| 消费侧 | ingress、submitter | 本机的应用和 AI agent | 发起流，用自己的节点密钥给 `Open` 头部和任务签名；ingress 只判断直连还是交给下一跳 |
| 提供侧 | egress、service、executor | workspace 内其他节点 | 验签得到对端身份后，用生效策略（本地或 agentserver 下发，6.7）决定谁能用我、能用到什么程度；自管时把生效策略随 `Advertise` 上报，供控制面预检 |
| 控制面 | agentserver（独立程序，管理平台） | 整个实例上的所有 workspace | 目录、分组与成员证书、路由表、策略渲染与预检、证书签发、relay 指派；作为 relay 的后端回答查询、签名发给节点的消息，不在数据路径上 |
| 数据面 | agentrelay（独立程序，可多实例） | 被指派的 workspace | 节点唯一连接的服务端：终结控制流、在节点与后端间转交消息；转发前本地验签，再向控制面查询选路与预检结果（控制面先选目的节点，再查角色，再用目的节点的策略预检），答案缓存；HTTP 服务的边缘；argv 级的细粒度授权留给提供侧（HTTP 服务除外） |

### 5.2 ingress

职责：把本机的 TLS 和 SSH 连接变成 `tcp` 流，并决定哪些交给下一跳（relay）、哪些直连。转给哪个出口不是 ingress 的事，由控制面按路由表选。

入口四种，共用一个 dispatcher：

- HTTP 代理：CONNECT。请求自带域名，仍对首段数据嗅探以确认协议与 SNI。
- SOCKS5：CONNECT。同上。不支持 UDP ASSOCIATE。`ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:7891 %h %p'` 可用，但推荐下一种。
- `agentd connect <host> <port>`：CLI 经 unix socket 让守护进程开一条流，把标准输入输出接上去。这是 ssh `ProxyCommand` 的推荐用法，不需要 TUN，域名直接来自命令行。
- TUN：由 elevator 创建设备、接管默认路由和系统 DNS，把文件描述符交给用户态主进程；主进程用 gVisor netstack 把 IP 包还原成连接。

TUN 模式的具体行为：

- TCP：进入嗅探。首段数据的读取总预算 200 毫秒、上限 16 KiB；ClientHello 可能跨多个 TCP 段（Chrome 启用 ML-KEM 后 ClientHello 超过一个 MSS），要按 record 长度累积到完整的 TLS record；超时或都不匹配即按 6.3 处理。目的地不在 fake-IP 池、而端口在 `sniffing.skip_ports` 里（默认 22、25、110、143、3306）的连接跳过嗅探直接直连：SMTP、POP3、IMAP、MySQL 是服务端先说话，嗅探只会白等一次超时；SSH 的字节里没有域名，到真实 IP 的 SSH 不论嗅不嗅探都只能直连。PostgreSQL 这类客户端先说话但不是 TLS 的协议不用进列表，嗅探会立即失败并直连。其他端口上到真实 IP 的连接仍然嗅探，因为 DoH、应用自带解析器、hosts 文件或 `fake_ip.mode: services` 都会让 `via` 域名拿到真实 IP，只有 SNI 能把它们认出来。
- UDP 53：交给内置 DNS。
- UDP 443：解析 QUIC Initial 包里的 SNI（参考 Xray-core `common/protocol/quic/sniff.go`），命中转发规则或服务域名的丢弃，让浏览器回退 TCP；其他原样直通。
- 其他 UDP：原样直通到原始目的地（netstack 的 UDP forwarder），不黑洞。NTP、VoIP、游戏、其他 VPN 的共存不受影响。
- 目的地在 fake-IP 池里的连接：映射给出域名；TLS 的 SNI 必须等于该域名，否则 RST；首字节为 `SSH-` 或目的端口为 22 的按 SSH 处理；80 端口回 301；其他 RST，不去拨一个不存在的地址（6.3）。
- 自身流量绕过 TUN：到 agentserver 与 relay 的 transport 连接、内置 DNS 到上游的查询、egress 的拨号都绑定物理接口（macOS `IP_BOUND_IF`，Linux `SO_BINDTODEVICE` 或 fwmark + 策略路由）。
- 系统 DNS 的接管与恢复是独立工作项：macOS 用 `scutil` 写 DNS 配置，Linux 兼容 systemd-resolved 和 resolvconf；elevator 在退出、崩溃和网络切换时负责恢复。
- TUN、系统 DNS 接管与 53 端口重定向是设备级资源：同一台设备同一时刻只能有一个实例开启 `tun`，elevator 只服务这一个实例，第二个实例请求 TUN 时被拒并告警；其他实例用代理入口（各自的端口）和 `agentd -i <实例名> connect`。TUN 实例只认识自己 workspace 的分流表和服务域名，其他实例的域名在它看来是直连（第 10 节第 13 条）。

判定依据：agentserver 推送的分流表（协议、域名模式到「交给下一跳 / 直连 / 拒绝」，按本节点渲染、不含目的节点）和服务列表（服务域名一律交给下一跳）。ingress 把 `to` 写成所连 relay 的公钥并签名，出口由控制面在 relay 查询时按路由表选出；ingress 从 Ack 的 `responder` 得知这条连接最终由谁服务，只用于日志和 P2P 的流放置（7.8）。

其他：

- 服务域名的 80 端口：ingress 本地回复 301 跳转到 https。
- 每条连接的决策（域名来源、协议、分流表的判定、实际服务它的节点、动作、耗时）写结构化日志，`agentd status` 显示最近的直连原因统计，包括「带 ECH 扩展」和「SNI 为公共外层名」的计数。

### 5.3 egress

职责：替 workspace 内的节点发起 TLS 和 SSH 连接。

- 接受 `tcp` 流。先验签：`Open` 的签名必须对得上 `from` 的公钥，`to` 必须是送来这条流的会话对端（经中继时是自己所连的 relay，直连时是自己），时间戳在窗口内且随机数未见过；`from` 或它出示的有效成员证书的签发者必须等于某条规则的 `public_key`（或有 `*` 规则），否则回 Ack 错误。然后用策略校验发起者、协议、域名与端口，最后才拨号。
- 策略 (谁, 允许/拒绝, 协议, 域名模式或域名集合[, 端口列表])，显式 deny 优先、其余取 allow 的并集、默认拒绝（6.6）；`谁` 是公钥（节点、组或 workspace 的）或 `*`，没有别名；`proto` 是单个协议，默认 `tls`，同一组域名要同时放行 tls 和 ssh 就写两条；端口默认 tls 为 443、ssh 为 22。target 一律是字面的域名模式列表，节点上没有域名集合；agentserver 的中央策略可以引用它自己的域名集合，渲染时展开成字面模式再下发（6.7、6.8）。
- 上报：自管（`policy_source: local`）时把生效策略随 `Advertise` 上报，控制面据此在转发前预检；生效策略仍然在本地逐条判定。
- 策略通过后用本机解析器解析域名（校园网内解析），拨号头部指定的端口，回 Ack。
- 协议复核：`tls` 重新解析 ClientHello，SNI 必须与头部域名一致；`ssh` 客户端的首行必须以 `SSH-` 开头（服务端先说话的旧客户端会先收到服务端 banner 再发，所以复核在客户端首字节到达时做，不阻塞服务端方向）。不符即 RESET，防止 ingress 伪报域名或协议绕过策略。
- 结构化错误：验签失败、对端未知、重放、策略拒绝、协议不匹配、端口不允许、解析失败、连接被拒、超时。

### 5.4 service

职责：以一个真实域名暴露一个本地目标。HTTP 服务的 TLS 由 relay 用控制面签发的权威 CA 证书终结；SSH 服务由节点自己承担。只有这两种，不做非 HTTP 的 TLS 透传。

```yaml
service:
  enabled: true
  servers:
    - name: nas
      target: { host: 127.0.0.1, port: 8080 }     # 默认 proto: http，反向代理
    - name: homepc
      proto: ssh
      target: { host: 127.0.0.1, port: 22 }       # ssh homepc.home.agentsrv.example.com，节点验签后按策略放行
    # - name: router
    #   target: { host: 192.168.1.1, port: 80 }     # 目标只能是明文 HTTP；https 的内网目标不支持
    # - name: grafana
    #   target: { host: 127.0.0.1, port: 3000 }
  policy_source: local                    # local | server；server 时下面的 allow 被忽略、deny 仍生效
  policies:                               # 谁能访问哪个服务。public_key 是一把公钥或 "*"（任何人：HTTP 服务含公网访问者，由 relay 的边缘执行）
    - { public_key: "hC3Qm…", action: allow, service: nas }      # laptop 的公钥
    - { public_key: "hC3Qm…", action: allow, service: homepc }
    # - { public_key: "*",     action: allow, service: grafana }  # 公网可直接访问，由应用自己做登录
```

HTTP 服务（`proto: http`，默认）：

- 节点连上 agentserver 时在 `Advertise` 里注册服务；agentserver 分配域名 `nas.home.agentsrv.example.com`（或 workspace 自定义基础域名下的 `nas.<自定义域名>`）。workspace 的通配证书已存在时服务立即 `ready`；刚创建 workspace 或刚绑定自定义域名时处于 `cert_pending`，期间对该域名的连接回错误码 `service-not-ready`。
- 边缘在 relay：公网 443 端口和经 ingress 送来的 `tcp/tls` 流进入同一个 TLS 监听逻辑，按 SNI 选 workspace 与服务，用控制面下发的该 workspace 证书终结 TLS。访问控制只有策略：服务节点 `service` 规则的 `public_key` 是成员公钥时，只接受经成员 ingress 送来、身份命中的连接；有 `public_key: "*"` 的 allow 规则时任何人都能访问，公网直连也接受；没有 `*` 规则的服务，公网直连得到一个说明页。判定由控制面按该服务节点的策略做出（relay 查询时给出，答案缓存），relay 的边缘执行，成员身份来自送流会话的节点公钥。
- relay 用 Go `httputil.ReverseProxy` 把请求以 HTTP/1.1 送到节点：浏览器侧可协商 h2，节点侧 HTTP/1.1；加 `X-Forwarded-For`、`X-Forwarded-Proto: https`、`X-Forwarded-Host`；来源是成员时加 `X-Agentd-Peer: laptop` 和 `X-Agentd-Peer-Key: <公钥>`，公网来源的同名头一律剥离。这给了服务一个免登录的身份信号，类似 Cloudflare Access 的做法。
- 节点收到 relay 开的 `tcp/http` 流（`from` 是 `Welcome.relays` 里的 relay 公钥）后再做一层 HTTP/1.1 反向代理到 `target`：目标只能是明文 HTTP，保留原始 Host 并加 X-Forwarded-*，没有可配项；WebSocket 升级两层都原样转发。这是 Synology、Home Assistant、Nextcloud、Grafana 一类 Web UI 能正常工作的最低要求。
- 端口语义：到服务域名的 `tcp/tls` 流只接受 443；其他端口回 Ack 错误。

SSH 服务（`proto: ssh`）：

- 没有证书，也不经公网 443；只能经成员 ingress 访问（ProxyCommand 或 TUN + fake-IP）。
- relay 向控制面查询：按域名查服务表得到节点、用该节点的策略预检发起方；通过后转发。节点验签、再按策略判定一次，然后按字节接到 `target`。relay 经手的是 SSH 密文。
- 用它登录节点本身时服务名直接用节点名。

### 5.5 submitter

职责：给本机的 AI agent 和用户一个下发任务的接口。只对本机暴露。

- 形态：守护进程内置 MCP server（本机 HTTP），`agentd mcp` 是 stdio 桥接；同时提供 CLI。
- 固定工具：`agentd_list_executors()` 返回 executor 节点、在线状态和各自声明的工具。
- 动态工具：按 agentserver 推送的清单，为每个 executor 的每个工具生成一个 MCP tool，名字 `<executor>__<tool>`（executor 用短名），如 `office__exec_command`、`office__write_stdin`；Claude Code 等客户端会再加 `mcp__<server>__` 前缀并限制 64 字符，所以 3.1 建议实例名不超过 32 字符。参数 schema 是 Codex 同名工具的裁剪版：`exec_command` 只暴露 `cmd`、`workdir`、`tty`、`yield_time_ms`、`max_output_tokens`，`write_stdin` 只暴露 `session_id`、`chars`、`yield_time_ms`、`max_output_tokens`；Codex 里与沙箱审批、环境选择有关的参数不暴露。
- 工具描述来自 executor 配置，但对 AI agent 来说是不可信输入：限长，并以「来自节点 office」前缀标明来源，防止某个成员节点借描述注入提示词。
- `session_id` 是 executor 内唯一的整数，不同 executor 之间会重叠，靠工具名前缀区分；submitter 记住每个 session 属于哪个 executor。
- 返回给 AI agent 的文本采用 Codex 发给模型的格式（7.6），同时在 MCP 的 structuredContent 里给出结构化字段；只接受 executor 签名有效的输出，验签失败按「结果未知」处理。
- 会话中断导致结果未知时，submitter 不自动重试，向调用方返回明确的「结果未知」错误并附 `call_id`；调用方重试时复用同一 `call_id` 可由 executor 去重（5.6）。
- CLI：`agentd task exec office -- 'lark-cli msg send …'` 封装成 `exec_command` 调用。

### 5.6 executor

职责：以登录用户的身份、在策略范围内执行 workspace 内其他节点发来的 Codex tool call。

```yaml
executor:
  enabled: true
  policy_source: local                        # local | server
  description: 公司机器，已登录 lark-cli
  policies:                                   # 能执行的程序就是 allow 规则里出现过的 argv[0]；可写裸名或绝对路径
    - { public_key: "hC3Qm…", action: allow, argv: ["/opt/homebrew/bin/lark-cli", "msg"] }
    - { public_key: "hC3Qm…", action: allow, argv: ["lark-cli", "doc"], stdin: true }
    - { public_key: "hC3Qm…", action: allow, argv: ["git", "status"] }
  workdir: /Users/me/work
  env: { passthrough: [HOME, PATH, LANG, TERM] }
  limits: { max_sessions: 4, default_yield_ms: 10000, max_output_bytes: 1048576, session_idle: 10m }
```

执行模型：

- 收到 `task` 流后依次：验签（签名覆盖 `Open` 头部和整个 `function_call`，`task.executor` 必须是自己，`to` 必须是送来这条流的会话对端，时间戳在窗口内、随机数未见过），发起方公钥或其有效成员证书的签发者必须等于某条规则的 `public_key`（或有 `*` 规则）；按 (发起方公钥, call_id) 去重，重复的调用直接返回缓存结果或附着到进行中的会话（缓存保留 10 分钟）；校验工具名；解析并匹配策略；执行。
- 不经 shell。`cmd` 用 shell 语法解析器（Go 可用 `mvdan.cc/sh/v3/syntax`，参考 Codex `shell-command/src/bash.rs` 的白名单做法）解析为简单命令，只接受字面量 word、管道 `|`、`&&`、`||`、`;`；出现变量展开、命令替换、重定向、通配符、子 shell 等任何其他语法一律拒绝。agentd 自己 exec 每个简单命令并在 Go 里实现管道与短路。
- 没有单独的程序表：能执行的程序就是 allow 规则里出现过的 `argv[0]`。规则里的 `argv[0]` 写裸名（守护进程启动时在自己的 PATH 里解析一次并固定）或绝对路径；调用方 `cmd` 里的 `argv[0]` 不论写成相对路径还是绝对路径都按 basename 与规则比较，实际执行的路径永远取自规则，调用方指定不了。
- 策略匹配 argv 前缀数组（Codex `prefix_rule` 的形式）：`["lark-cli", "msg"]` 匹配 `lark-cli msg send …` 但不匹配 `lark-cli --json msg …`，所以要放行的写法都要列出来；显式 deny 优先、其余取 allow 的并集（6.6）；管道或复合命令里任一子命令被拒即整体拒绝。只写允许规则，不依赖拒绝规则，因为参数重排会绕过拒绝。
- Codex 参数里的 `shell` 和 `login` 不接受（调用方不能选解释器），`tty` 默认 false。完整 shell 只能对特定调用方显式开启：策略项加 `shell: true` 后该调用方的 `cmd` 交给配置里指定的 shell 执行，CLI 和文档对此给出明确警告。
- `write_stdin` 默认关闭：只有命中的策略项带 `stdin: true` 时，该会话才接受后续写入；否则进程的 stdin 直接关闭。原因是一旦允许交互，白名单就只约束第一条命令。
- `exec_command` 的语义与 Codex 一致：启动进程，等待 `yield_time_ms` 后返回已有输出；进程未结束则返回 `session_id`，之后由 `write_stdin` 写入并继续取输出。
- 输出按 `max_output_tokens` 和本地字节上限（与 Codex 相同的 1 MiB）截断，并在输出里标注。
- 并发上限、超时、`workdir` 限定在配置目录下、环境变量只透传白名单；审计日志记录发起方公钥与名字、`call_id`、argv、起止时间、退出码。
- 返回的 `function_call_output` 由 executor 签名（覆盖 call_id、输出字段、发起方与自己的公钥、时间戳），submitter 验签后才交给 AI agent，防止中间环节伪造工具输出向模型注入内容。
- 节点把 `description`、支持的工具（自管时还有生效策略）上报给 agentserver，供 submitter 生成动态工具、供控制面在转发前预检。

### 5.7 agentserver（控制面，管理平台兼后端）

职责：workspace 的全部状态与决策。不接受节点的连接，只和 relay 与管理员说话；不在数据路径上。模块：

- **coordinator**：workspace、目录（公钥、名字、角色上限、在线状态）、分组与组密钥、workspace 密钥、成员证书的签发、续期与吊销、路由表、服务注册与状态、各节点上报的策略来源与自管节点的生效策略、加入令牌。处理 relay 转来的节点消息（`Advertise`、`PolicyApplied`、`Pull`、`RelayReport`、P2P 信令），生成发给节点的消息（`Welcome`、`Update`、`PolicyUpdate`、`Notice`、`AdvertiseResult`），用该 workspace 的密钥签名，交 relay 送达。
- **policy**：中央策略的存储、按节点渲染与 `PolicyUpdate` 下发（6.8）；转发预检的判定（受管节点用渲染结果，自管节点用上报的生效策略）；边缘访问的判定。
- **routing**：路由表（6.5）：为 relay 的查询选出口，为 ingress 节点渲染分流表。
- **relay 管理**：注册 relay（名字、公钥、地址、transport 路径、STUN 端口），为它服务的每个 workspace 用该 workspace 的密钥签发短期 relay 证书，给每个 workspace 指派 relay（MVP 一个），维护与每个 relay 的会话：回答查询（这把公钥是谁、加入请求、某条流的选路与预检结果、某 workspace 的服务证书），目录、路由表、服务、策略或证书变更时推 `RelayInvalidate`，推服务证书；在 `Welcome` / `Update` 里把 relay 证书列表与指派告诉节点，收到节点的 `RelayReport` 时改派。
- **ACME**：按 workspace 基础域名所在 zone 的 DNS 凭据完成 DNS-01，为每个 workspace 签发并续期通配证书 `*.<基础域名>`；证书与私钥加密存在状态库，经 relay 会话下发给服务该 workspace 的 relay；需要公开访问时写入 `*.<基础域名>` 指向 relay 的记录。
- **P2P 会合**：候选地址保存、`P2PConnect` 的校验与 `P2PInvite` 的下发（7.8），消息都经 relay 转交。
- **admin API 与 CLI**：管理 workspace、目录、分组、路由表、策略、域名、relay；`agentserver backup` 导出状态库（含服务器私钥、组与 workspace 私钥、ACME 账户密钥、证书私钥和目录，丢失等于全网重新 join）；Web 控制台放后续。

多租户：一个 agentserver 服务多个 workspace，不同 workspace 的节点互不可见；每个 workspace 有自己的基础域名、证书、路由表、分组和目录。agentserver 只需要对 relay 和管理员可达，可以放在内网；它的规模随 relay 数而不是节点数增长。

### 5.8 agentrelay（数据面与节点接入）

职责：作为节点唯一的服务端，维持节点的会话，终结控制流并在节点与后端之间转交消息，在节点之间转发流，充当 HTTP 服务的 HTTPS 边缘。与 agentserver 分开部署，可以多实例；没有持久状态，不持有目录、路由表或策略的副本，只有对后端答案的 TTL 缓存和内存里的证书。

- **hub**：接受节点的会话（Noise_IK 响应方，凭 relay 证书被节点认可）。握手时向后端查这把公钥是谁（答案缓存），带令牌的握手转为加入请求；后端确认后回 `ServerHello{OK}` 并记下 workspace、名字、角色上限，从此接受它的数据流；同一公钥的新会话替换旧会话。节点上下线报告给后端（`RelayPresence`）。
- **control**：节点的流 1 是控制流，在 relay 终结。后端发给该节点的消息（都在 workspace 密钥签名的 `Signed` 信封里）原样送达；节点发来的消息（`Advertise`、`PolicyApplied`、`Pull`、`RelayReport`、P2P 信令）以 `NodeMessage{节点公钥, 消息}` 转给后端，relay 对后端证明消息来自谁。relay 不解释也不缓存这些消息，会话建立时向后端要一份该节点的 `Welcome` 送达。
- **forwarder**：清单 A（协议规范 4.1）：本地校验（验签、`from` 与会话一致、`to` 是自己、时间戳、随机数），向后端查询这条流的选路与预检结果（后端先按路由表或服务表选出目的节点、任务按 `task.executor`，再查双方角色，再用目的节点的策略预检；答案缓存），确认目的节点在线，然后拼接两条流；填 `RelayInfo`；原样转发 `Open`、成员证书与后续字节。
- **edge**：公网 443 与经 ingress 送来的服务域名流进入同一监听逻辑，按 SNI 选 workspace 证书（向后端取得，内存持有）与服务，访问者是否被允许（含公网访问者）来自后端按服务策略给出的答案（缓存），以 HTTP/1.1 反向代理到服务节点并注入身份头；edge 发起的流由 relay 的身份密钥签名；公网 80 回 301。
- **STUN 反射**：UDP 3478，供开启 P2P 的节点获取反射地址（7.8）。
- **relay 会话**：relay 作为 Noise_IK 发起方连到 agentserver，`session_kind = RELAY`，一条流承载全部消息：relay 的查询（`RelayLookup`）、节点消息转交（`NodeMessage`）、在线状态（`RelayPresence`），以及后端的答案（`RelayAnswer`）、发给节点的签名消息（`Deliver`）、缓存失效（`RelayInvalidate`）、服务证书（`WorkspaceCerts`）和 relay 自己的证书（`RelayCert`）。后端不可达时：已有会话与已缓存的答案继续工作，控制流上没有新消息，新节点与未缓存的组合得到 `CONTROL_NOT_READY` 并退避重试，证书到期不再续；重连后清空缓存并重报在线节点。
- **缓存**：答案以查询内容为键、按后端给的 TTL（默认 60 秒）缓存，LRU 有界；一个 workspace 的任何变更都让后端推一条 `RelayInvalidate`，relay 清掉该 workspace 的全部条目并关闭被移除节点的会话。relay 不自己做选路或策略判定，判定逻辑只有 agentserver 一处实现。
- **well-known**：`GET /.well-known/agentd?workspace=<基础域名>` 返回本 relay 在该 workspace 的 relay 证书、协议版本区间与 transport 路径，供 `agentd join` 首次接触时用 workspace 公钥验证这个 relay。

MVP：每个 workspace 指派一个 relay，该 workspace 的全部成员都连到它，relay 之间不转发。多 relay、就近指派与 relay 间转发（DERP 网状那种）放后续。

---

## 6. 域名、寻址与路由

### 6.1 域名体系

| 对象 | 域名 | 示例 |
| --- | --- | --- |
| agentserver | 自己的域名，供 relay 建 relay 会话，也是默认 zone；节点不直接连它 | `agentsrv.example.com` |
| relay | 自己的域名，供节点建会话 | `relay-hk.agentsrv.example.com` |
| workspace 基础域名 | 默认 `<ws>.<agentserver 域名>`；可改为自定义域名 | `home.agentsrv.example.com`；自定义如 `home.example.org` |
| 服务 | `<service>.<基础域名>`，HTTP 服务走 443，SSH 服务走 22 | `nas.home.agentsrv.example.com`、`homepc.home.agentsrv.example.com` |

节点本身没有 DNS 域名，它的名字是 `agentd://` URI（3.1）：任务的目的地在线上是公钥，配置和 CLI 里可以用名字形式或短名；要用 SSH 登录节点，发布一个同名的 `proto: ssh` 服务即可。

公网解析：默认不发布服务域名的公网记录，成员经 ingress 访问时由 fake-IP 或代理请求提供域名。workspace 打开 `publish_dns` 后，agentserver 用 zone 的 DNS 凭据写入 `*.<基础域名>` 指向服务该 workspace 的 relay 的记录，策略里对 `*` 开放的服务即可被任何浏览器访问。relay 放在 Cloudflare 橙云后面时，这条记录应为灰云（直指 relay），因为免费的 Universal SSL 不覆盖两级通配名。

### 6.2 证书

- 每个 zone（agentserver 自己的域名，以及 workspace 的自定义域名）配置一份 DNS 提供商凭据（首个实现支持 Cloudflare，经 `golang.org/x/crypto/acme` 做 DNS-01；阿里云、DNSPod 等按同一接口扩展），用于 ACME DNS-01 和（可选）写服务记录。DNS-01 不要求域名有公网 A 记录，所以服务域名可以只在工作区内解析。
- 每个 workspace 一张通配证书 `*.<基础域名>`，由 agentserver 在创建 workspace 或绑定自定义域名时申请，到期前 30 天续期；DNS-01 通常要 1 到 3 分钟，期间该 workspace 的 HTTP 服务处于 `cert_pending`。私钥与证书由 agentserver 签发并加密存放在状态库里，经控制面与 relay 的会话下发给服务该 workspace 的 relay，relay 只在内存持有；节点上没有任何公网域名的私钥。
- 通配证书的前提是私钥不离开运营方的服务端（agentserver 与它指派的 relay），这正是 v0.4 的决定；它也把 Let's Encrypt 的签发配额从「每服务一张」降到「每 workspace 一张」。
- agentserver 与 relay 各自域名的证书：放在 Cloudflare 后面时可用 Cloudflare 源站证书，直连时同样走 ACME。
- 自定义域名的 zone 凭据只用于 `_acme-challenge.<基础域名>` 和 `*.<基础域名>` 两条记录，应申请只限该 zone 的最小权限令牌。

### 6.3 协议与域名识别顺序

对进入 ingress 的每条 TCP 连接，按下面顺序处理：

1. 目的地在 fake-IP 池里：映射给出域名 D（服务域名或分流表判为交给下一跳的域名）。读首段数据（200 毫秒、16 KiB 预算）：是 TLS ClientHello 则 SNI 必须等于 D，`proto: tls`；首行以 `SSH-` 开头或目的端口为 22 则 `proto: ssh`（不等待首字节）；80 端口的 HTTP 请求回 301；其他 RST。
2. 目的端口在 `sniffing.skip_ports` 里（默认 22、25、110、143、3306）：不嗅探，直连。这些端口上要么服务端先说话、嗅探只会白等，要么是 SSH、字节里没有域名；到真实 IP 的 SSH 没有域名可用，只能直连。
3. 在 200 毫秒、16 KiB 预算内累积首段数据，解析 TLS ClientHello 取 SNI，查分流表：`via` 则开流交给 relay（出口由控制面选），`direct` 则直连并回放，`reject` 则 RST；服务域名一律开流，由 relay 送到边缘或服务节点。ClientHello 带 ECH 扩展时记录计数；外层 SNI 照常参与规则匹配。
4. 都没有：这是无 SNI 的 TLS 或非 TLS 连接，直连原始 IP 和端口，回放已读字节。

代理模式（HTTP CONNECT、SOCKS5、`agentd connect`）下请求自带域名：嗅探只用来判定协议；TLS 的 SNI 与请求域名不一致时以 SNI 为准并记录；首行 `SSH-` 或目的端口 22 判为 SSH。

明文 HTTP 不识别、不转发：到服务域名 80 端口回 301，其他直连。

### 6.4 内置 DNS 与 fake-IP

- 内置 DNS 只在 TUN 模式存在（`tun.dns`），监听 UDP 和 TCP。它不做任何按 IP 的分流：分流只按域名，但 TUN 看到的是 IP 包，域名要么从 SNI 嗅探出来，要么在解析阶段就记下来；内置 DNS 就是后一条路。elevator 把系统 DNS 指向它（`override_system`，默认开），并把发往任意地址 53 端口的查询重定向过来；TCP 53 也要接管，否则 TC 位重试会绕过下面的剥离。代理模式的三种入口自带域名，不需要它。
- 返回 fake-IP 的域名有两类，没有开关：工作区服务域名（它们默认没有公网记录，且必须走成员路径携带身份）；分流表判为 `via` 的域名。后者的理由：校园网内网域名在校外解析不到，没有 fake-IP 浏览器在 DNS 阶段就失败，TUN 根本看不到连接；SSH 没有 SNI，只能靠映射拿到域名。嗅探到的 SNI 优先级高于映射，两者不一致时以 SNI 为准并记录。
- 池为 198.18.0.0/15（RFC 2544 保留段），IPv6 用 2001:2::/48（RFC 5180 保留段，与 Xray 一致，避开家庭路由常用的 ULA）。分配按域名哈希确定，跨重启稳定，因为 Chrome 在 macOS 上会把系统解析结果固定缓存 60 秒，TTL 1 秒挡不住。
- 其他域名从物理接口转发上游并返回真实答案；上游默认是接管前系统原有的解析器，也可在 `tun.dns.upstream` 指定。对所有应答剥离 HTTPS（类型 65）和 SVCB 记录，使浏览器不会拿到 ECH 配置。
- 对 Firefox 的金丝雀域名 `use-application-dns.net` 返回 NXDOMAIN，让 Firefox 关闭默认开启的 DoH。Chrome 在系统 DNS 指向本机地址时不会自动升级到 DoH；用户显式配置的 DoH 仍会绕过本机 DNS。
- TUN 模式下，对已知公共 DoH 端点的 SNI（dns.google、cloudflare-dns.com、mozilla.cloudflare-dns.com 等）本地 RST，让浏览器回退明文 DNS；列表可配置、可关闭。
- 已知局限：显式配置 DoH 且未被上述手段拦下时，服务域名解析不到，公网域名可能启用 ECH 而静默直连；`agentd status` 的计数用于发现这种情况。

### 6.5 路由表（agentserver 上，按 workspace）

路由表回答「谁发起的、什么协议、去哪个域名的连接，由哪个节点出去」。每条路由是（源，协议，域名模式，目的）：

```yaml
# workspace home
routes:
  - { from: group:pc,  proto: [tls, ssh], domains: [{ kind: suffix, value: ucas.edu.cn }, { kind: suffix, value: ucas.ac.cn }], to: dorm }
  - { from: workspace, proto: [tls],      domains: [{ kind: domain, value: login.ucas.edu.cn }],                to: direct }   # 更具体的例外
  - { from: workspace, proto: [tls, ssh], domains: [{ kind: suffix, value: internal.example.com }],            to: office }   # office 若也启用 egress
default: direct
```

- 源：`node:<名>`、`group:<名>` 或 `workspace`，与策略的主体写法相同（6.8）；不写等于 `workspace`。
- 协议：`tls`、`ssh` 中的一个或两个；不写等于两个。
- 域名模式写成对象 `{ kind, value }`：`kind: domain` 精确匹配，`kind: suffix` 匹配本身及所有子域。没有 IP 或 CIDR。域名集合（`kind: set`）第一期不做，位置保留。
- 目的：某个 egress 节点、`direct`、`reject`。服务域名不写路由，服务注册即路由。
- 判定：先取源包含请求方（节点本身、它所在的组或 workspace）且协议匹配的路由，再在其中取最具体的域名匹配（精确 > 更长的后缀 > 更短的后缀 > 默认）；同等具体时按书写顺序取前者。
- 路由表只在 agentserver 上，不下发：relay 转发一条流时向控制面查询，控制面按请求方、协议、域名选出目的节点（答案缓存，5.8）。给每个 ingress 节点渲染的是分流表：只取源包含该节点的路由，目的只保留「交给下一跳 / 直连 / 拒绝」，不含任何节点。ingress 因此不知道出口是谁，换出口、加出口只在 agentserver 上改。
- 分流表随 `Welcome` 下发、变更时经 `Update` 整体替换，带版本号；ingress 判分流表与控制面判路由表用同一个比较函数。ingress 收到 `NO_RULE` 且 Ack 里的版本比自己的分流表新时，重新拉取后按新表处理（可能变成直连或拒绝）。
- Ack 失败时 ingress 的行为：目标离线、无路由、控制面不可达按可配置策略处理，默认回退直连原始 IP 并回放已缓存的首段数据（`fallback: direct`），可配为失败；`reject` 则本地 RST；目标是服务或目的地是 fake-IP 时不回退。已缓存的首段数据保留到收到 Ack 为止。
- 两个 egress 想负责同一目的时写两条路由，前者优先；故障切换放后续。出口的选择完全在控制面，将来做故障切换或就近选择也不需要改 ingress。

### 6.6 策略模型

策略回答「谁可以对哪个目标做什么」。不论策略来自本地配置还是 agentserver 下发，提供侧节点实际执行的永远是同一种形态：

```
(public_key: 一把公钥或 *, action: allow | deny, target)
```

`public_key` 可以是三种身份里的任意一种：节点公钥、组公钥、workspace 公钥（6.8）；一条规则只写一把，多把就多写几条。请求方的身份集合是它自己的公钥，加上它随请求出示的、验证通过的成员证书的签发者公钥。一条规则命中，指 `public_key` 在身份集合里且 target 匹配。`*` 匹配任何人：对 egress、executor 与 ssh 服务就是任何签名有效的成员（只有成员能把流送到这里），对 HTTP 服务还包括未经 ingress 的公网访问者，由 relay 的边缘执行；要表达「所有成员」又不想放开公网，写 workspace 公钥。

target 是字面的，节点上没有目标组：

| 角色 | target | 执行点 |
| --- | --- | --- |
| egress | 一个协议（默认 `tls`；同一组域名要同时放行 tls 和 ssh 就写两条）+ 域名模式对象列表（`{ kind: domain | suffix, value }`）+ 可选端口列表（默认 tls 443、ssh 22）；请求的协议、域名、端口都落在其中才匹配 | 节点，凭验签得到的身份集合 |
| executor | argv 前缀数组 + 可选 `stdin` / `shell` 开关；解析出的简单命令匹配前缀才算命中 | 节点，凭验签得到的身份集合 |
| service（ssh） | 服务名 | 节点，凭验签得到的身份集合 |
| service（http） | 服务名；`public_key: "*"` 含公网访问者 | 控制面判定、relay 边缘执行，凭送流会话的身份或边缘登录身份 |

判定：显式 deny 优先。对一个请求，先看是否有任一 deny 规则命中，命中即拒绝；否则看是否有任一 allow 命中，命中即允许；否则拒绝。规则之间没有顺序，与 AWS IAM、Teleport 的角色、Cedar 的 forbid-overrides-permit 相同。此前的「首条命中」改为这种无序判定，原因是分组策略由 agentserver 渲染和合并，无序判定不依赖渲染顺序，也便于把本地 deny 叠加在下发策略之上。对 executor 的建议不变：只写 allow，不要指望用 deny 挡住参数重排；管道或复合命令里任一子命令没有被 allow 覆盖或被 deny 覆盖即整体拒绝。

节点上永远没有目标组。域名集合第一期不做（6.5）；将来加上时也只在 agentserver 上定义、渲染时展开成字面模式，命令集合之类的新组概念同理。

### 6.7 策略来源：local 与 server

每个提供侧角色（egress、service、executor）各自用 `policy_source` 选择策略的权威来源，二选一；同一节点可以 egress 自管、executor 受管。不论来源，策略都是唯一的授权抽象：提供侧节点执行它，控制面在转发前用同一份做预检，没有单独的接受名单。

| 来源 | 生效的策略 | agentserver 的下发 | 控制面预检用的策略 |
| --- | --- | --- | --- |
| `local`（默认） | 本地配置文件里的规则 | 照常下发，节点忽略并回 `PolicyApplied{applied: false}` | 节点随 `Advertise` 上报的生效策略（配置热更新时重报） |
| `server` | agentserver 渲染并下发的规则；本地文件里的 allow 被忽略，deny 仍然生效（刹车） | 变更即推送，节点原子替换后回 `PolicyApplied{applied: true, version}` | 它自己渲染的那一份 |

- 切换来源是节点自己的决定，写在该角色的配置里，随 `Advertise` 按角色上报；agentserver 在目录里记录每个节点各角色的来源，管理界面显示「受管 / 自管」。
- 两种来源下 `public_key` 都只写一把公钥或 `*`，没有别名：节点、组、workspace 的公钥一视同仁。自管节点从 `agentd peers` 的输出复制进规则，只信任自己写下的那几把；受管节点由下发的规则直接携带。没有「是否信任 agentserver 目录」这种开关，目录只用于显示和复制。
- 预检看得到的维度：请求方的身份集合（节点、它所在的组、workspace，按目录算）、协议、域名、端口、服务名；argv 只有提供侧在解析命令后才知道，预检对任务只看「谁对这个 executor 至少有一条 allow 且没有覆盖它的 deny」。预检是提前拒绝，不替代提供侧的判定。
- `server` 模式下本地 deny 仍然生效，是给设备持有者留的刹车：例如 `- { public_key: "*", action: deny, shell: true }` 保证即使中央策略被改宽也不会在这台机器上开 shell。本地 allow 在 `server` 模式下被忽略并告警，避免两份 allow 叠加后没人说得清边界。
- 服务的访问控制也是策略，没有单独的 `access` 或 `allow_from`：`service` 角色的 `policies` 里写 `(public_key, allow | deny, service: 名字)`，`public_key: "*"` 对 HTTP 服务表示任何人（含未经 ingress 的公网访问者），由 relay 的边缘执行；`server` 模式下来自中央策略，节点只声明服务的存在、协议和本地目标。
- 路由表（6.5）不是策略：它一直是 agentserver 的，ingress 总是接受分流表；它不授予任何权限。
- `workdir`、`env`、`limits`、服务的 `target` 等描述本机环境的配置始终是本地的，不属于策略。

### 6.8 身份层级、成员证书与渲染

**四级密钥。** 所有身份都是 Ed25519 密钥对，密钥形式的名字统一是 `agentd://<公钥>`：

| 身份 | 持有者 | 用途 | 名字形式 |
| --- | --- | --- | --- |
| 节点 | 节点自己 | 签 `Open`、任务与输出；派生 X25519 与 agentserver 握手 | `agentd://<ws 域名>/<实例名>` |
| 组 | agentserver（状态库，加密存放） | 给组成员签成员证书 | `agentd://<ws 域名>/group/<组名>` |
| workspace | agentserver（状态库，加密存放） | 成员唯一钉住的信任根：签发给成员的控制消息、该 workspace 的 relay 证书和全部成员的成员证书（表达「任何成员」） | `agentd://<ws 域名>/`，写在成员配置的 `workspace.public_key` |
| agentserver | agentserver | 派生 X25519 与 relay 握手 | 无；节点不需要知道它，只有 relay 配置的 `control.public_key` |
| relay | 每个 relay | 派生 X25519 与节点和 agentserver 握手；签 edge 发起的流 | 无，随 relay 证书下发 |

节点不需要知道一把公钥属于哪一级：`public_key` 写了谁，就看请求方自己是不是它，或者有没有它签发的证书。组密钥将来也可以交给 agentserver 以外的持有者（比如组的管理员设备），协议不变。

**成员证书。**

- 内容：`{成员公钥, 签发者公钥, workspace, 签发时间, 过期时间, 组名}`，由签发者（组或 workspace）的私钥用 Ed25519ctx 签名。
- 有效期默认 1 小时。agentserver 在 `Welcome` 里发给成员它当前持有的全部证书，在剩余有效期过半时经 `Update` 续发；成员离组或离开 workspace 时停止续发，并向 workspace 内全部节点推送吊销记录（成员, 签发者, 截止时间），节点保留到截止时间。
- 发起方开流时把自己持有的证书附在 `StreamOpen.certs` 里（最多 16 份，不进 `Open` 的签名）。接收方只验证签发者出现在自己策略里的那些，其余忽略；验证条件是签名对得上签发者公钥、成员等于 `from`、workspace 一致、未过期、不在吊销记录里。
- 证书是签给成员的，与请求走哪条路径无关：经 relay 中继和将来的 P2P 直连（7.8）用同一套判定。转发预检由控制面按目录里的成员关系判定，不看证书；relay 也不改动证书。
- `UNKNOWN_PEER` 的含义：没有规则的 `public_key` 等于 `from` 或它出示的有效证书的签发者，也没有 `*` 规则。

**中央策略与渲染。** agentserver 上的策略用主体书写：

| 主体 | 含义 | 渲染到节点 | 在边缘 |
| --- | --- | --- | --- |
| `node:<name>` 或 `agentd://…` | 一个实例 | 该实例的公钥 | 按送流会话的公钥 |
| `group:<name>` | workspace 配置里命名的一组实例 | 组公钥 | 按成员关系 |
| `workspace` | 全部成员 | workspace 公钥 | 任何成员会话 |
| `user:<邮箱>`、`usergroup:<name>` | 在边缘登录过的人（后续） | 不渲染，节点不认人 | 按边缘登录身份 |
| `public` | 任何人，包括未登录 | `public_key: "*"` | 公网匿名访问 |

渲染算法（agentserver 上，每个 workspace 一份）：

1. 对每个报告 `policy_source: server` 的提供侧角色（节点 N 的 egress、service 或 executor），挑出目标落在该角色上的 allow 与 deny 条目：`egress: N`、`exec: N`、`service: <N 上的服务>`。
2. 把主体换成公钥：`node:` 换节点公钥，`group:` 换组公钥，`workspace` 换 workspace 公钥；`user:` 丢弃，`public` 换成 `*`；一条语句有几个主体就生成几条规则。
3. 生成 `(public_key, action, target)`，按 egress、exec、service 分三组；target 只有字面模式（域名集合第一期不做，将来在这一步展开）。
4. 计算哈希，与上次发给 N 的不同时版本号加一，经 `PolicyUpdate` 推送，等待 `PolicyApplied`。
5. 边缘策略单独渲染，主体保留五种，供 edge 判定 HTTP 服务。

成员进出组不触发重渲染，因为规则里只有组公钥；触发重渲染的只有策略语句、分组的新建与删除、服务注册注销和角色切换 `policy_source`。

workspace 配置示例（9.1 有完整版）与 `dorm` 收到的渲染结果：

```yaml
groups:
  pc: [laptop, laptop2]
policies:
  - subjects: [group:pc]
    allow:
      - { egress: dorm, proto: tls, domains: [{ kind: suffix, value: ucas.edu.cn }, { kind: suffix, value: ucas.ac.cn }] }
      - { egress: dorm, proto: ssh, domains: [{ kind: suffix, value: ucas.edu.cn }, { kind: suffix, value: ucas.ac.cn }] }
      - { exec: office, argv: ["lark-cli", "msg"] }
  - subjects: [workspace]
    deny:
      - { egress: dorm, proto: tls, domains: [{ kind: domain, value: login.ucas.edu.cn }] }
```

```yaml
version: 12
egress:
  - { public_key: "<pc 组公钥>",        action: allow, proto: tls, domains: [{ kind: suffix, value: ucas.edu.cn }, { kind: suffix, value: ucas.ac.cn }] }
  - { public_key: "<pc 组公钥>",        action: allow, proto: ssh, domains: [{ kind: suffix, value: ucas.edu.cn }, { kind: suffix, value: ucas.ac.cn }] }
  - { public_key: "<home workspace 公钥>", action: deny,  proto: tls, domains: [{ kind: domain, value: login.ucas.edu.cn }] }
```

**laptop 访问 office 的 lark-cli。**

1. 管理员 `agentserver group create home pc` 生成 pc 组密钥对，`agentserver group add home pc laptop`。office 的策略里写 `{ public_key: "<pc 组公钥>", action: allow, argv: ["lark-cli", "msg"] }`：自管时从 `agentd peers` 复制 pc 组公钥，受管时由渲染结果携带。
2. laptop 在 `Welcome` 里拿到 pc 组和 home workspace 签给它的两份证书，之后每半小时续一次。
3. laptop 构造并签名 `Open`（TASK，from 为 laptop，to 为 relay，`task.executor` 为 office，整个 `function_call`），附上两份证书，开流。
4. relay 验签，向控制面查询（控制面确认目的节点 office、查角色、按目录里的成员关系用 office 的策略预检），原样转发 `Open` 与证书。
5. office 验 laptop 的签名，验 pc 组证书（签发者是规则里写的 pc 公钥，成员是 laptop，未过期，未吊销），身份集合为 {laptop, pc, home}；解析 `cmd`，没有 deny 命中，`(pc, allow, lark-cli msg)` 命中，放行并记录「laptop 以 pc 组成员身份被放行」。

相关工作的对照：

| 系统 | 做法 | 对 agentd 的借鉴 |
| --- | --- | --- |
| OpenSSH 证书 | authorized_keys 里一行可以是用户公钥，也可以是 `cert-authority` 的 CA 公钥；持有 CA 签发证书的用户同样被放行；证书有有效期，吊销靠 KRL | `public_key` 既可以是节点公钥也可以是组或 workspace 公钥；成员证书与吊销记录 |
| Nebula、ZeroTier | 分组或标签写进由 CA 签名的节点证书或凭据，节点离线也能验组；ZeroTier 的 capability 由控制器签发 | 成员证书由成员携带、与路径无关 |
| Tailscale、Headscale 的 ACL | 中心策略用用户、`group:`、`tag:` 书写，控制面编译成每个节点自己的包过滤表下发 | 渲染成按节点裁剪的规则；区别是我们不展开成员，组保留为一把公钥 |
| Cloudflare Access | 每个应用一组策略，动作 Allow、Block、Bypass，规则按邮箱、身份组、Everyone | 边缘的 `user:` 与 `public` 主体 |
| Teleport、AWS IAM、Cedar | 显式 deny 优先、判定与书写顺序无关 | 6.6 的判定规则 |

### 6.9 评估过但不采用的方案

- Cedar 引擎：现在的模型是 Cedar 的子集（主体即 principal，allow / deny 即 permit / forbid，forbid 优先、默认拒绝一致），但三元组判定几十行代码就够，Cedar 要带进 schema、实体图和一门策略语言，换来的 context 条件与动作扩展正是暂缓的部分。将来若需要，agentserver 可下发 Cedar 策略文本、节点用 `cedar-go` 判定，成员证书照样提供 principal 的父实体，骨架不变。
- 把成员关系图下发到节点：每次成员变更都要推全网，节点要维护与自己无关的状态，还有拿着旧图的窗口。改为成员证书随请求携带。
- 由 agentserver 在中继时附加组签名：把授权绑死在中继路径上，P2P 直连时没有人附签。改为证书签给成员、由成员自己出示。
- 提供侧自定义命名资源：在节点上引入目标组会带来歧义，节点的 target 保持字面，目标组只在 agentserver 上。
---

## 7. 协议与传输

本节是概要；线上格式、状态机、校验顺序与常量的权威定义在 `docs/protocol.md`，protobuf 消息定义在 `proto/agentd/v1/wire.proto`。

### 7.1 分层

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ 签名：节点签 Open 与任务请求、executor 签输出；workspace 密钥签发给节点的控制消息      │  relay 与提供侧都验签，载荷不加密
├─────────────────────────────────────────────────────────────────────────────────┤
│ 流：control（流 1，在 relay 终结）/ tcp(proto, domain, port) / task               │  yamux 多路复用，同一条会话
├─────────────────────────────────────────────────────────────────────────────────┤
│ 会话：Noise_IK（节点 ⇄ relay；relay ⇄ agentserver；节点 ⇄ 节点直连）              │  CDN 只见密文
├─────────────────────────────────────────────────────────────────────────────────┤
│ transport：WebSocket（默认）/ XHTTP / HTTP Upgrade；预留 p2p（QUIC）              │  节点 ⇄ CDN ⇄ relay；relay ⇄ agentserver
└─────────────────────────────────────────────────────────────────────────────────┘
```

命名：在 Go 生态里这一层通常就叫 transport（Xray-core 的 `transport/internet`、标准库的 `http.Transport`、libp2p 的 transport），本文从 v0.4 起沿用，不再叫 carrier。

### 7.2 transport（节点 ⇄ relay，relay ⇄ agentserver）

三种 transport 在 relay 和 agentserver 的端点上按路径区分，节点按配置选一种（或 `auto`）；每种都只需要提供「一条可靠有序的双向字节流」这一个抽象，会话层以上与 transport 无关。节点只对 relay 建 transport 连接；relay 对 agentserver 建一条。参考 Xray-core v26.10.21 的实现：

| transport | Xray-core 对应 | 特点 | 经 Cloudflare |
| --- | --- | --- | --- |
| WebSocket（默认） | `transport/internet/websocket` | 一条双向连接，上下行对称，最简单；二进制消息按字节流对待 | 可用，所有套餐支持 |
| XHTTP | `transport/internet/splithttp`（`client.go`、`dialer.go`、`upload_queue.go`、`mux.go`、`hub.go`，模式在 `config.proto` 的 `mode` 字段） | 下行一条长 GET，上行分片 POST；`packet-up` 模式为 CDN 设计，每片带序号、服务端重排 | 可用；作为 WebSocket 被阻断时的回退，上行吞吐受分片与重排限制 |
| HTTP Upgrade | `transport/internet/httpupgrade` | 发 WebSocket 样式的 Upgrade 头，但之后是裸字节，无帧开销 | 与 Xray 实现一致，需实测 |
| p2p（预留） | 无 | 节点间 UDP 打洞后的 QUIC 连接，一条双向 QUIC 流作为字节流；只用于直连会话（7.8） | 不经 CDN |

CDN 约束（以 Cloudflare 为例，数字需实测）：代理连接约 100 秒无数据即被关闭，会话保活间隔设为 30 秒；请求体有大小上限（Free/Pro 约 100 MB），XHTTP 的分片远低于此；回源默认 HTTP/1.1，这也是 XHTTP 单长 POST 的 `stream-up` 模式会被 CDN 缓冲、必须用 `packet-up` 的原因；边缘到源站没有 UDP，所以经 CDN 的 transport 没有 QUIC 选项。部署时关闭 relay 主机上的 Bot Fight Mode、缓存、压缩和脚本改写，否则 Go 默认 TLS 指纹的非浏览器客户端会被出挑战。

### 7.3 会话、密钥与签名

**一把密钥，两种用途。** 每个实例只有一对 Ed25519 密钥（`agentd key show` 显示公钥，它就是 `agentd://<公钥>`）。它做两件事：

| 用途 | 原语 | 为什么 |
| --- | --- | --- |
| 建会话：节点 ⇄ relay、relay ⇄ agentserver、节点 ⇄ 节点直连 | Noise_IK 握手，静态密钥是由 Ed25519 密钥按固定转换派生的 X25519 密钥 | 两个直接相连的参与方需要的是「认证 + 加密 + 前向保密」的通道，这是密钥交换（DH）的活，Noise 一个来回做完；Noise 框架本身就不用签名，WireGuard、Tailscale 都是这样 |
| 作声明：`Open` 头部、任务请求、任务输出；agentserver 发给节点的控制消息 | Ed25519ctx 签名 | 这些声明要穿过 relay 被第三方核验：relay 终结了两边的 Noise 通道，提供侧只有靠签名才能不依赖 relay 地确认「这确实是 laptop 开的流、office 产出的结果」，节点也只有靠签名才能确认「这份策略确实来自 agentserver 而不是 relay 编的」。签名对任何持有公钥的人都可验，与通道无关，P2P 直连时同样成立 |

为什么不用两把密钥：用户要的是「每个节点一份密钥对，像 WireGuard」；WireGuard 的密钥是 X25519，不能签名，而我们两种用途都要。Ed25519 到 X25519 的派生是标准做法：私钥取 SHA-512(seed) 的前 32 字节并 clamp，公钥按 Edwards 到 Montgomery 的映射 u = (1+y)/(1-y)，即 libsodium `crypto_sign_ed25519_*_to_curve25519`，age 对 ssh-ed25519 密钥也这样用；Thormarker（2021，IACR ePrint 2021/509）分析了同一密钥对兼做 Ed25519 签名与 X25519 密钥交换的联合安全性。实现上是十几行代码，用户永远只看到一把 Ed25519 公钥。若安全评审不接受单密钥派生，备选是每节点两把密钥（身份 Ed25519 加传输 X25519，加入时用身份密钥签传输公钥），对外名字不变（第 10 节）。agentserver、每个 relay、每个组和 workspace 也各是一对 Ed25519 密钥，用法相同：agentserver 的只用来与 relay 握手，relay 的用来握手和签 edge 发起的流，组的签组成员证书，workspace 的签 workspace 成员证书、发给成员的控制消息和该 workspace 的 relay 证书（由 agentserver 代签），是成员唯一钉住的信任根。

**握手。** 协议名 `Noise_IK_25519_ChaChaPoly_BLAKE2s`，prologue 为 `agentd/1`；这与 Tailscale 控制协议 ts2021 的选择一致（`control/controlbase/handshake.go`）。IK 的含义：发起方事先知道响应方的静态公钥（I），发起方自己的静态公钥在第一条消息里加密传给响应方（K），两条消息完成双向认证和前向保密。两处握手：

| 握手 | 发起方知道的响应方公钥从哪来 | 第一条消息的载荷 | 第二条消息的载荷 |
| --- | --- | --- | --- |
| 节点 ⇄ relay | relay 证书：首次从 relay 的 `/.well-known/agentd?workspace=…` 取得并用 workspace 公钥验签，之后随 `Welcome.relays` 更新 | 会话种类、版本区间、TAI64N 时间戳、身份公钥；首次加入时加令牌、建议名字与 workspace | 版本、会话 ID、结果码、两个名字、角色上限、relay 身份、服务端时间；`WRONG_RELAY` 时附正确的 relay 证书。relay 回消息 2 之前向后端问这把公钥是谁（或转加入请求），答案缓存 |
| relay ⇄ agentserver | relay 配置里的 `control.public_key` | 会话种类 relay、版本区间、时间戳、relay 公钥 | 版本、会话 ID |

时间戳的用法来自 WireGuard 白皮书 §5.1：响应方记住每个公钥上次的时间戳，不大于它的拒绝（relay 记在内存，后端为加入请求持久化）。未在目录中且没有有效令牌的公钥在消息 2 里得到带错误码的拒绝；未在 5 秒内完成握手的连接直接断开，限制扫描者的开销。

**控制消息的签名。** agentserver 发给节点的每条控制消息都放在 `Signed` 信封里：`body` 是 {收件节点公钥, 签发时间, 消息}，`sig` 是 agentserver 用该 workspace 的私钥按 Ed25519ctx（上下文 `agentd/control/v1`）的签名。节点用钉住的 workspace 公钥验签，核对收件人是自己、时间在窗口内，并按各消息自己的版本号（目录、分流表、策略）丢弃不比当前新的内容，所以 relay 既不能伪造也不能回放旧策略。节点发给 agentserver 的消息不签：relay 已经用 Noise 认证了节点，以会话身份转交；伪造它们需要攻破 relay，而且影响有限（最多冒名注册服务或改预检用的策略，节点自己的策略仍是最后一道闸）。

**加密帧。** 握手之后每一帧是 `[u16 长度][Noise transport 密文]`，Noise 规定单条消息不超过 65535 字节（规范 §3，§13 推荐的 16 位长度前缀），实现上按 16 KiB 切分，与 TLS record 一致。按 Noise 规范 §11.3 的 Rekey，两侧各自在发送和接收计数到 2^20 条消息时同步换密钥；Rekey 只换密钥不重置 nonce，所以仍要在 2^64 条消息前重新握手，会话至少每 24 小时重建一次。对比：ts2021 没有 Rekey、靠重连；WireGuard 每 2 分钟重新握手。

**多路复用。** yamux 跑在解密后的字节流上。用 libp2p 维护的 go-yamux v5：有 `Reset()`，每流窗口初始 256 KiB、按 RTT 测量自动增长到最多 16 MiB（固定 256 KiB 在 50 ms RTT 下会把单流限制在约 5 MiB/s）；`ConnectionWriteTimeout` 从默认 10 秒调到 30 秒并按实测调整，因为它一旦触发会关掉整条会话；所有写错误路径以 `Reset()` 收尾（7.7）。节点会话上流 1 是控制流，其余是数据流；relay 会话上只有一条流。保活用 yamux 的 ping，间隔 30 秒。

**重连。** 节点的会话带抖动的指数退避；同一公钥的新会话替换旧会话。会话断开时 relay 把节点报为离线，`tcp` 流无法重建，对应的 TCP 连接断开由应用自行重连；进行中的 `exec_command` 进程继续运行，结果按 (发起方公钥, call_id) 缓存，submitter 复用 `call_id` 重试即可取回（5.6）。吞吐不够时可配置多条会话，流在会话间分配。

### 7.4 控制消息（控制流上，protobuf）

节点 ⇄ relay ⇄ agentserver。agentserver 发出的在 `Signed` 信封里，relay 原样送达；节点发出的由 relay 以 `NodeMessage` 转交后端：

| 方向 | 消息 | 内容 |
| --- | --- | --- |
| agentserver → 节点 | `Welcome` | 分流表与版本号（不含目的节点）、服务列表（域名、协议、节点）、目录（公钥、名字、角色、在线状态、组与 workspace 公钥）、executor 清单、提供侧节点的策略（`PolicyUpdate`）、本节点的成员证书、relay 证书列表与当前指派 |
| 节点 → agentserver | `Advertise` | 本节点的服务定义（名字、协议）、executor 描述与工具、各提供侧角色的策略来源 `policy_sources`，自管角色附生效策略，`p2p_enabled` |
| agentserver → 节点 | `AdvertiseResult` | 登记结果：服务的 fqdn 与状态、被拒的服务 |
| agentserver → 节点 | `Update` | 分流表、服务、目录、在线状态的增量，带版本号；续发的成员证书与吊销记录；relay 列表与改派 |
| 节点 → agentserver | `Pull` | 发现分流表或目录版本过旧时请求全量 |
| agentserver → 节点 | `PolicyUpdate` | 为该节点渲染好的全量策略与版本号（6.8）；`Welcome` 里也带一份 |
| 节点 → agentserver | `PolicyApplied` | 已应用的版本，或 `applied: false` 表示节点采用本地策略 |
| 节点 → agentserver | `RelayReport` | 连不上被指派的 relay，请求改派 |
| agentserver → 节点 | `Notice` | 关闭、移除、改名、角色变化、文本 |
| 双向 | `P2PCandidates` / `P2PConnect` / `P2PInvite` / `P2PResult` | P2P 会合（7.8，预留） |

relay ⇄ agentserver（relay 会话，协议规范 5.8）：

| 方向 | 消息 | 内容 |
| --- | --- | --- |
| relay → agentserver | `RelayLookup` | 按需查询：这把公钥是谁（握手）、加入请求（带令牌的握手）、某条流的选路与预检结果（转发）、某 workspace 的服务证书（edge） |
| agentserver → relay | `RelayAnswer` | 对应的答案与可缓存的 TTL；节点查询的答案含 workspace、名字、角色上限和签好名的 `Welcome`；错误时就是 relay 应回给发起方的状态码 |
| relay → agentserver | `NodeMessage` | 某节点发来的控制消息，relay 以会话身份标明来源 |
| agentserver → relay | `Deliver` | 发给某节点的控制消息，已在 `Signed` 信封里；节点不在线时丢弃，它重连时会拿到新的 `Welcome` |
| relay → agentserver | `RelayPresence` | 节点上线与下线 |
| agentserver → relay | `RelayInvalidate` | 某 workspace 的目录、路由表、服务、策略或证书变了：清该 workspace 的缓存，关闭被移除节点的会话 |
| agentserver → relay | `WorkspaceCerts` | 服务域名的通配证书与私钥，签发或续期时推送（也是证书查询的答案）；relay 只在内存持有 |
| agentserver → relay | `RelayCert` | relay 在它服务的每个 workspace 的身份证书（由该 workspace 密钥签），注册与续签时推送；relay 在 `/.well-known/agentd` 上按 workspace 公布 |

认证、版本协商和加入都在 Noise 握手的载荷里完成，不再有独立的 `Hello` / `Challenge` / `Auth` 消息。未知的控制消息类型忽略并记日志；未知的流类型回 Ack 错误；字段只增不改，弃用字段保留编号。

### 7.5 流的打开、签名与头部

打开一条流的第一帧是 `Open`，接收方回 `Ack`。`Open` 是一个信封：`body`（序列化后的 `OpenBody` 字节）加 `sig`（发起方用 Ed25519 对 `body` 的签名）。接收方先对收到的 `body` 字节验签再解码，所以不需要规范化编码；签名用 RFC 8032 的 Ed25519ctx，上下文字符串 `agentd/open/v1`，与其他用途隔离。

`OpenBody` 的字段：

| 字段 | 含义 |
| --- | --- |
| `kind` | `tcp` 或 `task` |
| `workspace` | workspace 基础域名，防止跨 workspace 混用 |
| `from` | 发起节点公钥 |
| `to` | 下一跳：这条流所在会话对端的公钥。经 relay 时是 relay，P2P 直连时是对端节点，edge 向服务节点开流时是服务节点，控制流里是 relay。它不是最终目的地：出口由控制面按路由表选，服务节点由 `domain` 决定，executor 写在 `task.executor`。提供侧要求它等于自己所连的 relay 或自己 |
| `issued_at`、`nonce` | 签发时间（秒）与 16 字节随机数。接收方只接受 5 分钟窗口内的时间戳，并在窗口内记住见过的 (from, nonce) |
| `tcp`：`proto`、`domain`、`port` | 转发目标 |
| `task`：`executor`、`function_call` | 目标 executor 的公钥，以及整个 Codex `function_call`（call_id、name、arguments），都在签名内不可篡改；executor 要求 `executor` 等于自己 |

各类流：

| kind | 发起 → 接收 | relay 的处理（本地校验后向控制面查询，答案缓存） |
| --- | --- | --- |
| `tcp` | ingress → egress | 验签且 `to` 是 relay 自己；控制面按路由表选出出口（选不出回 `NO_RULE`）、查双方角色、用出口的策略预检；出口在线 |
| `tcp` | ingress → service 节点（ssh 服务） | 验签且 `to` 是 relay 自己；控制面按服务表由 `domain` 选出服务节点、用它的策略预检；服务节点在线 |
| `tcp` | ingress → relay 边缘（http 服务） | 验签且 `to` 是 relay 自己；控制面答复服务存在且 `ready`、访问者被策略允许；连接交给 edge |
| `tcp` | relay 边缘 → service 节点 | 由 edge 发起，`from` 为 relay 公钥（在 `Welcome.relays` 里），`proto: http`，附真实访问者身份 |
| `task` | submitter → executor | 验签且 `to` 是 relay 自己；控制面确认 `task.executor` 是同 workspace 有 executor 角色的节点、发起方有 submitter 角色、用 executor 的策略预检；目标在线 |

约定：

- 发起方开流后不必等 Ack 就可以发首段数据（`tcp` 的 ClientHello 或 SSH 首行）；接收方在策略通过前把它放在有界缓冲（16 KiB）里，拒绝时连同流丢弃。relay 在自己的校验通过前不向目标开流，失败时立即回错误 Ack。
- 提供侧验签时要求 `to` 等于送来这条流的会话对端、任务的 `task.executor` 等于自己、服务流的 `domain` 是自己的服务，所以 relay 不能把任务送给别的 executor、不能把服务流送给别的节点；要求 `from` 等于签名公钥，所以不能冒充来源；`body` 被改动则签名失效。egress 流的出口本来就由控制面选、relay 执行，一个被攻破的 relay 能做的改道只是在愿意接受该发起方的出口之间换一个，出口自己的策略仍然把关。此外 relay 能做的只有拒绝、延迟，以及向 `tcp` 流的后续字节注入数据（这会破坏 TLS 或 SSH 连接，立即可见）。
- `task` 的响应 `function_call_output` 同样是信封：executor 用自己的密钥对 {call_id, from, to, 输出字段, issued_at} 签名，submitter 验签。
- 流上的后续字节不签名也不加密，靠两跳的 Noise 会话保护，CDN 看不到；relay 看得到（`tcp` 是 TLS / SSH 密文，`task` 的请求在 `Open` 里、响应在信封里，都是明文）。
- 半关闭与 RESET 由 yamux 逐跳传递，relay 原样转发。
- `from` 既在签名里也由 relay 用会话身份核对，两者必须一致。
- 发起方把自己持有的成员证书附在 `StreamOpen.certs`（不在 `Open` 的签名内，最多 16 份）；接收方据此把组或 workspace 公钥算进请求方的身份集合（6.8）。relay 原样转发，不增不改。

Ack 错误码：目标离线、无路由、控制面不可达且无缓存、角色不符、服务未就绪、验签失败、来源与会话不符、时间戳超窗、重放、预检被策略拒绝、对端未知、策略拒绝、协议不匹配（SNI 与头部不符或不是 SSH）、端口不允许、不支持的工具。一条 `tcp` 流对应一条 TCP 连接，一条 `task` 流对应一次 tool call。
### 7.6 任务协议（Codex tool call）

任务的请求和响应采用 Codex 的 Responses API 项目形态（`codex-rs/protocol/src/models.rs` 的 `ResponseItem::FunctionCall` 与 `FunctionCallOutput`：`arguments` 是 JSON 字符串，`call_id` 是字符串）。请求放在签名的 `Open` 里，响应放在 executor 签名的信封里（7.5）：

```json
{ "type": "function_call", "call_id": "c_01", "name": "exec_command",
  "arguments": "{\"cmd\":\"lark-cli msg send --to ops --text hi\",\"workdir\":\"/Users/me/work\",\"yield_time_ms\":10000}" }
```

```json
{ "type": "function_call_output", "call_id": "c_01",
  "output": "Wall time: 0.8000 seconds\nProcess exited with code 0\nOutput:\nsent\n" }
```

`output` 是文本，格式与 Codex 发给模型的一致（`codex-rs/core/src/tools/context.rs` 的 `response_text`）：可选的 `Chunk ID:` 行、`Wall time: x.xxxx seconds`、`Process exited with code N` 或 `Process running with session ID N`、截断时的 `Original token count: N`、然后 `Output:` 和正文。agentd 的线上消息同时携带结构化字段（`output`、`wall_time_seconds`、`exit_code`、`session_id`、`chunk_id`、`original_token_count`，对应 `shell_spec.rs` 的 `unified_exec_output_schema`），由 submitter 渲染成文本并放进 MCP 的 structuredContent。

MVP 实现的两个工具，参数语义与 Codex 的 `codex-rs/core/src/tools/handlers/shell_spec.rs` 一致，但只接受下表列出的参数：

| 工具 | 接受的参数 | 不接受 |
| --- | --- | --- |
| `exec_command` | `cmd`（必填）、`workdir`、`tty`（默认 false）、`yield_time_ms`（默认 10000，范围 250 到 30000）、`max_output_tokens`（默认 10000） | `shell`、`login`（调用方不能选解释器）、`environment_id`、`justification`、`sandbox_permissions`、`additional_permissions`、`prefix_rule` |
| `write_stdin` | `session_id`（必填，整数）、`chars`（空串表示只轮询）、`yield_time_ms`（非空写入默认 250、上限 30000；空轮询默认 5000、上限 300000）、`max_output_tokens` | 无 |

- 任务是请求响应式：一条 `task` 流承载一次 tool call，流关闭即结束。长任务靠 `session_id` 分多次调用，和 Codex 的 unified exec 一样。
- 不限定工具名集合：`name` 是任意字符串，executor 对不认识的工具回错误；后续可加 `apply_patch`、executor 侧 MCP 工具等，协议不变。
- 执行语义的差异只有一处：命令不经 shell（5.6）。其余超时、截断、`chars` 的编码沿用 Codex 的行为。

### 7.7 来自 Xray 的流拼接经验

Xray-core v26.10.21（提交 1b1647c）里与「把一条 TCP 连接嗅探后经中继拼到另一端」直接相关的实现和坑，按主题整理，行号以该版本为准；每条后面是 agentd 的对应决定。

**嗅探与首段数据回放**（`app/dispatcher/default.go`、`common/protocol/tls/sniff.go`）

- 嗅探循环的总预算是 200 ms（`default.go:391`），但最多只读两次：读到空或 `ErrNoClue`（record 不完整）各算一次尝试，`totalAttempt >= 2` 即放弃（`default.go:409-421`）。TLS 嗅探只解析第一个 record，record 不完整返回 `ErrNoClue`（`sniff.go:142-148`）。后果：Chrome 启用 ML-KEM 后 ClientHello 约 1.8 KB、跨两个 TCP 段，第二段必须在第二次读之前到达；三段以上（小 MSS 的隧道、后量子加 ECH）静默失败，连接按 IP 直连，用户无感。
  agentd：按 TLS record 头的长度字段累积到 `5+len` 字节为止，只受 16 KiB 和 200 ms 两个上限约束，不数尝试次数。
- 首段数据不是「重新写出去」，而是留在 `cachedReader` 的缓存里，出站第一次读先把缓存读走（`default.go:52-72, 294, 349`）；`Interrupt()` 释放缓存（`83-92`）。
  agentd：ingress 的首段缓存同样作为流上的第一条数据发出，保留到收到 Ack 为止（6.5）。
- 两条读路径的超时语义不同：pipe 路径超时返回 `buf.ErrReadTimeout` 使嗅探中止（`transport/pipe/impl.go:108-126`）；dokodemo / socks 路径用 `TimeoutWrapperReader` 把挂起的读放进 goroutine，超时返回空而不丢字节（`common/buf/io.go:31-78`）。
  agentd：只用一种读法：带截止时间的读，超时不丢已读字节。
- `routeOnly` 让嗅探结果只用于路由而仍按原 IP 拨号（`default.go:311-315`）。
  agentd：不存在这个选择，egress 一律按域名拨号，IP 根本不传过去。

**对拷、半关闭与计时器**（`common/buf/copy.go`、`proxy/freedom/freedom.go`、`features/policy/policy.go`）

- Xray 没有任何 `CloseWrite`：一个方向读到 EOF 后，另一个方向只剩 `UplinkOnly` / `DownlinkOnly` 默认 1 秒的空闲时间（`policy.go:125-142`；`freedom.go:390-391, 419, 427`），然后整条连接 `Close`（`freedom.go:372`）。流式响应因为计时器被活动刷新而存活，但需要收到 EOF 才开始回应、或请求结束后超过 1 秒才出第一个字节的服务端会被切断。`task.Run` 在任一方向出错时返回，另一方向在途的数据被丢弃（`common/task/task.go:20-64`）。
  agentd：真正的按方向半关闭。yamux 流的 `Close()` 是 FIN、仍可继续读；egress 把它映射为 `TCPConn.CloseWrite`；每个方向一个空闲计时器；两个方向都 FIN 之后才短暂排空并关闭。
- 默认 `Handshake` 60 秒的注释说明是为了和 nginx 的 `client_header_timeout` 一致，避免暴露服务端身份（`policy.go:128-129`）；`ConnectionIdle` 300 秒。
  agentd：会话握手 5 秒上限（8.7）；流的空闲超时按协议区分：tls 300 秒，ssh 不限（交互 shell 长时间无数据是常态，靠会话保活和拨出连接的 TCP keepalive）。
- splice 零拷贝只在 Linux、两侧都是裸 TCP 且没有任何用户态层时才启用，需要一个三态标志跟踪（`proxy/proxy.go:733-818`），启用后把空闲计时器调到 24 小时（`774-777`）。
  agentd：经 yamux 和 Noise 不可能 splice，按用户态拷贝做预算，每次读 64 KiB（Xray 的 ReadV 最多一次 8 个 8 KiB 缓冲，`common/buf/readv_reader.go:23-37`）。
- pipe 的 `Close` 让读方排空后结束，`Interrupt` 丢弃缓冲（`transport/pipe/impl.go:176-209`）。
  agentd：同样区分优雅关闭（FIN，排空）与 RESET（丢弃），分别映射到 yamux 的 `Close()` 与 `Reset()`。

**WebSocket**（`transport/internet/websocket/`）

- 每次 `Write` 一条二进制消息（`connection.go:75-80`），多缓冲写先 `buf.Compact` 合并到 8 KiB 以内再逐条发（`82-87`）；gorilla 的写不是并发安全的，Xray 依赖单一写者。
  agentd：会话层单一写 goroutine，把同一时刻待发的 Noise 帧合并成一条 WebSocket 消息。
- 心跳是可选的，只发 Ping、不处理 Pong、没有读截止时间（`connection.go:25-35`）。
  agentd：保活用 yamux 的 ping/pong（它检查应答），并给底层连接设读截止时间。
- 早期数据：把第一次写的前 `Ed` 字节 base64url 放进 `Sec-WebSocket-Protocol` 头，服务端解出来接到流前面（`dialer.go:143-146, 189-209`；`hub.go:55-75`）。
  agentd：阶段 4 的优化项：把 Noise 握手第一条消息放进 WebSocket 握手请求头，省一个 RTT。Tailscale ts2021 用 `X-Tailscale-Handshake` 头做同一件事。
- websocket/ 目录里没有任何 Cloudflare 相关的注释或特殊处理，CDN 的限制全靠外部实测。

**XHTTP**（`transport/internet/splithttp/`）

- 默认模式 `packet-up`（`dialer.go:332-341`）：下行一条 GET，上行分片 POST，每片 `scMaxEachPostBytes` 默认 1,000,000 字节、间隔 `scMinPostsIntervalMs` 默认 30 ms、带序号（`config.go:140-160`；`dialer.go:503-508`）；服务端用堆重排，缓冲 `scMaxBufferedPosts` 默认 30 片，超出即断连并「希望应用重试」（`upload_queue.go:103-110`）。注释直说：不把多次 `Write` 合并成大 POST「带宽会极其有限」（`dialer.go:465-482`）。
- 上下行两半靠路径里的 `sessionId` 关联，会话存在进程内的 `sync.Map`，30 秒内没等到 GET 即回收（`hub.go:41-94`）。
  agentd：XHTTP 只作回退；agentserver 多实例部署时负载均衡必须按会话 ID 保持亲和，否则 GET 找不到它的 POST。
- 为了让 CDN 和反向代理不缓冲：`X-Accel-Buffering: no`、`Cache-Control: no-store`、下行 `Content-Type: text/event-stream`、流式请求 `application/grpc`（`hub.go:216-217, 357-367`；`config.go:326-328`）；HTTP/1.1 关闭 keep-alive，因为「chunked 下载加 KeepAlive 有 bug」（`dialer.go:270-273`）。
  agentd：移植 XHTTP 时连同这些头一起带上。
- `xmux` 的多连接参数默认全为 0，即一条 H2/H3 连接复用一切（`config.go:430-483`）。

**HTTP Upgrade**（`transport/internet/httpupgrade/`）

- 客户端发的就是 WebSocket 握手头（`Upgrade: websocket`、`Sec-WebSocket-Key`、`Sec-WebSocket-Version: 13`，`dialer.go:99-110`），服务端回 101 并算 `Sec-WebSocket-Accept`（`hub.go:86-90`），之后裸字节、无帧（`connection.go:5-19`）。
- 服务端用 `bufio` 读请求后把裸 `conn` 交给上层，bufio 预读的字节被丢弃（`hub.go:51-55, 103`）；TLS 上每次读一个 record 所以碰巧没事，明文加早期数据时是竞态。
  agentd：若实现 HTTP Upgrade，服务端必须把 bufio 剩余字节接到流前面；它能否过 Cloudflare 需实测（第 10 节第 15 条）。

**Mux.Cool**（`common/mux/`）

- 帧：`2B 长度 | 2B 会话 ID | 1B 状态（New / Keep / End / KeepAlive）| 1B 选项`，New 帧带目标地址（`frame.go:19-56`）；数据按 8 KiB 分块（`writer.go:104-116`）。
- 没有流控：解复用是一个循环，把每个 Keep 拷进对应会话的 pipe，pipe 满则整个循环阻塞（`client.go:359-365`；`transport/pipe/impl.go:156-167`），一个慢接收方拖住同一连接上的所有子连接。
- 没有半关闭：收到 End 同时关两个方向（`session.go:171-204`）；KeepAlive 帧只解析从不发送；会话 ID 16 位递增不复用（`session.go:65-69`）；一个 worker 最多 128 个会话、默认并发 8（`app/proxyman/outbound/handler.go:120-142`）。
- 打开与首段数据合并：`writeFirstPayload` 最多等 100 ms 把第一段数据和 New 帧放在一起（`client.go:246-257`）。
- 与 XTLS Vision 不兼容的原因在代码里：Vision 要看到单条 TCP 连接的 TLS record 边界才能判断内层 TLS 并切到裸拷贝，mux 抹掉了这些边界（`proxy/vless/inbound/inbound.go:557-559, 178-189`）。
  agentd：这正是选 yamux 而不是自研 Mux.Cool 式协议的理由：每流窗口解决队头阻塞，FIN 与 RST 分开，ping 有应答，流 ID 32 位。要自己补的是：Open 头部与首段数据在同一帧发出；RESET 之后继续读到对端确认（排空）；每流缓冲有界。
- yamux 自己的坑：`ConnectionWriteTimeout` 默认 10 秒，底层连接写阻塞超时会关掉整条会话（hashicorp/yamux `session.go:349-372, 472-474`；go-yamux `session.go:569-592, 680-686`）；流级写超时只返回给该流，对端的读会一直挂着，应用必须在写错误后显式关闭或 Reset 流（hashicorp/yamux issue #142）。
  agentd：写超时调到 30 秒并按实测调整；所有写错误路径都以 `Reset()` 收尾。

**其他**

- freedom 按域名拨号，解析只用于评估最终路由（`freedom.go:294-339`）；Happy Eyeballs 是可选项（`transport/internet/dialer.go:262-266`）。agentd：egress 按域名拨号，用 Go 标准库自带的 Happy Eyeballs。
- 从不动 `TCP_NODELAY`，沿用 Go 的默认开启；拨号超时 16 秒，TCP keepalive 45 秒（`transport/internet/system_dialer.go:103-131`）。agentd：拨出连接开启 keepalive，SSH 的交互体验依赖它和 NODELAY。
- 多缓冲写用 `net.Buffers.WriteTo`（writev）（`common/buf/writer.go:22-66`）；缓冲池 8 KiB（`common/buf/buffer.go:13`）。

### 7.8 P2P 直连

MVP 的数据面全部经 relay 中继。P2P 让两个节点在 UDP 打洞成功后直接建立会话，数据面不再经过 relay；控制消息始终经 relay 的控制流到 agentserver；转发的对象不变，仍然是 TLS、SSH 和任务。协议层的名字、编号与报文格式在协议规范 2.6 预留，实现放在阶段 5。

**加入与否是节点自己的选择。** 节点配置 `p2p.enabled`，默认关闭。开启意味着三件事：向 agentserver 上报自己的候选地址、接受别人的直连邀请、在需要时发起直连。两端都开启才会尝试直连；任一方关闭就永远走中继，对方感知不到差别。关闭的节点不向任何人暴露自己的 IP，也保留 agentserver 转发预检这道闸。

**发现与信令**（agentserver 作会合点，不参与数据）：

- 候选地址三类：本机接口地址（host）；经 STUN 得到的反射地址（server-reflexive），STUN 服务器可配，默认用 relay 自带的 UDP 反射端口，relay 藏在 CDN 后面时换成公共 STUN；后续可加 NAT-PMP / PCP / UPnP 的映射地址。
- 节点在开启 P2P、网络变化、映射刷新时发 `P2PCandidates`。agentserver 只保存，不进目录，不广播。
- 触发：A 向 B 开流时若还没有直连会话且双方都开启，A 发 `P2PConnect{to: B}`。agentserver 校验双方都开启、A 对 B 至少有一条 allow（与转发预检同源），然后向双方发 `P2PInvite`：对方身份与候选地址、一次性 16 字节打洞 nonce、谁是会话发起方（固定规则：公钥字节序较小的一方作 Noise 发起方）。候选地址只在这一刻、只给通过了预检的对端。
- 打洞：双方收到邀请后同时向对方全部候选地址发探测报文（魔数 + nonce + 自身公钥前 8 字节），每 100 毫秒一轮、持续 5 秒；收到带正确 nonce 的回应即选定地址对，发起方在该地址对上建 QUIC 连接。失败则发 `P2PResult{failed}`，退避后可重试，期间一直走中继。两侧都是对称 NAT 时基本失败，这是预期行为；端口预测不做。

**直连会话**：

- transport `p2p`：QUIC（quic-go），一条双向 QUIC 流作为字节流 `Conn`，与 WebSocket 等并列。QUIC 自带的 TLS 用临时自签证书且不校验，认证完全靠其上的 Noise_IK，分层与中继会话完全一致，代价是双重加密；QUIC 只负责可靠传输、拥塞控制和 NAT 映射保活。
- Noise_IK：发起方用对端的派生 X25519 公钥（来自目录），prologue 同为 `agentd/1`，握手载荷用同样的 `ClientHello` / `ServerHello`，没有加入令牌和建议名字；yamux 参数相同，保活 25 秒以兼顾 NAT 映射；没有控制流，`KIND_CONTROL` 的 `Open` 回 `BAD_REQUEST`。
- 流的放置：新流优先放到已就绪的直连会话。任务与 ssh 服务的目的节点发起方本来就知道（`task.executor`、服务表）；egress 流的出口由控制面选，发起方只从该域名上一次经中继的 `Ack.responder` 得知出口，之后同一域名的新流可以放到与该出口的直连会话上，分流表版本变化时清掉这份记忆；HTTP 服务始终经 relay 的边缘。直连失败或断开时新流回到中继，直连上已有的流 RST、由应用重连；流不在两条路径间迁移。直连时 `Open.to` 就是对端自己。
- 验证与授权与中继路径完全相同：`Open` 的签名、成员证书、清单 B、策略；`RelayInfo` 缺席，接收方不得依赖它。这正是成员证书由成员自己携带的原因（6.8）。

**安全与隐私**：

- 候选地址只给预检通过的对端；关闭 P2P 的节点不暴露 IP。
- 探测报文带邀请里的 nonce，第三方不能诱导节点向任意地址发包；真正的身份认证在 Noise 握手。
- 直连绕过了 relay 的转发预检，接收节点是唯一判定点；不接受这一点的节点关闭 P2P 即可。
- relay 与 agentserver 都看不到直连上的数据和元数据（域名、任务），agentserver 只知道两个节点建立了直连；该路径的审计只在两端节点上。

**可观测性**：`agentd status` 列出直连会话与选定的地址对；决策日志记录每条流走的路径（relay / direct）；`P2PResult` 让 agentserver 统计打洞成功率。

**不做的**：对称 NAT 的端口预测、第三方中转（agentserver 本身就是中继）、UDP 数据面、流迁移。
---

## 8. 安全模型

### 8.1 信任边界

- agentserver 是受信的管理平台与后端：它持有 DNS 凭据、路由表、目录、组与 workspace 密钥、中央策略、自管节点上报的策略和服务证书，能改受管节点的策略、签发成员证书与 relay 证书、指派 relay、决定每条流的出口和预检结果；它不在数据路径上，看不到任何流。它不能冒充任何节点，因为节点私钥只在节点上。
- relay 是受信的接入点、转发者、粗粒度授权的执行点和 HTTP 服务边缘：它终结节点的会话与控制流，按后端的答案工作，能看到控制消息的内容（含加入令牌、`Advertise`）、每条流的头部、任务的请求与输出、被转发连接的字节（TLS / SSH 密文），能拒绝服务，能看到和篡改 HTTP 服务的明文。它不能冒充控制面：发给节点的控制消息都带 workspace 密钥的签名，relay 没有这把私钥，改不了策略、目录、证书和路由；它不能冒充任何节点，不能篡改 `Open` 和任务内容，不能把任务送给 `task.executor` 之外的 executor、把服务流送给别的节点，因为这些都由发起方和 executor 的签名保证；egress 流的出口由后端选，被攻破的 relay 能改的只是在愿意接受该发起方的出口之间换一个。它能伪造节点发给后端的消息（冒名注册服务、替自管节点上报更宽的策略），影响止于预检，节点自己的策略仍是最后一道闸。
- Cloudflare（若使用）只看到节点与 relay 之间的 Noise 密文和连接元数据；对向 `*` 开放且走橙云的服务它处于与 relay 相同的位置。
- 节点之间互不信任，提供侧只相信验签得到的对端身份，并用自己的策略决定是否服务；后端的预检是在它之前的一道闸，不是替代。
- HTTP 服务是唯一把授权完全交给服务端的地方：访问者是否被允许由后端判定、relay 的边缘执行并注入身份头。需要端到端保密的服务用 `proto: ssh` 承载自己的加密。

### 8.2 节点身份、加入与下发

- 节点首次运行生成 Ed25519 密钥对，存在实例目录的 `node.key`（默认 `~/.agentd/node.key`，0600），握手用的 X25519 密钥按需派生、不单独保存。密钥形式的名字 `agentd://<公钥>` 是身份，名字形式是目录里的别名（3.1）。换机器就是换公钥；名字可以在 agentserver 上重新分配给新公钥，但其他节点规则里写的旧公钥不会跟着变，提供侧会在日志里告警「目录里 laptop 的公钥与规则里写的不同」并要求改规则。这是有意的：换了设备必须重新信任。
- 加入流程见 4.5。它的安全性质：令牌一次性、短 TTL、绑定 workspace 与角色上限，服务端只存哈希；令牌只出现在加入链接和 Noise 第一条消息的加密载荷里，CDN 看不到；链接里带 workspace 公钥，首次接触就能认证 relay（凭 workspace 密钥签的证书）并验所有控制消息的签名；之后每次建会话只凭密钥握手，没有长期 bearer 凭据；`agentd://` 不是浏览器会发到网上的协议，链接误贴进浏览器不会泄露，`agentd join` 也可从标准输入读链接以免进 shell 历史。
- 角色上限写在目录里，agentserver 在 `Advertise` 和开流时都校验：被攻破的 `dorm` 不能宣告成 executor，也不能以 ingress 身份开流。
- 下发开关：策略的来源由每个提供侧角色的 `policy_source` 二选一（6.7），`server` 时接受 agentserver 渲染下发的策略、本地 deny 仍生效，`local` 时忽略下发。分流表（只有 ingress 用）和目录（只用于显示和复制公钥）总是接受，它们不授予任何权限，所以没有别的开关。
- 分组与 workspace 的信任：策略里只有公钥；要让一个组或整个 workspace 的成员获得授权，就把组公钥或 workspace 公钥写进 `public_key`，请求方凭 agentserver 签发的成员证书证明归属（6.8）。没有「信任 agentserver 目录」的开关。

### 8.3 策略执行点

| 层 | 检查 | 失败结果 |
| --- | --- | --- |
| ingress | 只把分流表判为 `via` 的域名和服务域名交给下一跳；对 `Open` 签名；不知道出口 | 其余直连 |
| relay（本地校验 + 控制面答案） | 验签且 `from` 与会话一致、`to` 是自己；时间戳窗口；同 workspace；向控制面查询（答案缓存）：先按路由表或服务表选出目的节点（任务按 `task.executor`），再查双方角色，再用目的节点的策略预检发起方，HTTP 服务的访问者（含公网访问者）；目的节点在线且服务就绪；最后转发 | Ack 错误 |
| egress | 先验签、`to` 是所连 relay 或自己、防重放；再校验发起者（签名公钥或有效成员证书的签发者等于某条规则的 public_key）与动作（(谁, proto, 域名, 端口) 策略）；最后拨号，并复核首段数据与声明协议一致 | Ack 错误或 RESET |
| service（ssh） | 验签；(谁, service 名) 策略 | Ack 错误 |
| service（http） | 节点侧不再检查身份，只做反向代理 | — |
| executor | 先验签（含整个 function_call）、`task.executor` 是自己、`to` 是所连 relay 或自己、防重放；再校验发起者（签名公钥或有效成员证书的签发者等于某条规则的 public_key）与动作（去重；工具名；(谁, argv 前缀) 策略；stdin / shell 开关）；最后执行：并发与超时；对输出签名 | tool call 错误输出 |
| submitter | 验证 executor 对输出的签名 | 结果未知 |

### 8.4 agentserver 与 relay 的可见性

| 谁 | 看得到 | 看不到 |
| --- | --- | --- |
| relay | 连接它的节点的公钥、名字、角色与在线状态；控制流上的全部消息（它送达或转交的），包括加入令牌；每条 `tcp` 流的协议、域名、端口、来源、出口、字节数、时间，以及字节本身（TLS / SSH 密文）；每个 `task` 流的来源、目标、时间，以及 `function_call` 的参数与输出；HTTP 服务的完整明文（它是边缘） | 节点私钥与 agentserver 私钥，因而不能冒充节点或控制面、不能伪造或篡改签过名的 `Open`、任务、输出与控制消息；不能把任务或服务流送到签名绑定之外的节点；目录、路由表与策略的全貌，它只拿得到问过的答案和经手的消息 |
| agentserver | 目录、分组、路由表、策略、服务定义、executor 工具清单、各节点的在线状态与所连 relay、P2P 候选地址、每条经 relay 查询的流的元数据（来源、协议、域名、目的） | 任何数据面的字节：它不在数据路径上 |
| Cloudflare | 节点与 relay 之间连接的元数据 | 内容，只有 Noise 密文 |

### 8.5 executor 隔离

- 主进程以登录用户身份运行（macOS LaunchAgent、Linux `systemd --user`），executor 永远不以 root 执行；TUN 所需的特权在 elevator 里，elevator 不执行任何命令。
- 命令不经 shell，策略匹配的 argv 就是实际 exec 的 argv；`argv[0]` 只能是某条 allow 规则里出现过的程序，执行路径取自规则而不是调用方。
- `write_stdin` 和完整 shell 都是策略项上的显式开关，默认关闭。
- `workdir` 限定在配置的目录下；环境变量只透传白名单；并发、超时、输出大小都有上限。
- 审计日志追加写入，记录发起方公钥与名字、`call_id`、argv、起止时间、退出码。
- 白名单的实际边界取决于被放行程序自身的能力：`lark-cli` 若有执行脚本或读任意文件的子命令，策略就要把这些子命令排除在前缀之外。文档和 CLI 对 `shell: true` 与 `public_key: "*"` 给出明确警告。
- 后续：macOS `sandbox-exec` / Linux namespaces 进一步限制文件系统与网络。

### 8.6 密钥与凭据

| 密钥 | 在哪 | 用途 | 泄露后果 |
| --- | --- | --- | --- |
| 节点 Ed25519 私钥 | 节点，0600 | 给 `Open`、任务、输出签名；派生 X25519 密钥与 relay 和 agentserver 握手 | 攻击者可冒充该节点；在 agentserver 上移除公钥即吊销 |
| agentserver Ed25519 私钥 | agentserver 状态库 | 派生 X25519 密钥与 relay 握手 | 攻击者可冒充控制面对 relay 说话（给出任意查询答案、改派），但签不了发给节点的控制消息；轮换只需 relay 更新 `control.public_key` |
| relay Ed25519 私钥 | relay 主机 | 派生 X25519 密钥与节点和控制面握手；签 edge 发起的流 | 攻击者可冒充该 relay（在证书有效期内）、读它能读的一切、冒充 edge 向服务节点发请求，但不能伪造节点或 agentserver 的签名；在 agentserver 上移除该 relay、不再续签证书并改派即吊销 |
| 组私钥 | agentserver 状态库，加密 | 签发组成员证书 | 攻击者可伪造该组成员资格；轮换组密钥并让自管节点改规则 |
| workspace 私钥 | agentserver 状态库，加密 | 签发 workspace 成员证书、发给成员的控制消息和 relay 证书 | 攻击者可向该 workspace 的成员下发任意策略、目录与证书，也可伪造成员资格；轮换需要全部成员更新 `workspace.public_key`（等于重新 join） |
| workspace 通配证书私钥 | agentserver 状态库（加密）；服务该 workspace 的 relay 内存 | relay 的边缘终结 HTTP 服务的 TLS | 攻击者可冒充该 workspace 的所有 HTTP 服务；吊销并重签 |
| DNS 提供商凭据 | agentserver，加密 | ACME DNS-01、写服务记录 | 攻击者可改 zone 记录、签任意子域证书；用只限 zone 的最小权限令牌 |
| 加入令牌 | 一次性，短 TTL | 把公钥登记进目录 | 攻击者以该名字加入；角色上限限制损失 |
| ACME 账户密钥 | agentserver 状态库 | 续期 | 影响很小，可重新注册 |

`agentserver backup` 导出的状态库包含以上除节点私钥外的全部密钥，备份本身要加密保存。

### 8.7 威胁与应对

| 威胁 | 后果 | 应对 |
| --- | --- | --- |
| relay 被攻破 | 看到流元数据、任务内容和被转发的密文；拒绝服务；冒充或监听它服务的 HTTP 服务；向 `tcp` 流注入字节（只会破坏连接） | 不能冒充节点、篡改任务、伪造输出、把任务或服务流送错节点：开流与输出都有签名且绑定 `from`、`to`、`task.executor` 与 `domain`；egress 流最多在愿意接受该发起方的出口之间换一个，出口策略仍把关；看得到控制消息与加入令牌，但伪造不了 agentserver 签名的策略、目录与证书，只拿得到它问过的后端答案；在 agentserver 上移除并改派即隔离 |
| agentserver 被攻破 | 改宽受管节点的策略；给任意公钥签发任意组的成员证书；给恶意 relay 签证书并改派；改路由表让流从别的出口出去 | 规则里只写节点公钥的自管节点不受影响；写了组或 workspace 公钥的节点会受影响，这是选择信任 agentserver 的代价；本地 deny 刹车仍生效；它读不到任何数据面内容，也不能伪造节点签名 |
| CDN 被攻破 | 看到连接元数据 | 节点与 relay 之间是 Noise 密文，CDN 读不到任何内容，也不能冒充双方 |
| 消费侧节点（笔记本）被攻破 | 可使用 workspace 内所有向它开放的提供侧能力 | 提供侧策略限制损失：egress 只放行字面列出的域名和协议，executor 只放行 argv 前缀，且 stdin 和 shell 默认关闭 |
| 越权使用 | 被攻破的 laptop 向不该用的 executor 发任务 | 控制面用 executor 的策略预检先拒绝一次，提供侧策略再拒绝一次 |
| 成员离组后证书仍在有效期内 | 最多 1 小时的残留权限 | 吊销记录即时推送到全部节点；证书有效期可按 workspace 调短 |
| ingress 伪报域名或协议 | 借 campus 规则访问任意站点，或借 tls 规则跑 ssh | egress 复核 SNI 与头部一致、SSH 首行以 `SSH-` 开头 |
| 提供侧节点被攻破 | 只能响应请求 | 角色上限在开流时校验，它无法以消费侧身份开流 |
| 加入令牌泄漏（含被攻破的 relay 看到令牌） | 攻击者以该名字加入 | 单次、短 TTL、角色上限、带外传递；relay 与 agentserver 同属运营方；后续可改为封给 workspace 公钥的密文 |
| 名字重新分配 | 新机器继承旧授权 | 策略认公钥不认名字；目录里的新公钥与规则里写的不同时告警 |
| 重放 `Open` 或握手第一条消息 | 重复执行命令或多拨一次号 | 会话握手：时间戳单调递增；`Open`：5 分钟窗口加 (from, nonce) 去重，任务再按 (from, call_id) 去重 |
| 成员节点注入提示词 | 借工具描述影响 AI agent | 描述限长并标注来源节点 |
| 公网扫描 agentserver 或 relay | 消耗资源 | 未完成握手的连接 5 秒断开并限速；CDN 在前面挡一层 |
| 自环 | ingress+egress 同机时流量被自己捕获 | 所有 agentd 自身出站连接绑定物理接口 |

---

## 9. 配置、CLI 与运维

### 9.1 agentserver 与 agentrelay

```yaml
# /etc/agentserver/config.yaml（控制面，管理平台；只需对 relay 与管理员可达）
apiVersion: agentd/v1
kind: AgentserverConfiguration
domain: agentsrv.example.com
listen: ":443"                                      # relay 会话的端点；可以是内网地址
key_file: /var/lib/agentserver/server.key          # 可选：agentserver 的 Ed25519 静态私钥，只用于 relay 会话；省略时密封保存在状态库
tls: { mode: acme }                                 # 自身域名的证书；内网部署可用自签并让 relay 钉住
transports: { ws: /ws, xhttp: /x, httpupgrade: /up }   # relay 会话的 transport 端点
admin_listen: "127.0.0.1:7800"                      # admin API（docs/agentserver-openapi.yaml），CLI 经它操作；远程管理放 SSH 隧道或反向代理后
admin_token_env: AGENTSERVER_ADMIN_TOKEN             # admin API 的 Bearer 令牌所在环境变量
database: { url_env: AGENTSERVER_DATABASE_URL }     # PostgreSQL：目录、路由表、策略、证书、令牌
state_key_env: AGENTSERVER_STATE_KEY                # 私钥密封用的密钥（取 SHA-256），证书私钥与各类私钥加密存放
relay_join_token_env: AGENTSERVER_RELAY_TOKEN       # 可选：relay 自注册的长期引导令牌（helm chart 用它）
relay_cert_ttl: 720h                                # relay 证书有效期，到一半时续签；每个 (relay, workspace) 一张，用 workspace 密钥签
dns_providers:
  cf-main: { provider: cloudflare, token_env: CF_API_TOKEN }   # agentsrv.example.com 所在 zone
```

```yaml
# /etc/agentrelay/config.yaml（数据面，节点唯一直接连接的服务端；与控制面分开部署，可多实例）
apiVersion: agentd/v1
kind: AgentrelayConfiguration
name: relay-hk
domain: relay-hk.agentsrv.example.com
listen: ":443"
key_file: /var/lib/agentrelay/relay.key              # relay 的 Ed25519 静态私钥，公钥用 agentserver relay add 注册
control: { url: https://agentsrv.example.com, public_key: "Ws3kL…" }   # 控制面；public_key 可省略（经校验的 TLS 从 /.well-known/agentserver 取得）；它用各 workspace 的密钥签发并推送本 relay 的证书
tls: { mode: acme }                                   # 自身域名的证书；服务域名的证书由控制面下发、只在内存
transports: { ws: /ws, xhttp: /x, httpupgrade: /up }  # 节点会话的端点
cache: { ttl: 60s, max_entries: 100000 }              # 控制面答案的缓存（5.8）
stun: ":3478"                                         # P2P 反射地址（7.8）
```

```yaml
# workspace home（也可用 agentserver CLI 逐条管理）
apiVersion: agentd/v1
kind: Workspace
name: home
base_domain: home.agentsrv.example.com     # 自定义时写 home.example.org 并指定它所在 zone 的 dns_provider
dns_provider: cf-main
relay: relay-hk                            # 指派给该 workspace 的 relay，成员都连它
publish_dns: false                         # true 时写入 *.home.agentsrv.example.com 指向 relay，供有 public_key "*" 规则的服务公开访问
routes:                                    # 路由表（6.5）：(源, 协议, 域名) → 目的；只在 agentserver 上，ingress 只收去掉目的的分流表
  - { from: group:pc,  proto: [tls, ssh], domains: [{ kind: suffix, value: ucas.edu.cn }, { kind: suffix, value: ucas.ac.cn }], to: dorm }
  - { from: workspace, proto: [tls],      domains: [{ kind: domain, value: login.ucas.edu.cn }],                to: direct }
default: direct
groups:                                    # 实例组，每个组有 agentserver 保管的密钥对
  pc: [laptop, laptop2]
policies:                                  # 中央策略，只对 policy_source: server 的角色生效，并用于转发预检与 HTTP 服务的边缘判定（6.8）
  - subjects: [group:pc]
    allow:
      - { egress: dorm, proto: tls, domains: [{ kind: suffix, value: ucas.edu.cn }, { kind: suffix, value: ucas.ac.cn }] }
      - { egress: dorm, proto: ssh, domains: [{ kind: suffix, value: ucas.edu.cn }, { kind: suffix, value: ucas.ac.cn }] }
      - { exec: office, argv: ["lark-cli", "msg"] }
      - { exec: office, argv: ["lark-cli", "doc"], stdin: true }
      - { service: nas }
      - { service: homepc }
  - subjects: [workspace]
    deny:
      - { egress: dorm, proto: tls, domains: [{ kind: domain, value: login.ucas.edu.cn }] }
  - subjects: [public]
    allow: [{ service: grafana }]
```

### 9.2 agentd

agentd 的全部文件集中在 `~/.agentd/`（Windows 为 `%USERPROFILE%\.agentd\`），目录权限 0700。完整的参考配置（全部字段、默认值与说明）见 `docs/agentd-config.yaml`，下面只给四个典型节点的最小配置。所有配置文件都以 k8s 风格的 `apiVersion: agentd/v1` 和 `kind` 开头，四种 kind：`AgentdConfiguration`、`AgentserverConfiguration`、`AgentrelayConfiguration`、`Workspace`；字段像 kubelet / kubeadm 的组件配置一样直接放在顶层，不套 `spec`。一台设备可以跑多个实例：默认实例直接用 `~/.agentd/`，其他实例各用 `~/.agentd/instances/<实例名>/`，布局相同；`agentd -i <实例名>`（或 `AGENTD_INSTANCE`）选择实例，所有子命令都带这个选项；`AGENTD_HOME` 或 `--home` 可把某个实例的目录整个指到别处（系统服务等场景）。实例之间除了共享 elevator 没有任何共享状态：

```
~/.agentd/
  config.yaml      配置（下面的示例）
  node.key         Ed25519 私钥，0600，首次运行生成
  audit.log        executor 审计日志，追加写入（log.audit.path）
  agentd.sock      CLI 与守护进程通信的 unix socket（Windows 用命名管道 \\.\pipe\agentd）
  state/           运行时状态：fake-IP 映射、分流表与目录的副本、relay 证书、nonce 缓存等，可删除
  logs/            守护进程日志（log.file）与决策日志（log.decision.path）
  instances/<名>/  其他实例，各自一套上面的文件（socket 也在各自目录下；Windows 命名管道为 \\.\pipe\agentd-<名>）
```

```yaml
# laptop：ingress + submitter（完整字段见 docs/agentd-config.yaml）
apiVersion: agentd/v1
kind: AgentdConfiguration
metadata: { name: laptop }
workspace:
  domain: home.agentsrv.example.com
  public_key: "Rt7aB…"                   # 本 workspace 的公钥：唯一信任根，来自加入链接；验 relay 证书、控制消息与 workspace 成员证书
  relay:                                 # 归属 workspace，由 agentserver 指派
    url: https://relay-hk.agentsrv.example.com   # 当前 relay 的 transport 端点；其余候选来自 Welcome.relays，缓存在 state/
    transport: { type: ws }              # ws（默认）/ xhttp / httpupgrade / auto
roles:
  ingress:
    enabled: true
    http:   { enabled: true, address: 127.0.0.1, port: 7890 }
    socks5: { enabled: true, address: 127.0.0.1, port: 7891 }
    tun:    { enabled: true }                 # 需要已安装 elevator；一台设备只能有一个实例开启；内置 DNS 随 TUN 启用
    fallback: direct                      # 目标离线、无路由或控制面不可达时回退直连
  submitter:
    enabled: true
    mcp: { address: 127.0.0.1, port: 7900 }
p2p:
  enabled: false                          # 加入 P2P 发现：上报候选地址、接受邀请、需要时发起；默认关闭（7.8）
```

```yaml
# dorm：egress
apiVersion: agentd/v1
kind: AgentdConfiguration
metadata: { name: dorm }
workspace: { domain: home.agentsrv.example.com, public_key: "Rt7aB…", relay: { url: https://relay-hk.agentsrv.example.com } }
roles:
  egress:
    enabled: true
    policy_source: local                                   # local（默认）或 server；server 时本地 allow 被忽略、deny 仍生效
    policies:                                              # public_key 直接写公钥（从 agentd peers 复制）或 "*"；一条规则一个协议；target 写字面模式
      - { public_key: "QmX9v…", action: allow, proto: tls, domains: [{ kind: suffix, value: ucas.edu.cn }, { kind: suffix, value: ucas.ac.cn }] }   # pc 组公钥：组成员凭证书通过
      - { public_key: "QmX9v…", action: allow, proto: ssh, domains: [{ kind: suffix, value: ucas.edu.cn }, { kind: suffix, value: ucas.ac.cn }] }
      - { public_key: "*",     action: deny,  proto: tls, domains: [{ kind: domain, value: login.ucas.edu.cn }] }
```

```yaml
# homepc：service
apiVersion: agentd/v1
kind: AgentdConfiguration
metadata: { name: homepc }
workspace: { domain: home.agentsrv.example.com, public_key: "Rt7aB…", relay: { url: https://relay-hk.agentsrv.example.com } }
roles:
  service:
    enabled: true
    servers:
      - { name: nas, target: { host: 127.0.0.1, port: 8080 } }                 # https://nas.home.agentsrv.example.com
      - { name: homepc, proto: ssh, target: { host: 127.0.0.1, port: 22 } }    # ssh homepc.home.agentsrv.example.com
    policies:
      - { public_key: "hC3Qm…", action: allow, service: nas }     # laptop 的公钥
      - { public_key: "hC3Qm…", action: allow, service: homepc }
```

```yaml
# office：executor，策略由 agentserver 接管
apiVersion: agentd/v1
kind: AgentdConfiguration
metadata: { name: office }
workspace: { domain: home.agentsrv.example.com, public_key: "Rt7aB…", relay: { url: https://relay-hk.agentsrv.example.com } }
roles:
  executor:
    enabled: true
    policy_source: server                 # 生效的 allow 来自 agentserver 的渲染结果（6.8）；本地只写 deny 作刹车
    description: 公司机器，已登录 lark-cli
    policies:
      - { public_key: "*", action: deny, shell: true }     # 刹车：这台机器永远不开 shell；能执行的程序由下发的 allow 规则决定
    workdir: /Users/me/work
```

同一台笔记本再加入公司的 workspace `work`：`agentd -i work join '<链接>'`，实例目录 `~/.agentd/instances/work/`，配置里 `http.port`、`socks5.port`、`mcp.port` 要与默认实例错开（如 7892 / 7893 / 7901），`tun.enabled` 保持 false（设备上只有默认实例持有 TUN）；`~/.ssh/config` 里对该 workspace 的域名写 `ProxyCommand agentd -i work connect %h %p`。

笔记本上的 `~/.ssh/config`：

```
Host *.home.agentsrv.example.com
  ProxyCommand agentd connect %h %p
```

### 9.3 CLI

```
agentd [-i <实例名>] <子命令>                   选择实例：省略即默认实例 ~/.agentd/，否则 ~/.agentd/instances/<实例名>/
agentd run                                     以当前用户前台运行守护进程
agentd service install|uninstall               安装为用户级服务（LaunchAgent / systemd --user；每个实例一个单元，名字带实例名）
agentd elevator install|uninstall              安装特权助手（LaunchDaemon / 系统 systemd 单元），仅 TUN 需要
agentd key show                                显示本节点的两个名字：agentd://<公钥> 与 agentd://<ws 域名>/<实例名>
agentd join <join-link> [--name <n>] [--replace]  加入 workspace（链接也可从标准输入读；令牌未定名字时默认用 hostname）
agentd leave                                   退出当前 workspace，保留密钥文件
agentd peers                                   查看目录里的成员、组与 workspace 的名字和公钥，供复制进规则的 public_key
agentd connect <host> <port>                   开一条 tcp 流并接到标准输入输出，供 ssh ProxyCommand 使用
agentd reload                                  重新加载本地配置与策略
agentd status                                  会话与所连 relay、在线节点、分流表版本、最近直连原因统计、时间戳拒绝
agentd routes                                  当前分流表与服务列表
agentd task exec <executor> -- <cmd>           exec_command
agentd task stdin <executor> <session_id> …    write_stdin
agentd mcp                                     stdio MCP server

agentserver run                                控制面
agentrelay run                                 数据面，配置见 9.1
agentserver key show                           显示 agentserver 公钥
agentserver workspace create|list|delete|set-relay|key <ws> [--base-domain …] [--dns-provider …] [--publish-dns] [--relay <name>]   key 显示 workspace 公钥（加入链接的 key、成员配置的 workspace.public_key）
agentserver relay add|remove|list <name> --public-key … --url … [--stun …]   注册 relay、签发 relay 证书并供 workspace 指派
agentserver token create --workspace <ws> [--name <node>] [--roles …] [--ttl 24h]   输出加入链接
agentserver token list|revoke --workspace <ws>
agentserver node list|remove|rename|set-roles --workspace <ws>
agentserver group create|delete|add|remove|list --workspace <ws>   组及其密钥；add / remove 管理成员
agentserver route add|remove|list --workspace <ws>   路由表（源、协议、域名、目的）
agentserver policy add|remove|list|replace --workspace <ws>   中央策略语句
agentserver service list --workspace <ws>      已注册的服务及状态
agentserver status                             relay 与节点的在线统计
agentserver cert list|renew --workspace <ws>
agentserver backup <file>
```

agentd 的 CLI 通过实例目录下的 `agentd.sock`（默认 `~/.agentd/agentd.sock`；Windows 用命名管道）和该实例的守护进程通信。agentserver 的 CLI 是 admin API 的封装，每个子命令对应一个操作，接口定义见 `docs/agentserver-openapi.yaml`（`agentserver backup` 例外，直接读状态库）。

### 9.4 技术选型（建议）

- 语言：Go，三个二进制 `agentd`、`agentserver`（控制面）与 `agentrelay`（数据面），共享内部包。
- 密码学：Noise 用 `github.com/flynn/noise` v1.1.0（`HandshakeIK`、`DH25519`、`CipherChaChaPoly`、`HashBLAKE2s`、`CipherState.Rekey()`、`MaxMsgLen = 65535`；更新慢，但 go-libp2p 在生产使用）。签名用标准库 `crypto/ed25519` 的 Ed25519ctx（`ed25519.Options{Context: …}`）；Ed25519 到 X25519 的派生用 `filippo.io/edwards25519`（公钥 `BytesMontgomery()`）加 SHA-512 clamp（私钥），与 libsodium 一致。密钥编码 base64url 无填充。
- transport：参考 Xray-core 的 `websocket`、`splithttp`、`httpupgrade` 实现，按需移植而不是整体依赖 Xray-core 模块。
- 嗅探：TLS 参考 `common/protocol/tls/sniff.go`，但它只解析第一个 TLS record，跨 record 和跨 TCP 段的累积要自己写；SSH 只看首行前缀；QUIC 参考 `common/protocol/quic/sniff.go`；整体流程参考 `app/dispatcher/default.go` 的嗅探分支（7.7）。
- fake-IP：参考 `app/dns/fakedns`，分配改为按域名哈希确定。
- TUN：gVisor netstack（TCP 与 UDP forwarder）+ `wireguard-go/tun`；DNS：`miekg/dns`；ACME：`golang.org/x/crypto/acme`（DNS-01 走 Cloudflare API；agentserver 与 relay 自身域名用 TLS-ALPN-01 的 autocert）；存储：PostgreSQL（pgx）；admin API：oapi-codegen 生成的 strict server，Web 控制台的类型、客户端与界面元数据由同一份 OpenAPI 生成；MCP：官方 Go SDK；多路复用：libp2p go-yamux v5（活跃维护，有 `Reset()`，窗口按 RTT 自动调整）；HTTP 反向代理：标准库 `httputil.ReverseProxy`；命令解析：`mvdan.cc/sh/v3/syntax`。
- 任务：Codex 的 tool schema、输出格式和 bash 白名单解析作为参考实现。
- 平台：macOS 与 Linux 先行，Windows（wintun）第四阶段。

建议的仓库布局：

```
cmd/agentd
cmd/agentserver
cmd/agentrelay
internal/transport     ws / xhttp / httpupgrade 的客户端与服务端，统一成一条字节流
internal/session       Noise_IK 会话、分帧、Rekey、yamux、保活、重连、版本协商；控制流与 Signed 信封的验签
internal/wire          控制消息、Open / Ack 与输出信封（protobuf）、Ed25519ctx 签名与验签、防重放窗口
internal/identity      节点 Ed25519 密钥与 X25519 派生、目录、join、relay 证书的验证与缓存
internal/sniff         TLS ClientHello / SSH 首行 / QUIC Initial 解析
internal/ingress       dispatcher、http、socks5、connect、tun（netstack）、dns（fake-IP）、决策日志
internal/elevator      特权助手：TUN 创建、路由、系统 DNS 接管与恢复、fd 传递
internal/egress        策略、解析、拨号、协议复核
internal/service       节点侧：HTTP 反向代理到目标、ssh 透传
internal/task          tool call 编解码、命令解析与策略、exec_command / write_stdin 执行器、去重
internal/mcp           submitter 的 MCP server 与动态工具
internal/control       coordinator、routing、policy 渲染与预检、成员证书、acme、relay 管理（证书、查询应答、节点消息处理、Signed 签名与送达、失效推送）、p2p 会合、admin api、store、backup
internal/relay         hub（节点会话）、control（控制流终结、消息转交）、forwarder、edge（TLS 终结、反向代理、身份头）、stun、relay 会话与答案缓存
internal/sim           单进程集成测试：N 个 agentd + 1 个 agentserver + 1 个 agentrelay
proto/agentd/v1        wire.proto：握手载荷、Open / Ack、任务结果、控制消息
docs/                  design.md、protocol.md
```

### 9.5 运维

- 日志：阶段 1 起每条连接和每次 tool call 都有结构化决策日志（域名来源、协议、分流表判定、实际服务的节点、动作、错误码、耗时），这是调试「为什么这条连接直连了」的唯一手段；指标接口阶段 4。
- 多实例：每个实例一个服务单元、一份日志和一个 socket，`agentd -i <名> status` 分别查看；升级二进制对所有实例同时生效。
- 配置热更新：`agentd reload` 或 SIGHUP 重新加载本地策略与服务定义，不断开会话。
- 时钟：Noise 第一条消息的时间戳、`Open` 签名的 5 分钟窗口、ACME、join TTL、证书有效期、审计日志依赖正确时间；启动时检查与 agentserver 的时钟偏差并告警。
- 协议演进：版本取交集，prologue 含大版本；未知控制消息忽略，未知流类型失败安全；protobuf 字段只增不改。
- 状态机：节点在 workspace 中的生命周期、会话与控制流、transport、流、任务、服务、成员证书、受管策略、relay 会话与缓存、P2P 的状态机在协议规范第 12 节，实现按它写显式的状态变量。
- 状态备份：`agentserver backup` 定期导出；状态库含服务器私钥、组与 workspace 私钥、证书私钥、ACME 账户密钥和目录，备份要加密。relay 没有持久状态，不需要备份。
- 密钥轮换：节点换密钥等于重新 join；agentserver 换密钥只需 relay 更新 `control.public_key`；workspace 换密钥需要全部成员更新 `workspace.public_key`（等于重新 join），提供一段双密钥并行期；relay 换密钥只需重新注册并续签证书，节点随 `Welcome.relays` 更新。
- 升级：agentserver 先升级并兼容旧版本区间，再升级 relay，最后升级节点。relay 会话断开期间控制流上没有新消息、数据流按缓存继续。

---

## 10. 待决问题

每条附建议：

1. 实现语言。建议 Go。
2. 目标平台。建议 macOS + Linux 先行。
3. 一把 Ed25519 密钥兼做签名和派生 X25519 握手密钥（当前方案，用户只要一份密钥对），还是每节点两把密钥？建议单密钥；若安全评审反对，改两把不影响对外名字。
4. 内置 DNS 对服务域名和分流表判为 `via` 的域名都返回 fake-IP，不提供「只给服务域名」的开关（否则校园网内网域名和 SSH 都用不了），是否接受？建议接受。
5. `policy_source` 默认 `local`，是否合适？建议是：新节点先自管，确认中央策略渲染无误后再切 `server`。
6. 成员证书有效期默认 1 小时、过半续发，成员离组后最多 1 小时残留（有吊销推送兜底），是否接受？建议接受。
7. HTTP 服务由 relay 的边缘终结 TLS，意味着 relay 能看到这些服务的明文，是否接受？建议接受（这是本轮反馈的决定），需要保密的用 `proto: ssh`。
8. `public_key: "*"` 的服务规则与 `publish_dns` 是否进 MVP？建议进阶段 1，实现成本很低。
9. 身份头的名字 `X-Agentd-Peer` / `X-Agentd-Peer-Key` 是否合适？建议先用，阶段 4 前定稿。
10. ingress DNS 剥离 HTTPS/SVCB 记录、对金丝雀域名返回 NXDOMAIN、RST 已知 DoH 端点，这三项是否接受？建议接受，均可配置关闭。
11. executor 不经 shell、`shell: true` 只对特定调用方显式开启，是否接受？AI agent 写的 `cd x && ls`、重定向、`$(…)` 会被拒绝。建议接受。
12. service 固定保留原始 Host、目标只能是明文 HTTP，没有 Host 改写和目标 TLS 的开关，是否接受？建议接受；需要再加时作为服务条目的新字段。
13. 一台设备多个实例已支持（各属一个 workspace），但 TUN 同一时刻只能由一个实例持有，其他实例只能走代理入口；是否需要让 TUN 实例把其他 workspace 的域名转交同机实例？建议后续，先用代理入口。
14. 两个 egress 覆盖同一目标时是否需要故障切换？建议后续。
15. HTTP Upgrade transport 经 Cloudflare 是否可用，要不要像 Tailscale 那样把它作为默认？建议保持 WebSocket 默认，阶段 4 实测后再定。
16. 密钥形式的名字用 base64url（43 字符），还是用 base32 小写（52 字符）以便将来能直接当 DNS label 用（`<公钥>.<workspace 域名>`）？建议 base64url，与 WireGuard 的显示习惯接近。
17. 加入链接是否同时提供 `https://` 形式（手机扫码后能打开说明页）？建议后续。
18. 策略判定从「首条命中」改为「显式 deny 优先、allow 取并集」，是否接受？建议接受，理由见 6.6。
19. executor 对输出签名是否进 MVP？建议进，否则被攻破的 agentserver 能向 AI agent 伪造工具输出。
20. `server` 模式下保留本地 deny 作为刹车、忽略本地 allow，是否接受？建议接受。
21. 主体种类里的 `user:` 与 `usergroup:`（边缘登录）放到阶段 5，MVP 只实现 node、group、workspace、public，是否接受？建议接受。
22. P2P 直连的 transport 用 QUIC 只作字节流、其上照跑 Noise 与 yamux（双重加密），还是用 QUIC 自带的 TLS 与流取代它们？建议前者，认证与复用只有一套代码。
23. MVP 每个 workspace 指派一个 relay、成员都连同一个，多 relay 与 relay 间转发放后续，是否接受？建议接受。
24. 服务证书的私钥下发到 relay 内存以便边缘终结 TLS，是否接受？建议接受，relay 与控制面同属运营方且不落盘。
25. relay 缓存控制面答案的默认 TTL 为 60 秒，控制面不可达时缓存不过期、未命中的请求退避重试，是否接受？建议接受；要更快生效的变更走 `RelayInvalidate`。
26. 控制流在 relay 终结、agentserver 作为后端并对发给节点的控制消息签名（而不是在控制流里再套一层到 agentserver 的隧道），已按此定；代价是 relay 看得到加入令牌与 `Advertise`，是否接受？建议接受，relay 与 agentserver 同属运营方；介意的话后续把令牌改成封给 workspace 公钥的密文。
27. 路由表的源维度（节点 / 组 / workspace）是否进 MVP？建议进：分流表本来就要按节点渲染，多一个维度几乎不增加成本。

---

## 11. 实施路线

| 阶段 | 内容 | 可演示的结果 |
| --- | --- | --- |
| 0 骨架 | 三个二进制；WebSocket transport；Noise_IK 会话与分帧；yamux 多路复用、保活、重连；节点到 relay 的一条会话与控制流；relay 会话、查询与缓存、消息转交、`Signed` 信封；join 与目录；路由表与分流表推送；`Open` 签名、验签、防重放与 Ack；自管策略上报、组与 workspace 密钥、成员证书的签发与验证、中央策略渲染与 `PolicyUpdate` 下发；`agentd status`；单进程集成测试框架 | 四个模拟节点、一个控制面、一个 relay 在一个进程里互相看到在线，开流签名在 relay 和目标两处都能验过，越权的开流在 relay 被拒 |
| 1 网络 MVP（代理模式） | `tcp` 流（tls、ssh）；egress 策略与协议复核；ingress 的 HTTP / SOCKS5 入口、`agentd connect` 与嗅探；relay 本地校验、向控制面查询选路与预检、转发；控制面的 ACME DNS-01 与证书下发；relay 的 edge：TLS 终结、HTTP 反向代理、身份头、`*`（公网访问者）判定；service 节点侧反向代理与 ssh 透传；决策日志 | `curl --proxy socks5h://127.0.0.1:7891 https://course.ucas.edu.cn` 经 dorm 可达；浏览器配代理后打开 https://nas.home.agentsrv.example.com，证书合法；`ssh homepc.home.agentsrv.example.com` 经 ProxyCommand 登录 |
| 2 TUN | elevator 与 fd 传递；netstack TCP 与 UDP 直通；QUIC 嗅探阻断；fake-IP DNS（服务域名与 via 域名）与 HTTPS 记录剥离；DoH 对策；系统 DNS 接管与恢复；自身流量绑定物理接口；macOS 与 Linux；Private Relay 等兼容测试 | 浏览器和 ssh 不做任何配置即可访问两个站点和 homepc；NTP、其他 VPN 在 TUN 开启时照常工作 |
| 3 任务 MVP（可与阶段 2 并行） | `task` 流；`exec_command` / `write_stdin`；命令解析与 argv 前缀策略；去重；submitter 的 MCP 动态工具与 CLI；审计日志 | Claude Code 或 Codex 调用 `office__exec_command` 运行 lark-cli |
| 4 打磨 | XHTTP packet-up 回退与 HTTP Upgrade 在 Cloudflare 后分别实测；系统服务与 elevator 安装包；Windows；指标；Web 控制台；多会话 | 四台设备经 Cloudflare 长期运行一周无人工干预 |
| 5 后续 | P2P 直连（7.8：候选地址、打洞、QUIC 直连会话）、多 relay 与就近指派、relay 间转发、域名集合（`set:`）、节点间端到端加密（新的协议次版本）、更多 Codex 工具与 executor 侧 MCP、规则签名、边缘登录与 `user:` 主体、签名的成员与分组声明、egress 故障切换、edge 与会话分进程、多 agentserver 实例 | 按需 |

阶段 0、1、3 构成不含 TUN 的完整 MVP，覆盖第 1 节的四条典型链路（代理模式与 ProxyCommand）；阶段 2 让它在浏览器和 ssh 零配置下工作。

---

## 12. 评审与反馈的处理

### 12.1 第一轮：v0.2 的独立评审（15 条发现）

| 编号 | 发现 | 处理 | 章节 |
| --- | --- | --- | --- |
| F1 | TUN 丢弃所有非 53 UDP、嗅探等待首段数据、自身流量自环、系统 DNS 接管一笔带过 | 采纳：UDP 直通，QUIC 嗅探只阻断命中规则的；200 ms 预算与服务端先说话端口列表；全部自身出站绑定物理接口；DNS 接管与恢复列为独立工作项 | 5.2、6.3、11 |
| F2 | TUN 要 root 而 executor 同进程，命令会以 root 跑且看不到用户登录态 | 采纳：特权助手（现名 elevator）+ 用户态主进程 | 2.2#12、5.2、8.5 |
| F3 | executor 策略四条绕过：write_stdin、shell/login 参数、解析器与解释器不一致、glob 顺序 | 采纳：不经 shell 自己 exec，argv 前缀策略，programs 表固定路径，stdin 与 shell 显式开关，tty 默认 false | 5.6、7.6、8.5 |
| F4 | agentserver 可伪造 from；本地策略引用服务端集合自相矛盾 | 采纳：v0.3 用签名头部，v0.4 一度改为端到端 Noise 握手，v0.6 按用户决定回到签名（Ed25519ctx 信封）；策略不引用服务端集合，v0.8 起节点上没有集合、target 是字面的 | 4.4、7.5、8.1、8.7 |
| F5 | service L4 透传让典型 NAS Web UI 失败；端口语义未定义 | 采纳：默认 HTTP 反向代理，L4 透传为可选模式；只接受 443 | 5.4 |
| F6 | XHTTP packet-up 上行是提供侧瓶颈；Bot Fight Mode | 采纳：WebSocket 为默认 transport，XHTTP 为回退；部署注意事项 | 2.3、7.2 |
| F7 | 任务协议与 Codex 四处不符 | 采纳：输出改为 Codex 文本格式并附结构化字段；write_stdin 默认值更正；session_id 为整数；补 chunk_id；MCP schema 裁剪 | 5.5、7.6 |
| F8 | DoH + ECH 让公网规则静默绕过 | 采纳：金丝雀域名 NXDOMAIN、RST 已知 DoH 端点、接管 TCP 53、状态计数 | 2.3、6.4 |
| F9 | Ack 失败行为未定义；优先级两套说法 | 采纳：fallback 策略、规则版本号；优先级只保留一种。v0.6 起恢复流水线：首段数据紧跟 `Open` 发出，接收方有界缓冲 | 4.3、6.5 |
| F10 | 握手缺 Challenge；会话替换对 tls 流不成立；重试重复执行 | 采纳：v0.3 三步握手，v0.4 改为 Noise_IK；明确 tcp 流断开语义；(公钥, call_id) 去重与 call_id 复用；多路复用库需有 RESET | 5.5、5.6、7.3 |
| F11 | 证书缺 cert_pending 与续期触发；通配证书与私钥不离节点矛盾 | 采纳：状态机与错误码保留；v0.4 私钥改在 agentserver，于是通配证书成立，每 workspace 一张 | 5.4、6.2 |
| F12 | 提供侧默认值不一致；角色上限只在 Advertise 校验；名字重用继承授权；令牌在 query；工具描述注入 | 采纳：一律默认拒绝；开流时校验角色；策略认公钥；令牌放 fragment；描述限长标源 | 5.4、5.5、5.7、6.6、8.2 |
| F13 | fake 池目的地不应直连；分配应跨重启稳定；IPv6 段 | 采纳：fake 池目的地只按映射处理否则 RST；按哈希确定分配；IPv6 用 2001:2::/48。未采纳改用 RFC1918 段，因与家庭局域网冲突 | 5.2、6.3、6.4 |
| F14 | 时钟、早期日志、热更新、协议演进、备份、多 workspace、Private Relay | 采纳：新增运维小节；待决问题补多 workspace；Private Relay 列入阶段 2 测试 | 2.3、9.5、10 |
| F15 | 阶段 2 过重；service 可在代理模式先演示；任务可并行；缺集成测试 | 采纳：路线图重排，阶段 0 加单进程集成测试框架 | 11 |

### 12.2 第二轮及补充：v0.3 之后的反馈（27 条）

| 编号 | 反馈 | 处理 | 章节 |
| --- | --- | --- | --- |
| R1 | 权威 CA 的证书不会离开 agentserver，homepc 终结 TLS 是错的 | 采纳：agentserver 成为 HTTP 服务的 HTTPS 边缘，每 workspace 一张通配证书，节点只收 HTTP/1.1；SSH 与 L4 服务不经边缘 | 1、2.2#7、5.4、5.7、6.2、8.4 |
| R2 | 研究支持 SSH 的可行性 | 可行，已纳入：`tcp` 流的 `proto: ssh`，域名来自代理请求、`agentd connect` ProxyCommand 或 fake-IP；egress 复核 `SSH-` 首行；研究结论见附录 A | 5.2、5.3、5.4、6.3、附录 A |
| R3 | helper 改名 elevator | 采纳 | 全文 |
| R4 | carrier 在 Go 里一般叫 transport | 采纳：改名 transport，包名 `internal/transport` | 3、7.1、7.2、9.4 |
| R5 | 会话上的控制通道和流是否多路复用在一条物理连接上 | 是，已写清：transport 字节流 → Noise 会话 → yamux，控制通道是第一条流，两侧都能开流，并说明为什么不是每连接一条 | 4.3 |
| R6 | 流的拼接看看 Xray 踩过的坑 | 已整理为 7.7，并据此修正嗅探累积、半关闭、超时、yamux 参数 | 7.7 |
| R7 | 头部 `{domain, port, nonce, sig}` 是否参考了现代密码学做法；设想是 WireGuard 式密钥对 | 承认 v0.3 的签名头部是手搓构造；v0.4 改为 X25519 静态密钥对加两层 Noise_IK；v0.6 按用户决定去掉节点间的那层 Noise、只保留签名，并把签名方案按现代做法重写（Ed25519ctx、对字节签名、时间戳加随机数、绑定 to） | 2.2#3、4.4、7.3、7.5、8.2 |
| R8 | agentserver 维护公钥到名字的映射；节点可配置是否接受 agentserver 下发规则/配置 | 采纳：目录与本地 `peers`、`server.accept_push`；`trust_server_directory` 后在 v0.9 被成员证书取代 | 3、6.6、8.2、9.2 |
| R9 | agentserver 与本机已有的 `~/projects/agentserver` 无关 | 采纳：删除相关待决问题与风险 | 2.3、10 |
| R10 | 明文 HTTP 不支持，第一期只做 TLS，SSH 好搞就加上 | 采纳：去掉 HTTP Host 嗅探与可选开关；SSH 进阶段 1 | 6.3、11 |
| R11 | 每个实例有等价的名字 `agentd://<公钥>` 与 `agentd://<workspace 域名>/<实例名>`，实例名参考主机名 | 采纳：定义 `agentd://` URI 的两种形式、等价关系、编码、解析顺序、用途；实例名按 RFC 1123 label，默认取 hostname | 2.2#15、3.1、6.1、9.3 |
| R12 | 明确实例接入 agentserver 的流程 | 采纳：令牌、加入链接、握手载荷、目录登记、后续连接、改名换机吊销的完整流程与时序 | 4.5、7.3、8.2、9.3 |
| R13 | 任务转发时 agentserver 也要校验 laptop 有没有发给 office 的权限 | 采纳：提供侧把策略里的「谁」归纳成 `accept_from` 随 `Advertise` 上报，agentserver 转发前校验；v0.7 起受管节点改为直接按中央策略预检，workspace ACL 并入中央策略；提供侧策略仍然执行 | 2.2#9、4.4、5.7、6.6、7.5、8.3、9.1 |
| R14 | 节点之间再跑一层 Noise_IK 不必要，目前只需要签名不需要加密 | 采纳：去掉节点间 Noise 层；身份密钥改为 Ed25519，`Open`（含整个 function_call）由发起方签名、输出由 executor 签名，Ed25519ctx 加时间戳与随机数防重放，`to` 绑定目标；与 agentserver 的握手用派生的 X25519 密钥；恢复首段数据流水线 | 1、2.2#3-4、4.3、4.4、7.3、7.5、8 |
| R15 | 策略的权威来源二选一（agentserver 或本地），受管节点由 agentserver 经控制通道同步，自管节点忽略远程；节点执行的始终是 pubkey - action - target；agentserver 上可按实例 / 实例组 / workspace / 已登录用户 / public 配置，需要想清楚如何渲染；参考相关工作 | 采纳：`policy.source`、`PolicyUpdate` / `PolicyApplied`、本地 deny 刹车；主体模型与渲染算法；判定改为显式 deny 优先；对照 Tailscale、Cloudflare Access、Nebula / ZeroTier、Teleport / IAM / Cedar、K8s RBAC | 2.2#9、3、4.4、5.3、5.7、6.6 到 6.8、7.4、8.2、9.1、9.2 |
| R16 | 有没有更好的权限引擎；节点上总是执行 pubkey 策略是否合适 | 评估：pubkey 执行合适，它是节点唯一能独立验证的身份，分层与 WireGuard / Tailscale 一致。提出的三项改进经讨论都不做：节点侧不设自定义目标组（撤回「提供侧命名资源」），target 保持字面，目标组只在 agentserver 侧定义并在渲染时展开；`ask` / `audit` 动作与 `until` / 速率条件暂缓 | 2.2#9、3、5.3、6.6、9.1、9.2 |
| R17 | 不用 Cedar；节点、组、workspace、agentserver 四级密钥对；成员关系应由 agentserver 签发证书给成员而不是中继时附签，以便将来 P2P；为 UDP 打洞预留 transport | 采纳：成员证书（1 小时、过半续发、吊销推送）由成员随 `StreamOpen` 出示；渲染只做主体到公钥的替换；`trust_server_directory` 取消；6.9 记录不采用的方案；7.8 与协议 2.6 预留 P2P | 1、2.2#3、#9、#16、3、6.6 到 6.9、7.4、7.5、7.8、8、9 |
| R18 | 把 P2P 方案补进设计文档；每个实例自由选择是否加入 P2P 发现 | 采纳：7.8 写成完整方案（opt-in、候选地址与 STUN、agentserver 会合与打洞邀请、QUIC 直连会话、流的放置与回退、安全隐私、可观测性、不做的事），协议 2.6 预留四个消息、四个状态码和探测报文格式，`Advertise.p2p_enabled` | 2.2#16、3、4.3、7.8、9.2、10、11 |
| R19 | agentserver 的控制面和数据面（relay）要分开部署 | 采纳：拆成 agentserver（控制面）与 agentrelay（数据面）两个程序；节点一条控制会话加一条数据会话；relay 按控制面下发的快照做预检与转发、充当 edge、控制面不可达时继续工作；服务证书下发到 relay 内存；`Welcome.relays` 与指派、`RelayReport` 改派；MVP 每 workspace 一个 relay | 1、2.2#4-5、#7、#9、2.3、3、4.1 到 4.5、5、6、7、8、9、11 |
| R20 | 「每台设备跑一个 agentd」不准确：不反对一台设备上运行归属多个 workspace 的实例，设计上要支持 | 采纳：实例目录 `~/.agentd/instances/<名>/` 与 `agentd -i`，每个实例独立的密钥、配置、socket 与会话；TUN、系统 DNS 为设备级资源，同一时刻归一个实例；join 流程与术语按实例改写 | 1、2.2#17、3、4.5、5.2、9.2、9.3、9.5、10 |
| R21 | ingress 不需要知道最终目的地是 dorm，只需要知道该域名的下一跳要转给中心而不是直连；三段式：ingress 判断直连还是转发，中心先按路由找到目的实例、再查策略、再转发，目的实例先验签、再校验发起者与动作、再执行 | 采纳：ingress 只收分流表（去掉目的的路由表投影），`Open.to` 统一为下一跳，任务目标移到 `task.executor`；relay 清单 A 改为本地校验 → 向控制面查询选路与预检 → 转发，删除 `RULE_TARGET_MISMATCH`；提供侧清单 B 改为验签 → 策略 → 执行；`Ack.responder` 供日志与 P2P 放置 | 1、2.2#6、#18、3、4.3、4.4、5.2、5.3、5.8、6.5、7.4、7.5、7.8、8 |
| R22 | relay 为什么需要 snapshot？直接去 agentserver 上查，可以适当缓存，不要新起一个 snapshot 实体 | 采纳：删除 `RelaySnapshot` / `RelayDelta` 与快照相关消息及线上的 `Rules`；relay 按需发 `RelayLookup`（流、证书），答案按 TTL 缓存，`RelayInvalidate` 按 workspace 清除；选路与策略预检只在 agentserver 实现；控制面不可达时已缓存答案继续用、未命中回 `CONTROL_NOT_READY` | 2.2#5、#19、2.3、3、4.1、4.3、4.4、5.7、5.8、6.7、7.4、8、9.4、10 |
| R23 | 每个 agentd 实例应该只有一条到 relay 的连接，控制通道和数据通道都和 relay 交互，agentserver 只是管理平台；重新思考 agentserver 与 agentrelay 的功能划分 | 采纳：节点只连 relay，一条会话；流 1 是到 agentserver 的控制隧道，隧道内再做一次 Noise_IK，relay 只透传密文；agentserver 不再有面向节点的端点，可放内网；节点只钉 agentserver 公钥，relay 凭它签发的 relay 证书被认可；agentserver 在隧道内认证后向 relay 推 `NodeAdmitted` 放行数据流；加入链接的 `server=` 改为 `relay=` | 1、2.2#4-5、#20、3、4、5.1、5.7、5.8、7、8、9、协议 1、2.5、3、5.1、5.8、12 |
| R24 | 术语表逐条意见：路由规则应叫路由表且形态是（源节点 / 节点组，协议，目的节点）；`accept_from` 多余，transport 与 task 都遵守 policy 即可；transport 要提到 p2p；域名集合第一期不做；成员证书是否要下发 CA；开流签名与「共用同一条连接」的关系；密码学为什么同时有 Ed25519 签名与派生的 X25519 | 采纳：路由表改为（源、协议、域名、目的）并按节点渲染分流表；删除 `accept_from` / `allow_from` 概念，自管节点随 `Advertise` 上报生效策略，预检与边缘判定都用策略；transport 术语补 `p2p`；域名集合移入后续，协议保留位置；术语表补成员证书不需要 CA 文件的说明、开流签名与会话的关系；7.3 新增「一把密钥，两种用途」的说明 | 3、4.4、5.1、5.3、5.4、6.5 到 6.8、7.2、7.3、11 |
| R25 | 流 1 的控制隧道为什么要 agentserver 参与，控制通道应该是 agentrelay 的事；决定：relay 终结控制通道，agentserver 做后端 | 采纳：去掉隧道与隧道内握手；节点消息由 relay 以会话身份转交（`NodeMessage`），后端发给节点的消息一律签名（`Signed`）由 relay 送达（`Deliver`）；握手与加入由 relay 向后端查询（`node` / `join`）；删除 `NodeAdmitted` 与 `SESSION_CONTROL` | 2.2#4-5、#19、#21、3、4、5.1、5.7、5.8、7、8、协议 0、3、5.1、5.8、11、12 |
| R26 | 配置评审：顶层字段太乱要分组；地址写成 address / port 对象、同类条目用对象数组；本地不需要 peers，规则里直接写 public_key，支持合法公钥和 `*`；规则列表叫 `policies`；egress 规则的 `proto` 是单个协议；只有 policy 控制权限，服务的 `access` 也要写成 policy；policy 没有 who 只有 public_key；`policy.source` 下放到每个需要 policies 的角色 | 采纳：配置参考 `docs/agentd-config.yaml` 按 identity / workspace / relay / roles / p2p / log 分组并结构化；删除 `peers` 与 `--pin`，规则只有 `public_key`（一把公钥或 `*`，`*` 对 HTTP 服务含公网访问者）；`roles.*.policies` 与按角色的 `policy_source`；`EgressRule.proto` 单值；删除服务的 `access` 与 `allow_from`；9.2 与 5.4、5.6 示例按此重写 | 2.2#3、3、3.1、4.5、5.3、5.4、5.6、6.6 到 6.8、8.2、8.3、8.6、8.7、9.2、9.3、协议 4.1、5.3、5.6、5.7、6.3、9 |
| R27 | 节点配置里为什么钉 agentserver 公钥而不是 workspace 公钥；决定：节点只钉 workspace 公钥，注册流程同步改 | 采纳：加入链接的 `key` 与配置的 `workspace.public_key` 都是 workspace 公钥；发给成员的控制消息、relay 证书（按 relay × workspace 签发，well-known 按 workspace 返回）与 workspace 成员证书都由 workspace 密钥签（agentserver 代签）；agentserver 密钥只用于 relay 会话 | 1、2.2#3、#20、#21、3、3.1、4.3 到 4.5、5.7、5.8、6.8、7.1、7.3、7.4、8.1、8.2、8.6、9.1、9.2、9.5、协议 0.5、1、2.5、3.1、5.1、5.8、8.2、12.1 |

---

## 附录 A：SSH 可行性研究

结论：可行，而且比 TLS 简单。SSH 客户端的第一行是明文 ASCII `SSH-2.0-…\r\n`，前 4 个字节就能判定协议；困难只在域名，因为 SSH 协议本身不带目的主机名。域名必须来自客户端一侧：`ProxyCommand` 的 `%h`、SOCKS5 / CONNECT 请求里的域名，或 TUN 模式下的 fake-IP 映射。cloudflared 和 Tailscale 都是这样做的。

### A.1 协议事实（RFC 4253）

- §4.2：双方都必须发送标识串 `SSH-protoversion-softwareversion SP comments CR LF`，最长 255 字节，不得含 NUL。
- §4.2：服务端可以在标识串之前发送其他行（不以 `SSH-` 开头），客户端必须能处理；RFC 没有给客户端同样的许可，OpenSSH 的 sshd 会以 "client sent invalid protocol identifier" 拒绝客户端的多余行。
- RFC 不规定谁先发：§4 只说 "The client initiates the connection"，§5.2 明确允许客户端在收到服务端标识串之前就继续发数据。
- §8：双方的标识串（去掉 CRLF）是交换哈希的输入。中继必须逐字节透传，不能改写 CRLF、注释，也不能插入任何行。

### A.2 主流客户端是否先发标识串

| 客户端 | 是否先发 | 依据 |
| --- | --- | --- |
| OpenSSH ssh | 是 | `kex.c` 的 `kex_exchange_identification()`：先 "Prepare and send our banner"，再 "Read other side's version identification"。6.2（2013 年）起 SSH-2-only 时立即发送以省一个 RTT，8.0 起合并进 kex.c；更早的版本先等服务端 |
| Windows OpenSSH | 是 | 同一份 `kex.c` |
| Go `golang.org/x/crypto/ssh` | 是 | `transport.go` 的 `exchangeVersions()`：先写自己的版本行，再 `readVersion` |
| PuTTY 0.83 | 默认是 | `ssh/verstring.c`：`send_early = server_mode \|\| !ssh_version_includes_v1(...)`；只有配置含 SSH-1 或打开 `sshbug_dropstart` 时才等服务端 |
| libssh2 | 是 | `session.c` 的 `session_startup()`：`session_banner_send` 之后才 `session_banner_receive` |
| paramiko | 是 | `transport.py` 的 `run()`：先写 `local_version`，再 `_check_banner()` |
| Dropbear dbclient | 是，且不等对方就接着发 KEXINIT | `cli-session.c`：`send_session_identification(); … send_msg_kexinit();` |

### A.3 先例

- cloudflared：`ProxyCommand cloudflared access ssh --hostname %h`，按 HTTPS 主机名路由，走 WebSocket；隧道侧 `newTCPOverWSService` 对 `ssh` 类型补 22 端口后拨 TCP 并逐字节转发；sshd 不需要任何改动（`cmd/cloudflared/access/carrier.go`、`ingress/origin_service.go`）。`agentd connect %h %p` 是同一模式。
- Tailscale：Tailscale SSH 是替换 sshd 的内置服务端，不是中继；用户态网络模式下 `tailscale nc <host> <port>` 可作 ProxyCommand，与它的 SOCKS5 / HTTP 代理并列。
- ssh_config(5)：ProxyCommand "should read from its standard input and write to its standard output"；`%h` 原样交出未解析的主机名；ProxyCommand 与 ProxyJump 互斥（先出现者生效），跳板机的 ProxyCommand 要写在它自己的 `Host` 段里。

### A.4 对设计的要求

- 按首 4 字节判协议，不等 ClientHello；fake-IP 目的地加 22 端口时即使首字节未到也按 SSH 处理（6.3）。
- 服务端到客户端方向不能等客户端字节：egress 策略通过后立即拨号并开始回传服务端 banner；客户端首行到达时再校验 `SSH-`，不符则 RESET（5.3）。少数客户端（PuTTY 含 SSH-1、OpenSSH 6.2 之前）确实要先看到服务端 banner。
- 中继建立连接的耗时计入 sshd 的 `LoginGraceTime`（默认 120 秒）和客户端的 `ConnectTimeout`。
- 保活：`ServerAliveInterval` 默认 0。中继不能给 SSH 流设空闲超时；会话级保活（yamux ping）让 CDN 不切断物理连接；egress 拨出的 TCP 开启 keepalive（7.7）。
- 端口转发、agent 转发、scp / sftp 都是同一条 TCP 连接上的通道（RFC 4254），不需要额外路由；需要真实的背压（每流窗口）和逐段发送（NODELAY）保证交互体验。
- 未验证：Cloudflare 对 WebSocket 空闲连接的确切超时；HTTP Upgrade 能否过 Cloudflare。
