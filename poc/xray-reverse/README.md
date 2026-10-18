# Xray Reverse P0 PoC

定位更新：这是旧 Reverse 承载方案的实验，保留用于理解其行为边界。当前产品已确定由 agents 管理认证、连接目录和业务流，XHTTP/WSS 仅作承载；本 PoC 不作为该新方案的实现。见 [当前架构](../../docs/agents-agentd-architecture.md) 和 [本地三角色配置](../../docs/agentd-config.md)。

日期：2026-10-17

这个 PoC 验证 Xray 原生 Reverse 的最低可运行链路，不代表 agents 的授权实现已经完成。

测试证书和私钥不提交仓库。`configs/` 中的 TLS 路径与 pin 是模板；先运行 `python3 poc/xray-reverse/prepare.py`，再使用 `.generated/` 下的配置。脚本生成一次性自签名证书，并同步所有 server 路径及客户端 pin；输出目录已被 Git 忽略，不覆盖已存在证书。原始实验结果记录的是当时的测试材料，不保证与重新生成的材料具有相同 fingerprint。

## 拓扑

```text
client Xray (SOCKS 127.0.0.1:19087/19187/19287/19387)
        │ VLESS WS / XHTTP / XHTTP+TLS / WSS
        ▼
portal Xray (reverse portal, external + interconn)
        │ native reverse mux
        ▼
bridge Xray (reverse bridge)
        │ freedom
        ├── HTTP origin 127.0.0.1:19080
        └── hold/second target 127.0.0.1:19081/19082
```

`portal-*`、`bridge-*`、`client-*` 分别覆盖：

- `ws`：明文 WebSocket，仅用于基线；当前 Xray 会提示该传输已 deprecated。
- `xhttp`：`stream-one`，验证 XHTTP 能承载 Reverse。
- `xhttp-tls`：XHTTP over TLS，验证外层 TLS 后仍能承载 Reverse。
- `wss`：WebSocket over TLS，客户端使用测试证书 pin，验证外层 TLS 不影响 Reverse。

## 已执行实验

| 实验 | 结果 | 证据 |
|---|---|---|
| WS Reverse HTTP | 通过 | `curl --socks5-hostname 127.0.0.1:19087 http://127.0.0.1:19080/index.html` 返回 `agentd reverse poc` |
| XHTTP Reverse HTTP | 通过 | `curl --socks5-hostname 127.0.0.1:19187 ...` 返回 `agentd reverse poc` |
| XHTTP over TLS Reverse HTTP | 通过 | `curl --socks5-hostname 127.0.0.1:19387 ...` 返回 `agentd reverse poc` |
| WSS Reverse HTTP | 通过 | `curl --socks5-hostname 127.0.0.1:19287 ...` 返回 `agentd reverse poc` |
| RemoveUser 后的新连接 | 失败 | `xray api rmu ... -tag=external access-client-wss` 后 curl 得到 `Empty reply from server` |
| RemoveUser 后的既有流 | **仍然通过** | 长连接持续返回 `pong`，至少保持一分钟级；删除 VLESS user 没有关闭既有 reverse 流 |
| 删除 Reverse 提供方用户后 | **仍然通过** | 删除 `interconn/bridge-wss` 后既有 bridge worker 和新请求仍可工作，直到 bridge 进程停止 |
| 停止 bridge 后 | 拒绝 | 现有流最终断开；新请求得到空响应，没有回落到 Edge/其他出口 |
| 未配置目标的第二端口 | **可达** | `127.0.0.1:19082` 通过同一 Reverse 路径可访问，说明原生 Reverse 本身不提供域名/端口 allowlist |

## 运行环境与限制

- 运行二进制：Homebrew `Xray 26.3.27`，macOS arm64。
- 配置均先通过 `xray run -test` 验证。
- WSS 使用本地自签名证书和 `pinnedPeerCertSha256`，证书只用于测试。
- 调研文档中的 Xray 固定 commit `0f127f...` 已克隆，但由于 Go module 网络下载超时/依赖 checksum 不一致，没有完成该 commit 的完整编译和测试；因此本结果不是该 commit 的严格复现。
- 尚未验证真实 FrontDoor、反向代理后的 XHTTP 上下行粘性、`stream-up`/`packet-up`、自定义 PolicyGate、Go outbound Handler 扩展或多 `core.Instance`。

## 对架构的直接结论

1. Xray 原生 Reverse + Mux 可以承载“访问方 → Edge → 提供方”的基础双向字节流，XHTTP `stream-one` 和 WSS 均可跑通。
2. `RemoveUser` 只阻止后续认证，不能作为活动流或 Reverse worker 的撤销机制；必须实现活动流账本、显式关闭或 runtime 重建，并定义最大暴露时间。
3. Reverse 原生层不会执行 agents 的 hostname/port/Workspace 授权。未实现 PolicyGate 前，任何能通过 access-client 身份建立的目标都可能沿 bridge 的 `freedom` 继续拨号。
4. WSS 在当前版本仍可用但已收到 deprecated 警告；首版应优先把 XHTTP 作为主传输，并单独验证真实 TLS FrontDoor。

对应的修订方案见 [agents-agentd-p0-remediation.md](../../docs/archive/agents-agentd-p0-remediation.md)。
