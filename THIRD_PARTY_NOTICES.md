# 来源与第三方组件

- 项目结构与生命周期分工参考 cloudflare/cloudflared 的 `8e090e5bfa7a53e824fb2d7eb276f8ab08337b80`，重点是 cmd、config、connection、orchestration、supervisor 的职责划分。本轮没有将整个 cloudflared 源码复制进来。
- `transport/xhttp` 参考 XTLS/Xray-core `0f127f934c6d7c10e4bb6acbe98033db9e5fd922` 的 split HTTP/packet-up 设计，重写为独立的标准库包并修改线协议与生命周期。该目录按 MPL-2.0 提供，保留 [NOTICE](transport/xhttp/NOTICE) 和 [完整 LICENSE](transport/xhttp/LICENSE)。不表示原生 Xray 全协议兼容。
- `connection` 使用 HashiCorp yamux 实现多路复用，不自行实现数据流窗口和底层复用协议。
- 后端职责拆分参考 Headscale `fc97593bcea76c92fb3ad41a5b95076684ddc85a` 的注册、状态、策略与存储分层，使用本项目自有 API/schema，不复制 Tailscale/Headscale 协议或声明兼容。
- SQLite 与 PostgreSQL 分别使用 modernc.org/sqlite 和 pgx；发布包从两个实际编译命令的模块并集中收集许可证，不捆绑数据库状态或凭据。
- YAML、IDNA 和日志分别使用 go.mod 锁定的 yaml.v3、golang.org/x/net、zerolog。构建不 vendoring，不关闭 Go module checksum 校验。

依赖版本由 go.mod/go.sum 固定，第三方组件各自的许可证继续适用。
