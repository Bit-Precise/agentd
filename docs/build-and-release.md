# agentd 多平台发布与安装包

本仓库只发布客户端 `agentd`。服务端 `agents` 独立维护。

发布职责参考 [GitHub CLI 固定提交 fa92838](https://github.com/cli/cli/tree/fa92838bef95fe4a29c1587693885d5e9bdb6cf1)：按平台区分 GoReleaser build ID，在 post-build hook 中签名可执行文件，由 GoReleaser 生成归档和 Linux 安装包，再由原生工具制作 MSI/PKG。最终聚合后由 GoReleaser 发布。

## 公开产物矩阵

矩阵对应 [GitHub CLI v2.102.0](https://github.com/cli/cli/releases/tag/v2.102.0)，产品前缀替换为 `agentd`：

| 平台 | 架构 | 文件名和格式 | 数量 |
|---|---|---|---|
| Linux | 386、amd64、arm64、armv6 | `agentd_<version>_linux_<arch>.tar.gz`、`.deb`、`.rpm` | 12 |
| macOS | amd64、arm64 | `agentd_<version>_macOS_<arch>.zip` | 2 |
| macOS | universal（x86_64 + arm64） | `agentd_<version>_macOS_universal.pkg` | 1 |
| Windows | 386、amd64、arm64 | `agentd_<version>_windows_<arch>.zip`、`.msi` | 6 |
| 校验和 | 全部产品 | `agentd_<version>_checksums.txt` | 1 |

共 **21 个产品文件 + 1 个校验和文件 = 22 个公开 Release 资产**，不包括 GitHub 自动提供的源码下载。`<version>` 为去掉 v 前缀的包版本；开发归档使用 `0.0.0-dev-<commit>`，安装器数字版本为 `0.0.0`，CLI 内仍记录原始 `dev-<commit>`。

Linux tar.gz 和 macOS ZIP 含版本化顶层目录，Windows ZIP 不套顶层目录；可执行文件均在 `bin/agentd` 或 `bin/agentd.exe`。文档、配置示例、BUILDINFO 和第三方许可证包含在归档及安装包中。聚合 BUILDINFO 与原始目标校验和作为 CI 内部验证数据，不单独作为公开资产，也不混入公开 checksum。

汇总验证 10 个目标组：Linux 四组、macOS 两个架构及 universal 三组、Windows 三组。每个输入先验证原始 SHA256，再验证产品集合、版本、commit、签名和公证状态。许可证副本仅统一 CRLF/LF，任何真实内容差异仍失败。

## 工具和流水线

- Go 固定 **1.27.2**，GoReleaser OSS 固定 **2.18.3**；CGO=0、`-mod=readonly`、`-trimpath`。公开产品使用 `GOFIPS140=off`。
- GoReleaser 原生生成 tar.gz、ZIP、DEB/RPM。post-build hook 必须完成可执行文件签名和验证后才能归档；归档之后不重签其中的二进制。
- Linux amd64 DEB 实际安装/卸载，全部 RPM 检查结构和文件摘要算法；ARMv6 为 GOARCH=arm/GOARM=6。
- Windows 使用 **WiX 5.0.2** 生成三个架构 MSI；386/amd64 在 x64 runner 实装，arm64 在 `windows-11-arm` 原生实装。验证 CLI 版本、ZIP 与已安装 EXE 的 SHA256，以及卸载结果。
- macOS 两个架构分别在 Intel 和 Apple Silicon runner 构建、执行 ZIP 内 CLI。universal job 核验两 ZIP，`lipo` 合并两 slice 后重新签名 universal CLI，再生成 PKG；同一 PKG 在两种原生架构上安装验证。
- Actions 固定 commit。普通 main/PR 构建产生 unsigned 测试产品；手动签名验证不创建 GitHub Release；仅 `v*` tag push 允许正式发布。

## 本地构建

```sh
make agentd
make test lint
python3 -m unittest discover -s scripts -p 'test_*.py' -v

# 先安装 GoReleaser OSS 2.18.3，并确保 goreleaser 位于 PATH。
TARGET_OS=linux TARGET_ARCH=amd64 VERSION=v0.1.0 make release
TARGET_OS=linux TARGET_ARCH=armv6 VERSION=v0.1.0 make release

# macOS 每个目标生成 ZIP；universal PKG 消费两个已验证的目标目录。
python3 scripts/release.py build --os darwin --arch amd64 --version v0.1.0 --out dist/mac-amd64
python3 scripts/release.py build --os darwin --arch arm64 --version v0.1.0 --out dist/mac-arm64
python3 scripts/release.py universal --amd64-input dist/mac-amd64 --arm64-input dist/mac-arm64 --version v0.1.0 --out dist/mac-universal

# Windows 本机生成 ZIP/MSI；安装测试须在兼容架构的干净机器上运行。
./scripts/build-windows.ps1 -Architecture amd64 -Version v0.1.0 -OutDir dist -SmokeTest
```

不要并发写同一目标目录。`scripts/release.py products --os windows --arch arm64 --version v0.1.0` 返回版本化文件名；`expected --version v0.1.0` 列出完整 21 产品集合。

安装器要求数字版本：`v1.2.3` 对应 `1.2.3`。MSI major/minor 上限为 255；calendar 年份 2000–2255 映射为 year−2000，例如 `v2026.10.1` 的 MSI ProductVersion 为 `26.10.1`，CLI 保留原始版本。其他超限值拒绝，不截断。

## 安装位置和签名

Linux 安装到 `/usr/bin/agentd`，macOS universal 安装到 `/usr/local/bin/agentd`。Windows 386/amd64 使用各自 Program Files 下的 `agentd`；ARM64 使用 `agentd-arm64`，避免与 x64 模拟运行版本相互覆盖。三个架构使用独立升级码。MSI 默认不修改 PATH，可显式指定 `ADDLOCAL=Core,Path`。

安装器只安装 CLI 和文档，不自动注册设备、写入凭据或启动服务；卸载不删除用户 profile。项目没有指定统一开源许可证时，Linux 包 metadata 保持 `LicenseRef-Proprietary AND MPL-2.0`，第三方组件保留各自许可证。

Windows 使用固定 SHA256 的 Microsoft.ArtifactSigning.Client **1.0.128** 和受信任的 Windows SDK SignTool。Azure login v3.1.0 通过 OIDC 登录；GoReleaser EXE post-build hook 和 MSI 签名共用 `scripts/sign-windows.ps1`。私钥由 Azure 管理。EXE 和 MSI 均验证 Authenticode 签名、RFC3161 时间戳，再做安装测试。

macOS 的 `scripts/sign-macos.py` 管理临时 keychain；GoReleaser post-build hook 使用 Developer ID Application 签 CLI，再生成每架构 ZIP。最终 ZIP 直接提交 Apple 公证并要求 Accepted。universal job 核验输入、合并并重新签 CLI，用 Developer ID Installer 签 PKG，再要求 PKG 公证 Accepted、staple/validate 和 Gatekeeper 安装评估。ZIP 不支持 staple；PKG 携带公证票据。

凭据保存在 GitHub 组织级 Variables/Secrets，仅签名步骤接收。Go/GoReleaser 子进程只获得身份名称和临时 keychain 路径，不继承 P12/P8 内容或密码。临时 keychain 和私钥文件在正常成功/失败时清理，原 keychain 搜索列表恢复。配置项见 [release-signing.md](release-signing.md)。缺配置或验签失败时，正式发布不会降级为 unsigned。

## 本地 FIPS 构建

FIPS 不属于与 GitHub CLI 对齐的公开发布矩阵。`make fips` 仍可本地构建固定 `GOFIPS140=v1.0.0-c2097c7c` 的 Linux amd64 裸二进制，并检查构建记录和默认运行模式；这不表示 agentd 整体取得 NIST 产品认证。
