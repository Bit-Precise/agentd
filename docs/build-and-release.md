# agentd 多平台发布与安装包

本仓库只发布客户端 `agentd`。服务端 `agents` 独立维护；客户端构建不引用其源码、数据库、前端或私有依赖。

产物形态参考 cloudflared `8e090e5bfa7a53e824fb2d7eb276f8ab08337b80` 的 Makefile、`.ci/scripts/linux/build-packages*.sh`、mac/build.sh 和 Windows WiX 配置，名称替换为 agentd。没有复制 Cloudflare 的品牌、升级 GUID、凭据、签名证书或产品认证。

## 精确产物清单

普通 Linux 5×3=15，macOS 2×2=4，Windows 2×2=4，Linux amd64 FIPS=3，合计 **26 个产品文件**：

```text
agentd-amd64.pkg
agentd-arm64.pkg
agentd-darwin-amd64.tgz
agentd-darwin-arm64.tgz
agentd-fips-linux-amd64
agentd-fips-linux-amd64.deb
agentd-fips-linux-x86_64.rpm
agentd-linux-386
agentd-linux-386.deb
agentd-linux-386.rpm
agentd-linux-aarch64.rpm
agentd-linux-amd64
agentd-linux-amd64.deb
agentd-linux-arm
agentd-linux-arm.deb
agentd-linux-arm.rpm
agentd-linux-arm64
agentd-linux-arm64.deb
agentd-linux-armhf
agentd-linux-armhf.deb
agentd-linux-armhf.rpm
agentd-linux-x86_64.rpm
agentd-windows-386.exe
agentd-windows-386.msi
agentd-windows-amd64.exe
agentd-windows-amd64.msi
```

除此之外发布 `SHA256SUMS`、`BUILDINFO.json`、`agentd-licenses.tgz`，总共 29 个文件。汇总任务严格验证 26 个产品名、10 个目标组、每个输入校验和、版本/源码 commit 一致性，拒绝遗漏、重复和混入旧产物。裸文件下载后需要自己设置可执行位；DEB/RPM/PKG/MSI 使用安装包记录的文件权限。

## 工具与 CI

- Go 固定 **1.27.2**，构建使用 CGO=0、`-mod=readonly`、`-trimpath`。普通包显式 `GOFIPS140=off`。
- Linux 使用 **nfpm 2.48.0** 的官方发布二进制，并核验仓库固定的 SHA256；不是改扩展名的 tar 包。DEB/RPM 的架构元数据分别使用 i386/amd64/armel/armhf/arm64 和 i386/x86_64/armv5tel/armv7hl/aarch64，文件名保持上表。
- macOS 在原生 `macos-15-intel` 和 `macos-15`（ARM64）runner 使用 Apple `pkgbuild` 创建真实 PKG，展开检查，再实际安装并执行 version，随后清理安装及 receipt。
- Windows 在原生 runner 使用 **WiX 5.0.2** .NET tool 创建 MSI。脚本核对工具版本，实际静默安装、执行 version、比较已安装 EXE 的 SHA256、卸载并检查清理。需要 runner 提供管理员权限与 .NET 运行时。
- 原有 Ubuntu/macOS/Windows 原生测试与 vet 保留；Ubuntu/macOS 保留 race，手动工作流可再启用 Linux ARM64 原生测试。Linux amd64 的普通与 FIPS DEB 均实际安装/卸载，所有 RPM 核验包结构与 SHA256 文件摘要算法。
- 官方 Actions 固定 commit：checkout v7.0.1、setup-go v7.0.0、upload-artifact v7.0.2、download-artifact v8.0.2。工具版本和 runner 标签已向对应官方仓库核对，不使用浮动 latest 工具版本。

[工作流](../.github/workflows/build.yml) 在 main/PR/手动运行执行测试和完整构建。仅 push `v*` tag 发布 GitHub Release；PR 使用只读默认权限，只有 tag 发布 job 获得 contents:write。普通构建同样产生可下载的完整 artifact。

## 本地构建

```sh
make agentd
make test lint
make race
python3 -m unittest discover -s scripts -p 'test_*.py' -v

# 安装固定 nfpm 到指定工具目录，不改 go.mod。
python3 scripts/install-nfpm.py --destination /tmp/agentd-tools
NFPM=/tmp/agentd-tools/nfpm TARGET_OS=linux TARGET_ARCH=amd64 VERSION=v0.1.0 make release
NFPM=/tmp/agentd-tools/nfpm TARGET_OS=linux TARGET_ARCH=arm TARGET_ARM=5 VERSION=v0.1.0 make release
NFPM=/tmp/agentd-tools/nfpm TARGET_OS=linux TARGET_ARCH=arm TARGET_ARM=7 VERSION=v0.1.0 make release

# 在 macOS 主机生成指定架构的 TGZ 和 PKG。
TARGET_OS=darwin TARGET_ARCH=arm64 VERSION=v0.1.0 make release

# 在 Windows PowerShell 7 中生成 EXE/MSI，并在干净测试机安装/卸载。
./scripts/build-windows.ps1 -Architecture amd64 -Version v0.1.0 -OutDir dist -SmokeTest
```

`make all` 只构建 agentd。`make fips` 构建固定 FIPS 模块的 Linux amd64 裸文件。`scripts/release.py build` 只准备目标二进制、文档、许可证与 metadata；`package` 再生成 Linux/mac 安装包。Windows 的原生 MSI 步骤使用 PowerShell 脚本。不要并发写同一个目标目录；CI 每个目标使用独立目录，再统一汇总。

Git 版本写进 `agentd version`，不从包文件名推断。安装器要求数字版本：常规 `v1.2.3` 使用 `1.2.3`；开发版本 `dev-<commit>` 使用 `0.0.0`。MSI 的 major/minor 上限为 255，calendar 年份 2000–2255 映射为 year−2000，例如 `v2026.10.1` 的 MSI ProductVersion 为 `26.10.1`，EXE 版本仍是原始值。其它超限版本拒绝打包，不截断成潜在冲突版本。预发布版本仍写入原始 CLI 版本，安装器数字版本可能相同，因此发行升级测试应使用递增正式版本。

## 安装位置与行为

| 格式 | 二进制 | 文档 / 许可 |
|---|---|---|
| DEB/RPM | `/usr/bin/agentd` | `/usr/share/doc/agentd`；FIPS 为 `agentd-fips` |
| PKG | `/usr/local/bin/agentd` | `/usr/local/share/doc/agentd` |
| MSI | `Program Files/agentd` 或 `Program Files (x86)/agentd` | 同安装目录 |

普通 Linux 包名为 agentd，FIPS 包名为 agentd-fips，二者互斥，不能同时覆盖 `/usr/bin/agentd`。Windows 两架构使用本项目自己的独立升级码。MSI 默认不改 PATH；显式指定 `ADDLOCAL=Core,Path` 可加入机器 PATH。所有安装器仅安装 CLI 与文档，**不自动注册设备、写入凭据或启动系统服务**；本项目没有复制 cloudflared 的 service install 行为。状态目录保持用户独立管理，卸载不删除 profile。

项目未指定统一的开源许可证时，Linux 包 metadata 保持 `LicenseRef-Proprietary AND MPL-2.0`，不擅自授予整个项目 Apache/MIT 许可。第三方许可证保存在包内及独立 license bundle；以各组件原许可为准。

## 签名与 FIPS 的真实边界

tag 发布强制 Windows Authenticode 签名和 Apple Developer ID 签名/公证。缺少配置、签名失败、timestamp 无效或 Apple 未返回 Accepted 都停止发布，不能自动降级为 unsigned。普通 main/PR 构建明确生成 unsigned 测试产物；Go ARM64 ad-hoc 签名不代表 Developer ID。

配置与验证步骤见 [release-signing.md](release-signing.md)。GitHub `release-signing` environment 只划分 OIDC subject 和配置范围，不要求新增人工审批。`workflow_dispatch` 的 `signing_validation` 只允许在 main 上运行，完整签名/公证和安装测试后上传 artifact，不发布 GitHub Release。正式 `v*` tag 才发布。

Windows 使用官方 Azure Artifact Signing v2.0.0 + Azure login v3.1.0，两者固定 commit，OIDC 只在 Windows 签名 job 授予 `id-token: write`。签名顺序是 EXE → 验证签名和 timestamp → 用该 EXE 构建 MSI → 签 MSI → 再验证两者并安装测试 → SHA256SUMS。保留本地 `-SignThumbprint` 签名方式，不读取未指定的证书。

macOS 先对 CLI 执行 Developer ID Application codesign（hardened runtime + secure timestamp），然后构建 PKG 并用 Developer ID Installer productsign。Apple 公证分别提交 PKG 和包含 **TGZ 内同一已签名 CLI** 的 ZIP；两次都 Accepted 后对 PKG staple/validate 并作 Gatekeeper install assessment。裸 Mach-O CLI 与 TGZ **不能 staple**：TGZ 的 CLI 通过其签名 CDHash 取得在线公证票据，离线分发应使用已 stapled 的 PKG。最终校验 TGZ 内的 CLI 字节与公证输入相同，才生成校验和；不把 ZIP 临时载体作为额外发布产品。

Apple 私钥、证书与公证凭据只落在权限受限临时目录/keychain，不进入源码或 artifact。脚本在成功/失败/普通终止信号后恢复原 keychain 搜索列表，删除临时 keychain/文件；不修改 runner 默认 keychain。`BUILDINFO.json` 聚合各目标的签名、公证、staple 状态与提交 ID，正式汇总阶段再次拒绝任何缺失状态。

本地已有签名证书仍可使用：

```sh
bash scripts/build-release.sh --os darwin --arch arm64 --version v0.1.0 --out dist \
  --app-sign-identity 'Developer ID Application: YOUR IDENTITY' \
  --sign-identity 'Developer ID Installer: YOUR IDENTITY'
```

这条本地命令只签名；正式公证入口为 `scripts/sign-macos.py`，读取文档列出的 environment 配置。

FIPS 产物固定 `GOFIPS140=v1.0.0-c2097c7c`，这是 Go 1.27.2 自带 `lib/fips140/certified.txt` 对应的精确模块版本，不随 `latest` 漂移。构建检查 `go version -m` 中的模块值和 `DefaultGODEBUG=fips140=on`；Linux CI 还实际运行 FIPS 探针与客户端测试。证据覆盖所用 Go 模块和默认运行模式，**不是 agentd 整体产品获得 NIST 认证，也不继承 Cloudflare 的证书**。生产合规仍取决于模块安全策略和实际部署环境。

```sh
NFPM=/tmp/agentd-tools/nfpm TARGET_OS=linux TARGET_ARCH=amd64 FIPS=true VERSION=v0.1.0 make release
python3 scripts/release.py verify-fips --binary dist/agentd-fips-linux-amd64
```

交叉编译、包结构校验、原生安装测试分别是不同证据。ARMv5/v7 与 386 目标没有在全部实际设备上验证；真实 CDN、系统服务管理和生产容量也不由发布流水线保证。
