# 多架构构建与发布

仓库：`github.com/bit-precise/agentd`。GitHub Actions 配置位于 [build.yml](../.github/workflows/build.yml)，单目标打包入口为 [build-release.sh](../scripts/build-release.sh)。

架构矩阵来自 cloudflared `8e090e5bfa7a53e824fb2d7eb276f8ab08337b80` 的 GitLab 构建配置；这里迁移为 GitHub Actions。它复用 9 个常规目标，不复制 Cloudflare 的内部 runner、Vault、签名凭据、R2/APT/RPM 发布或 FIPS 产品承诺。

| 系统 | 产物架构 | Go 目标 | 格式 |
|---|---|---|---|
| Linux | 386、amd64、arm64 | 对应 GOARCH | tar.gz |
| Linux | arm | GOARCH=arm，GOARM=5 | tar.gz |
| Linux | armhf | GOARCH=arm，GOARM=7 | tar.gz |
| macOS | amd64、arm64 | 对应 GOARCH | tar.gz |
| Windows | amd64、386 | 对应 GOARCH | zip |

**触发与检查**

- 推送 main、针对 main 的 PR 和手动运行触发测试与构建。
- Go 固定 1.27.2，与当前参考项目一致。Ubuntu、macOS、Windows 运行原生测试和 vet；Ubuntu/macOS 运行 race。手动运行可额外启用 Linux ARM64 原生测试。
- 下载模块后检查 go.mod/go.sum 未改变；构建使用 `-mod=readonly`、`-trimpath`、CGO=0，普通构建关闭意外继承的 FIPS 设置。
- 9 个目标交叉编译并分别上传 artifact，汇总任务重新验证各目标 SHA256SUMS，生成完整下载包和统一校验文件。
- 只有推送 `v*` tag 才创建/更新对应 GitHub Release；普通分支和 PR 不发布 Release。写仓库权限仅授予 tag 发布任务，第三方 Actions 固定到已核实的官方 commit。

普通构建完成后，在 Actions 的 `agentd-release-<version>` artifact 中下载所有平台压缩包与 SHA256SUMS。tag 发布完成后，在 GitHub Releases 下载同样文件。当前产物未进行 Apple/Windows 代码签名，也不提供 deb/rpm/pkg/msi 安装包。

**本地构建**

```sh
make test lint
make agentd
TARGET_OS=linux TARGET_ARCH=arm64 make agentd OUTPUT=bin/agentd-linux-arm64
TARGET_OS=windows TARGET_ARCH=amd64 make agentd
TARGET_OS=linux TARGET_ARCH=arm TARGET_ARM=7 VERSION=v0.1.0 make release
```

`make agentd` 默认使用当前系统/架构，并将版本写入 `agentd version`。Windows 默认输出 `bin/agentd.exe`。`make release` 默认输出到 dist，包内包含二进制、配置示例、运行说明、来源/许可信息及 BUILDINFO；自定义目标必须来自上表。

**平台运行边界**

Windows 的 profile 使用 owner/DACL 校验与内核文件锁，不能用 Unix chmod 位替代；新建私有状态目录会建立受限继承 DACL。已有目录必须仅授予当前用户及受信主机管理员（SYSTEM/Administrators）访问，拒绝宽权限目录、UNC/device 路径、reparse 路径和备用数据流。Windows 控制台使用 Ctrl+C 退出，没有 SIGHUP 重载；配置变更需重启。Linux/macOS 继续使用私有权限和 flock。

交叉编译成功不等于在每种设备上完成运行验收。原生 OS 测试覆盖主要运行路径；ARMv5、ARMv7、Linux 386 和 Windows 386 的真机部署、真实 CDN 与性能验收仍需按部署环境进行。
