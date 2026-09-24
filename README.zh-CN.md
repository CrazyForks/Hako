<p align="center">
  <img src="assets/hako-logo-256.png" width="128" height="128" alt="Hako">
</p>

# Hako

[English](README.md) · 简体中文

[![官方网站](https://img.shields.io/badge/%E5%AE%98%E7%BD%91-%E8%AE%BF%E9%97%AE-2563EB)](https://clash.md/)
[![App Store 下载](https://img.shields.io/badge/App_Store-%E4%B8%8B%E8%BD%BD-black?logo=apple&logoColor=white)](https://apps.apple.com/app/id6794257189)
[![Telegram 频道](https://img.shields.io/badge/Telegram-%E9%A2%91%E9%81%93-26A5E4?logo=telegram&logoColor=white)](https://t.me/clashbyhako)
[![Telegram 交流群](https://img.shields.io/badge/Telegram-%E4%BA%A4%E6%B5%81%E7%BE%A4-26A5E4?logo=telegram&logoColor=white)](https://t.me/+t__WNRvjUbk3M2Nl)

Hako 是基于 **mihomo v1.19.31** 的代理内核，提供面向 Apple 应用的 Go 绑定与构建工具，可生成支持 iOS、macOS 和 tvOS 的 `Hako.xcframework`。

使用官方应用请点击顶部的 App Store 下载链接。本仓库面向构建或集成内核的开发者。

## 上游历史与修改说明

Hako 是基于 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 的独立衍生项目，上游基线为 [v1.19.31](https://github.com/MetaCubeX/mihomo/tree/v1.19.31)，提交为 `ab405bad5beeeac8b003bb01f60f134f6df54471`。本项目与 MetaCubeX 无隶属关系。上游要求无隶属关系的下游项目不要在项目名称中使用“mihomo”。

仓库保留上游原始提交及贡献者署名，同时保留 Hako 已有公开历史。上游稳定版本升级以合并提交接入：第一父链延续 Hako，第二父节点指向对应的官方上游提交；Hako 自身的修改继续按独立逻辑变更追加。比较上游基线与具体 Hako 提交，可查看 Apple 绑定、SDK 构建工具及内核适配的完整差异。

上游 GPL-3.0 许可证保留在 [LICENSE](LICENSE) 中。署名与依赖许可证见 [NOTICE](NOTICE) 和 [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。

## 项目仓库

| 仓库 | 内容 |
| --- | --- |
| [Hako](https://github.com/TokenPLS/Hako) | 代理内核、Go 绑定与 Apple SDK 构建工具 |
| [Hako-Adapter](https://github.com/TokenPLS/Hako-Adapter) | Swift 数据包桥接与扩展生命周期组件 |
| [Hako-Client](https://github.com/TokenPLS/Hako-Client) | iOS、iPadOS、macOS 和 tvOS 原生应用及扩展 |

上游基线版本表示代理引擎版本，与 App Store 应用版本、SDK 发布标签分别管理。当前源码分发仍处于预发布阶段；集成时请固定具体提交。

## 仓库内容

- 基于 mihomo 的代理引擎，包括协议实现、DNS、路由规则、代理组和资源提供者。
- `bind/hako`：通过 gomobile 暴露给 Apple 应用的接口。
- `cmd/build_libbox`：SDK 生成与平台打包工具。
- [`docs/config.yaml`](docs/config.yaml)：随源码提供的配置参考。

应用负责提供配置、存储、Network Extension 接入和签名。不同平台的能力有所区别；配置能被解析，不代表所有协议和规则都已在每个平台完成端到端验证。

Apple SDK 的 iOS 和 tvOS 切片使用 `no_easytier`，不包含 EasyTier；macOS 切片未应用这一排除。平台权限、TUN 栈及出站实现仍会影响实际能力。

## 构建 Apple SDK

需要 macOS、完整的 Xcode，以及 iOS、macOS、tvOS SDK。当前构建已使用 Xcode 27.0 验证。绑定模块在 [`bind/hako/go.mod`](bind/hako/go.mod) 中声明 Go 1.25.0，并选择 Go 1.26.6 工具链；请允许 Go 获取该工具链，或自行安装。

完整克隆仓库及标签，然后安装固定版本的 gomobile 工具：

```sh
git clone https://github.com/TokenPLS/Hako.git
cd Hako
go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.13
go install github.com/sagernet/gomobile/cmd/gobind@v0.1.13
make lib_apple
```

内核版本由随源码发布的 `UPSTREAM_VERSION` 指定，避免升级源码后误用较旧的 SDK 标签。SDK 发布版本仍由当前提交的发布标签决定；普通源码构建标为 `dev-<提交>`。

输出为 `Hako.xcframework`，包含五个平台切片：

| 平台 | 架构 |
| --- | --- |
| iOS 真机 | arm64 |
| iOS 模拟器 | arm64、x86_64 |
| macOS | arm64、x86_64 |
| tvOS 真机 | arm64 |
| tvOS 模拟器 | arm64、x86_64 |

SDK 是静态框架，直接链接时将嵌入选项设为 **Do Not Embed**，并链接 `libresolv`。应用和扩展可通过共享的动态框架封装它，避免重复打包内核；Client 的 iOS 和 macOS 工程已采用这种结构。具体接口以所固定提交生成的头文件为准。完整应用的接入方式可参考 [Hako-Client](https://github.com/TokenPLS/Hako-Client)。

## 开发与反馈

根目录 Go 模块可使用以下命令构建和测试：

```sh
go build ./...
go test ./...
```

Apple 绑定在 `bind/hako` 下有独立模块和测试。SDK 构建成功不代表签名真机上的运行行为已经验证。

内核问题请提交到本仓库的 [Issues](https://github.com/TokenPLS/Hako/issues)，附上源码提交、平台、复现步骤、预期行为与实际结果。配置示例应尽量精简，并移除密钥等敏感内容。应用界面或安装问题请提交到 [Hako-Client Issues](https://github.com/TokenPLS/Hako-Client/issues)。

安全问题请遵循 [SECURITY.md](SECURITY.md) 的报告方式。

## 许可证与致谢

Hako 基于 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) 及其贡献者的工作。Hako 是独立项目，与 MetaCubeX 没有隶属或背书关系。

项目采用 [GPL-3.0](LICENSE) 许可证。署名与依赖许可证见 [NOTICE](NOTICE) 和 [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。
