# bmc-provisioner

## Windows 桌面端更新

安装包安装后的桌面端可点击左上角版本号，检查新版本。更新包由 GitHub Release
提供，客户端会先验证 Tauri 签名，再下载安装并重启。Docker 与 Linux 二进制不走
桌面自动更新，仍按部署方式升级。

面向现场首次配置单台 BMC 的桌面与容器化工具。它从 `lessor` 获取已确认的 BMC，
或获取 DHCP Relay 作用域的活动租约候选；候选在执行前仍会由 Redfish 确认，再修改
初始密码和 IPv4 网络配置。

当前范围、架构与开发顺序见：

- [MVP 设计](docs/design.md)
- [开发计划](docs/development-plan.md)
- [本地 API](docs/api.md)
- [Docker Compose 部署指引](docs/deployment.md)
- [ASRR 8U16X GNR2 B300 首次登录兼容说明](docs/asrr-8u16x-gnr2-b300-first-login.md)

> 这是独立项目。lessor 只负责 DHCP 与 BMC IPMI 发现；本项目不修改 lessor
> 的配置，也不承载 DHCP 服务。

## 当前开发版本

服务核心可以读取 lessor 的 confirmed BMC；对 Relay 网段则读取活动 DHCP 租约，并在
执行前完成 HTTPS/Redfish 验证。它通过标准 Redfish 路径执行改密/静态 IPv4 任务。

本地构建与检查：

```powershell
cargo fmt --check
cargo test
cargo clippy -- -D warnings
cargo run --bin bmc-provisionerd
```

服务默认只监听 `http://127.0.0.1:6770`；例如 `GET /healthz` 返回 `204`。

每次配置完成或失败后，BMC 的 MAC、源/目标地址、证书指纹、配置结果和最后检查状态会
保存在本机 SQLite 清单中（Windows 默认位于 `%LOCALAPPDATA%\\bmc-provisioner\\inventory.sqlite3`）。
日常 BMC 管理使用每台设备自己的用户名和加密密码密文；数据库主密钥不在 SQLite 中：
Windows 桌面端保存在系统凭据管理器，容器部署从 Docker Secret 或挂载密钥文件读取。

## BMC 管理（B300 初始支持）

桌面端的“BMC 管理”页以本地 SQLite 清单为主，支持为服务器条目命名、手动增删改、
批量刷新在线/Redfish/认证/电源状态，以及对勾选条目批量开机、关机和重启。首次使用
自签名 HTTPS 证书时，必须在页面确认显示的 SHA-256 指纹，程序才会保存该指纹并发送
认证请求。

电源操作不会假定某个厂商路径或 ResetType：程序读取 `ComputerSystem.Reset` 的目标与
`ResetType@Redfish.AllowableValues` 后才启用相应按钮。当前在 B300 的 AMI MegaRAC
Redfish 实现上验证；其他机型只有在声明兼容标准资源和动作时才会被允许执行。

“集群”页仅保存集群名称，用于组织任意大小的 BMC 分组。每台 BMC 通过本地
`clusterId` 归属到一个集群；可在 BMC 管理页勾选多台后批量加入集群。lessor 的动态
发现只更新候选地址，不会覆盖这项归属。删除集群会将其成员改为未分配，保留全部 BMC
条目与操作历史。

另开一个终端可启动开发界面：

```powershell
cd ui
bun install
bun run dev
```

然后访问 Vite 输出的本机地址（默认 `http://127.0.0.1:5173`）。先启动
`bmc-provisionerd`，页面才能访问 `127.0.0.1:6770` 的本地 API。

桌面开发入口会构建 sidecar 并自动停止已有的开发桌面壳：

```powershell
just app
```

## IDC Docker Compose

`compose.yaml` 同时启动 `lessord` 与 bmc-provisioner，适合部署在**可路由到 BMC
管理网的 Linux 主机**。lessord 使用 host 网络以接收 DHCP 广播；默认通过宿主机所有
地址开放 Web 管理界面。完整的前置条件、防火墙示例、升级与数据卷说明见
[部署指引](docs/deployment.md)。

```sh
cp .env.example .env
docker compose pull
docker compose up -d
```

首次启动后：

1. 通过 `http://<服务器地址>:8080` 打开 lessor，选择网卡并创建 DHCP 作用域；
2. 通过 `http://<服务器地址>:6770` 打开 bmc-provisioner；lessor 地址保持默认
   `http://127.0.0.1:8080`；
3. 先创建 Compose 所需的主密钥文件：`mkdir -p secrets && openssl rand -base64 48 >
   secrets/bmc-provisioner-master-key && chmod 600 secrets/bmc-provisioner-master-key`。随后在
   “设备清单”的每台 BMC 编辑页保存用户名和密码；密码会以密文持久化，容器重启后仍可使用。

这套 Compose 使用命名卷持久化 lessor 配置/租约和 bmc-provisioner 清单。不要将
`docker compose down -v` 用于生产环境，它会删除这些卷。
