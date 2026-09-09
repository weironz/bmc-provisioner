# bmc-provisioner

面向现场首次配置单台 BMC 的桌面与容器化工具。它从 `lessor` 获取已确认的 BMC，
或获取 DHCP Relay 作用域的活动租约候选；候选在执行前仍会由 Redfish 确认，再修改
初始密码和 IPv4 网络配置。

当前范围、架构与开发顺序见：

- [MVP 设计](docs/design.md)
- [开发计划](docs/development-plan.md)
- [本地 API](docs/api.md)

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
每行可关联一个凭据档案；SQLite 只保存档案名，桌面端密码保存在系统凭据管理器。

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
管理网的 Linux 主机**。lessord 使用 host 网络以接收 DHCP 广播；两个管理界面仅监听
该主机的 `127.0.0.1`，从办公网访问应使用 VPN 或 SSH 隧道。

```sh
cp .env.example .env
docker compose pull
docker compose up -d
```

首次启动后：

1. 通过 `http://127.0.0.1:8080` 打开 lessor，选择网卡并创建 DHCP 作用域；
2. 通过 `http://127.0.0.1:6770` 打开 bmc-provisioner；lessor 地址保持默认
   `http://127.0.0.1:8080`；
3. 在“凭据档案”创建 BMC 凭据，再在清单每行选择对应档案。Compose 默认使用
   `BMC_PROVISIONER_SESSION_CREDENTIALS=1`：由于容器通常没有系统密钥链，密码只
   保存到服务内存，容器重启后须重新输入，且绝不会写入 SQLite。

这套 Compose 使用命名卷持久化 lessor 配置/租约和 bmc-provisioner 清单。不要将
`docker compose down -v` 用于生产环境，它会删除这些卷。
