# bmc-provisioner

面向现场首次配置单台 BMC 的桌面与容器化工具。它从本机 `lessor` 获取已经
确认的 BMC 临时 DHCP 地址，再用 Redfish 修改初始密码和 IPv4 网络配置。

当前范围、架构与开发顺序见：

- [MVP 设计](docs/design.md)
- [开发计划](docs/development-plan.md)
- [本地 API](docs/api.md)

> 这是独立项目。lessor 只负责 DHCP 与 BMC IPMI 发现；本项目不修改 lessor
> 的配置，也不承载 DHCP 服务。

## 当前开发版本

服务核心已经可以读取 lessor 的 confirmed BMC，并通过标准 Redfish 路径创建计划和
执行改密/静态 IPv4 任务。当前只使用 HTTPS Basic Auth；桌面 UI、BMC 自签名证书的
指纹确认、Mock 测试及真实硬件验证仍在后续阶段，不能将此开发版本直接当作生产工具。

本地构建与检查：

```powershell
cargo fmt --check
cargo test
cargo clippy -- -D warnings
cargo run --bin bmc-provisionerd
```

服务默认只监听 `http://127.0.0.1:6770`；例如 `GET /healthz` 返回 `204`。

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

容器版本复用同一个 Rust 服务和前端构建产物：

```powershell
docker compose up --build
```

容器端口只映射到主机 loopback，浏览器访问 `http://127.0.0.1:6770`。若 lessor 仍运行在
Windows 主机，页面中的 lessor 地址应填写 `http://host.docker.internal:6767`，而不是
`127.0.0.1`。
