# bmc-provisioner

面向现场首次配置单台 BMC 的桌面与容器化工具。它从本机 `lessor` 获取已经
确认的 BMC 临时 DHCP 地址，再用 Redfish 修改初始密码和 IPv4 网络配置。

当前范围、架构与开发顺序见：

- [MVP 设计](docs/design.md)
- [开发计划](docs/development-plan.md)

> 这是独立项目。lessor 只负责 DHCP 与 BMC IPMI 发现；本项目不修改 lessor
> 的配置，也不承载 DHCP 服务。
