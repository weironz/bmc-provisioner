# 开发计划

## Phase 0 — 项目基线

- [x] 新建独立 Git 仓库。
- [x] 固化单机单 BMC MVP 边界与安全模型。
- [x] 初始化 Rust 服务核心与本地 HTTP API 基线；Web UI 与本地开发命令待 Phase 2。

## Phase 1 — 可测试的核心闭环

- [x] 实现 lessor candidate client 与响应校验。
- [x] 实现 Redfish Service Root、账户与 EthernetInterface 资源发现（当前 Basic Auth）。
- [x] 实现自签名 BMC 的无凭据指纹探测与显式证书钉扎。
- [x] 实现 password change 的 Action/PATCH 回退与重新认证。
- [x] 实现静态 IPv4/DHCP 配置和新 IP 有限重连验证。
- [x] 用 mock Redfish + mock lessor 覆盖正常发现、两种改密分支与网络写入。

## Phase 2 — 本地操作界面

- [x] 建立 Svelte plan/apply 页面与安全密码输入。
- [x] 显示当前 IP、目标 IP、任务状态和可恢复错误。
- [x] 添加 Tauri Desktop sidecar 与 `just app` 开发入口。

## Phase 3 — 可部署交付

- [x] Docker 镜像与 Compose 示例。
- [ ] 安装包、签名、GitHub Actions 发布流水线。
- [ ] 在一台真实 BMC 上验证并记录厂商/固件兼容矩阵。

## 后续，不属于 MVP

- 多 BMC YAML/CSV、SN 与交换机端口映射。
- Redfish 资产采集、指标、事件订阅。
- IDC Agent 与中心控制平面。
