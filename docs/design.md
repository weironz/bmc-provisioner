# bmc-provisioner MVP 设计

## 目标

在 Windows 笔记本以网线直连一台出厂 BMC 的场景中，用户只填写 BMC 登录信息、
新密码和目标 IPv4 网络参数。工具自动从本机 lessor 找到 BMC 当前 DHCP 地址，
通过 Redfish 完成改密、关闭 DHCP、写入静态 IPv4，并在新地址重新认证验证。

## 非目标

- 不提供 DHCP、不修改 lessor 作用域。
- 不做多 IDC、资产管理、交换机端口查询、批量任务或监控。
- 不承诺所有厂商的 OEM Redfish 网络路径都相同；先实现标准 Redfish，按能力
  探测失败时给出可操作诊断。

## 架构

```text
Svelte Web UI / Tauri Desktop
             │ HTTP
             ▼
bmc-provisionerd (Axum)
  ├─ Lessor client: GET /api/v1/devices?kind=bmc
  ├─ Redfish client: ServiceRoot、Session、Account、Manager EthernetInterface
  ├─ Provision workflow: discover → password → network → verify
  ├─ Job log: 内存中，仅保存非敏感步骤状态
  └─ REST API: 供 Web、桌面端与 Docker 使用
             │ HTTPS
             ▼
             BMC Redfish
```

桌面端只打包 UI 和本地服务 sidecar；Docker 运行同一服务与 UI。业务逻辑只在 Rust
核心库中实现，避免两种部署形态产生不同的配置行为。

## 用户流程

1. 启动 lessor，在直连网卡作用域中为 BMC 发 DHCP 地址。
2. 打开 bmc-provisioner；页面读取 lessor 已确认的 BMC 列表。
3. 用户选择 BMC，填入用户名、当前密码、新密码、目标地址、前缀和网关。
4. 页面先请求 `plan`。服务验证地址、读取 Redfish Service Root、展示将写入的
   Ethernet Interface 和当前网络配置。
5. 用户确认后请求 `apply`。
6. 服务按固定顺序执行：
   - 创建 Redfish Session 或使用 Basic Auth。
   - 检查 `PasswordChangeRequired`；优先调用 `ChangePassword` Action，缺失时
     回退到 `PATCH ManagerAccount.Password`。
   - 重新认证，定位 `Managers/*/EthernetInterfaces/*`。
   - PATCH 静态 IPv4、掩码、网关和 `DHCPv4.DHCPEnabled=false`。
   - 连接通常会中断；轮询目标 IP，在限定时间内重新认证并读取网络配置。
7. 页面显示成功、失败阶段和安全的排障信息。密码绝不回显或记录。

## 数据与 API

### 读取 lessor

`GET {lessor_url}/api/v1/devices?kind=bmc[&scopeId=N]`

只接受 `confidence=confirmed` 的设备；若返回多台，必须由用户选择，绝不随意选
第一台。

### 本项目 API（第一版）

```text
GET  /api/v1/candidates?lessorUrl=...&scopeId=...
POST /api/v1/provision/plan
POST /api/v1/provision/plans/{plan_id}/apply
GET  /api/v1/jobs/{id}
```

`plan` 先通过 lessor 再次确认用户选中的 IP 仍是本作用域的 confirmed BMC，再访问
Redfish；生成的 plan 仅保存在内存，不含密码。`apply` 以 `plan_id` 和一次性重传的
账号密码发起任务并返回 job id。单 BMC 同时只允许一个进行中的 job。

## Redfish 兼容策略

先从 `/redfish/v1` 读取链接，不能把 `ManagerId`、账号 ID 或网卡 ID 写死。
网络配置以 Manager 的 EthernetInterface 为优先目标。响应中的 `@odata.type`、
`Actions`、`@Redfish.Settings` 和允许的方法决定实际写法。遇到 OEM-only 实现时
保留原始错误 MessageId，并标注需要新增厂商 adapter。

## 安全边界

- 当前密码、新密码只能出现在请求内存中；日志、错误、job 查询结果均不可含密码。
- 不接受任意 URL 转发；BMC 地址只能来自 lessor candidate 或用户明确确认的目标。
- 默认 HTTPS，首次直连自签名证书时 UI 明确展示指纹并要求用户确认；不静默忽略
  证书错误。
- Redfish Session 在任务结束时删除；失败时尽力清理。
- 变更前读取实际配置；变更后以新 IP 重新认证验证。无法验证时标为
  `network_changed_unverified`，不伪报成功。

## 验收条件

- lessor 返回一个已确认 BMC 时，UI 能展示当前 DHCP IP 与 MAC。
- Redfish mock 覆盖：正常 PATCH 改密、强制改密 Action、网络配置、会话中断后验证、
  认证失败和不支持的 EthernetInterface。
- 密码不出现在 API job 输出、终端日志或测试快照中。
- `cargo test`、`cargo clippy -D warnings` 与前端构建通过。
