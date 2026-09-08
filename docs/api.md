# 本地 API（开发中）

服务默认只监听 `127.0.0.1:6770`。它是桌面端的本地 sidecar 接口，不应直接暴露到
局域网或公网。

开发阶段的 Svelte/Vite 页面会运行在另一条本机端口，服务因此允许来自本机 Web UI 的
跨域请求；这不会改变服务仅绑定 loopback 的边界。

## 获取 lessor 确认的 BMC

```text
GET /api/v1/candidates?lessorUrl=http://127.0.0.1:8080&scopeId=1
```

只返回 lessor 标记为 `kind=bmc` 且 `confidence=confirmed` 的设备。

## 创建计划

```text
POST /api/v1/provision/plan
```

请求必须提供 `lessorUrl`、`scopeId`、`candidateIp`、`credentials`、`targetNetwork` 和
可选的 `ethernetInterfaceUri`。服务会重新查询 lessor，拒绝不在该作用域 confirmed BMC
列表中的地址。响应包含不带密码的 `planId` 和 Redfish 资源路径。

如果 BMC 暴露多块管理网卡，第一次请求不填 `ethernetInterfaceUri` 会返回需要选择的错误；
UI 应展示这些路径，让用户明确选择后再次创建计划。

## 自签名证书探测

```text
POST /api/v1/certificates/probe
```

请求提供 `lessorUrl`、`scopeId` 与 `candidateIp`。服务先向 lessor 重新确认候选 BMC，
然后在不发送账号密码的前提下读取其 HTTPS 叶证书 SHA-256 指纹。用户确认该值后，将它作为
`certificateFingerprint` 传入 `plan`；后续 Redfish 连接会钉住该证书，而不是关闭 TLS 校验。

## 执行计划与查询状态

```text
POST /api/v1/provision/plans/{planId}/apply
GET  /api/v1/jobs/{jobId}
```

`apply` 请求再次携带 `credentials`，因为服务永不把密码放入 plan 或 job。它返回 HTTP
202 与 job。网络写入后最多以 5 秒间隔重连 12 次；连接尚未恢复时结果是
`network_changed_unverified`，不视为完成。

## 已知静态 BMC 的只读诊断

```text
POST /api/v1/diagnostics/redfish/certificate
POST /api/v1/diagnostics/redfish
```

第一个接口只需要用户明确输入的 `bmcIp`，用于无凭据读取证书指纹。第二个接口接受
`bmcIp`、当前用户名/密码和可选、已确认的 `certificateFingerprint`，只读取 Redfish
Service Root、账户与管理网卡。它永不创建 provisioning plan/job，也没有 PATCH 或 POST
给 BMC 的代码路径。
