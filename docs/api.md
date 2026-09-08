# 本地 API（开发中）

服务默认只监听 `127.0.0.1:6770`。它是桌面端的本地 sidecar 接口，不应直接暴露到
局域网或公网。

开发阶段的 Svelte/Vite 页面会运行在另一条本机端口，服务因此允许来自本机 Web UI 的
跨域请求；这不会改变服务仅绑定 loopback 的边界。

## 获取 lessor 确认的 BMC

```text
GET /api/v1/candidates?lessorUrl=http://127.0.0.1:6767&scopeId=1
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

## 执行计划与查询状态

```text
POST /api/v1/provision/plans/{planId}/apply
GET  /api/v1/jobs/{jobId}
```

`apply` 请求再次携带 `credentials`，因为服务永不把密码放入 plan 或 job。它返回 HTTP
202 与 job。网络写入后最多以 5 秒间隔重连 12 次；连接尚未恢复时结果是
`network_changed_unverified`，不视为完成。
