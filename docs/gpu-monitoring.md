# GPU 与硬件监控

设备详情的自动采集快照增加 `gpu` 与 `hardware`。面板沿用绿灰配色，容量/计数使用等宽数字。顶部摘要六列，功率与温度趋势并排；GPU 默认每卡一行，窄窗口每卡两行，不依赖横向滚动。ECC、带宽及错误原因按行展开；硬件分类默认折叠，展开后多列紧凑展示。

## 数据来源与语义

| 指标 | Redfish 字段 |
| --- | --- |
| GPU 清单、型号、状态 | ComputerSystem → Processors；ProcessorType=GPU |
| 单卡显存 | Processor.MemorySummary.TotalMemorySizeMiB |
| 温度、功率、功率上限 | EnvironmentMetrics 的 TemperatureCelsius.Reading、PowerWatts.Reading、PowerLimitWatts.SetPoint |
| GPU SM 利用率 | ProcessorMetrics.Oem.Nvidia.SMUtilizationPercent |
| 显存占用率 | MemoryMetrics.CapacityUtilizationPercent |
| 显存带宽利用率 | MemoryMetrics.BandwidthPercent（不是显存占用率） |
| 显存 ECC 累计错误 | MemoryMetrics.LifeTime 下 CorrectableECCErrorCount / UncorrectableECCErrorCount |
| 行重映射 | MemoryMetrics.Oem.Nvidia.RowRemapping 下对应计数 |

优先跟随返回的资源链接。识别到 B300/HGX 时使用 HGX_Baseboard_0 的权威 GPU 清单及已知指标路径，不重复累计 System_0 中同卡的别名，也不将 FPGA 计为 GPU。显存按每张卡的容量求和，不假定卡型一致；清单或任意容量缺失时不显示误导性的总容量。

`availableCount` 统计已识别卡中 `Status.State=Enabled` 的数量，不等于运行任务数量。任意卡状态缺失时该值为空。GPU 清单读取完整且无 GPU 时隐藏 GPU 面板；读取失败时显示“尚未确认”，不得把失败当作 CPU-only。

零读数正常显示为 0。空值、负数哨兵、非有限数、超出 0–100 的百分比不作为读数。接口读取失败与固件未发布字段分开提示。累计 ECC 非零不意味着当前正在发生故障，需要结合事件日志判断。

GPU 可选采集单独限制 25 秒总预算、单请求 4 秒，串行读取指标，避免 BMC 对并发认证请求的兼容性问题；先完成清单再读指标，指标失败不丢弃卡信息。通用系统清单最多 16 个系统、每个集合最多 8 页、每页最多 128 个成员；超出限制标记为部分清单。

风扇、电源模块取自 Chassis Thermal/Power；磁盘取自 Storage.Drives；主机网口取自 ComputerSystem.EthernetInterfaces。仅展示实际返回的资源，空类别不等于未安装。此版本未遍历所有厂商的 OEM 硬件树。

GPU 指标目前是自动更新的当前快照；历史曲线仍是整机功率与最高温度，未新增 GPU 逐卡历史存储。

## 验证

### ASRockRack B300 产品标识与整机功率

- 产品 SN 优先使用 `Systems/System_0.SerialNumber`；不要用主板或机箱 SN 替代。
- 型号先读 `ComputerSystem.Model`，再跟随 `FruInfo`。实机固件 1.40.00 的 Redfish FRU 仅返回描述，因此仅对 ASRockRack 且公开脚本声明 AMI API 的设备，通过临时 Web 会话只读 `/api/fru`，取 `BMC_FRU.product.product_name`，随后注销该临时会话。已保存型号作为后续采集回退，不每轮登录 Web。不会调用改密接口。
- BMC MAC 从 `Links.ManagedBy → EthernetInterfaces` 中与当前 BMC IPv4 相匹配的接口获取，不使用主机业务网口或 USB 内部地址。
- 整机当前功率取 `Chassis/BMC_0/Power → PowerControl[0].PowerConsumedWatts`，为空时兼容 AMI 的 `PowerMetrics.CurConsumedWatts`；不使用平均值、功率限额或 HGX 底板功率替代。缺失仍为空，零值保留。
- **历史口径变化**：修正前 B300 的整机功率曲线可能保存了 HGX 底板功率。旧数据保留，不视为同口径的整机功率；修正后的新采样为主机机箱功率。
- 新增数据库可空列 `bmc_mac / serial_number / hardware_model`，不删除或覆盖原档案 MAC。部分采集失败保留已确认标识；更换 IP 清除自动标识，忽略旧 IP 的迟到结果；复制设备不复制自动标识。旧程序回滚可忽略额外列，无需删列。

- `cargo test`：CPU-only、发现失败、混合容量、FPGA 排除、离线卡、缺失与零值、权限失败、HGX/主机重复目录。
- `cd ui; bun run check; bun run build`。
- Vite 开发服务的 `/tests/telemetry.html` 是明确标注的独立样例页，不调用 BMC，也不进入生产构建入口。用于检查零值、缺失值、卡片布局、诊断展开和 CPU-only 隐藏。

字段语义参考 [DMTF 属性指南](https://redfish.dmtf.org/schemas/v1/DSP2053_2023.3.html)、[NVIDIA 环境指标接口](https://docs.nvidia.com/datacenter/dps/versions/latest/guides/concepts/redfish.html)、[Cisco 发布的 NVIDIA SM 利用率示例](https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/api/2-0-1/b_cisco-bmc-rest-api-guide-2-0/m_cisco-bmc-2-0-rest-api-examples.html)。
