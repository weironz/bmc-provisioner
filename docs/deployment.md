# Docker Compose 部署指引

`bmc-provisioner` Compose 会在同一台 Linux 主机启动两个服务：

- `lessord`：为直连 BMC 或 DHCP Relay 转发的请求提供 DHCP 服务，并发现 BMC；
- `bmc-provisioner`：从本机 lessor 读取候选 BMC，通过 Redfish 完成改密与静态 IPv4 配置。

## 前置条件

- Linux 主机可路由到目标 BMC 管理网；直连模式下，主机必须有连接 BMC 的物理网卡。
- 已安装 Docker Engine 与 Docker Compose v2。
- DHCP Relay 模式下，交换机 Relay 的目标地址应指向这台 Linux 主机，且 UDP 67 可达。
- 管理员已规划 DHCP 地址池、目标 BMC IPv4、前缀和网关。

## 快速部署

```sh
git clone https://github.com/weironz/bmc-provisioner.git
cd bmc-provisioner
cp .env.example .env
docker compose pull
docker compose up -d
docker compose ps
```

默认会创建两个命名卷，分别保存 lessor 配置/租约和 BMC 配置清单。

## 访问界面

默认 Compose 使用 host 网络，且两个 HTTP 服务监听 `0.0.0.0`：

| 服务 | 地址 | 用途 |
| --- | --- | --- |
| lessor | `http://<服务器地址>:8080` | 创建作用域、查看租约和发现结果 |
| bmc-provisioner | `http://<服务器地址>:6770` | 管理 BMC 清单并执行 Redfish 配置 |

`bmc-provisioner` 容器内部仍通过 `http://127.0.0.1:8080` 访问同一主机的 lessor；这不是用户浏览器需要访问的地址。

## 网络与防火墙

默认对所有可达网络开放 `8080` 和 `6770`，便于远程管理，但它们没有面向公网的认证代理。生产环境应仅允许管理网访问这两个 TCP 端口，并允许 DHCP Relay/BMC 网络访问 UDP 67。

例如，使用 UFW 时可仅允许一个管理网段：

```sh
ufw allow from <管理网 CIDR> to any port 8080 proto tcp
ufw allow from <管理网 CIDR> to any port 6770 proto tcp
ufw allow from <BMC 或 Relay 网段 CIDR> to any port 67 proto udp
```

请按现场网络策略替换占位 CIDR；不要直接向公网开放这两个管理端口。

## 首次配置

1. 打开 lessor，选择正确网卡并新建 DHCP 作用域；Relay 模式则创建对应 Relay 网段的作用域。
2. 打开 bmc-provisioner。默认 lessor 地址保持 `http://127.0.0.1:8080`，因为两个容器使用 host 网络。
3. 在“凭据档案”创建 BMC 凭据，并为每行 BMC 选择对应档案、填写目标静态 IPv4。
4. 勾选已配对的 BMC 后执行配置；任务完成后在同一清单检查 Redfish 与认证状态。

Docker 默认启用 `BMC_PROVISIONER_SESSION_CREDENTIALS=1`。容器没有系统凭据管理器，因此密码只保存在容器内存中，重启后需要重新录入；SQLite 清单不会保存密码。

## 日常运维

```sh
# 查看状态与日志
docker compose ps
docker compose logs -f --tail=100

# 拉取 .env 固定版本的镜像并重建容器
docker compose pull
docker compose up -d
```

不要执行 `docker compose down -v`，除非确定要删除 lessor 配置、租约和 BMC 清单这两个命名卷。

镜像版本可在 `.env` 中通过 `LESSOR_IMAGE` 与 `BMC_PROVISIONER_IMAGE` 固定；修改后执行 `docker compose pull && docker compose up -d`。
