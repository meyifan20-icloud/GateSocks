# GateSocks

GateSocks 是一个面向个人 VPS 的 SOCKS5 出口筛选、验证与管理项目。Web 面板负责节点池、SOCKS5、OpenVPN 隧道、测试记录、日志和设置；OpenVPN 是底层出口隧道，SOCKS5 是主要使用入口。

当前开发版本：`v0.2.0-dev`。

## Docker image

```text
ghcr.io/meyifan20-icloud/gatesocks:latest-dev
```

提交到 `main` 会自动构建开发镜像。当前仅构建 `linux/amd64`，用于现有 RN VPS。

## Current Web panel

已经实现：

- 响应式桌面 / 移动端 Web 面板
- 仪表盘
- 节点池页面骨架
- SOCKS5 管理页面与本地/外部访问卡片结构
- OpenVPN/TUN 状态检测
- 测试记录页面骨架
- 日志页面
- 端口与运行设置页
- FastAPI API 与健康检查

下一阶段接入真实 VPN Gate 拉取、OpenVPN 节点连接、出口 IP/住宅属性/风险/速度/稳定性检测，以及 SOCKS5 实例创建与自动重连。

## Runtime

- Python 3.12 slim
- FastAPI + Uvicorn
- OpenVPN
- iproute2 / iptables
- `/dev/net/tun`
- `NET_ADMIN`
- host network

Web 默认只监听：

```text
127.0.0.1:19080
```

SOCKS5 端口规划：

```text
18001-18099  正式 SOCKS5
18100-18149  节点测试
18150-18199  保留扩展
```

## Start

```bash
docker compose pull
docker compose up -d
docker compose logs -f gatesocks
```

打开本机页面：

```text
http://127.0.0.1:19080/
```

健康检查：

```bash
curl http://127.0.0.1:19080/health
```

> 当前仍是开发镜像。正式对公网开放管理面板前还需要完成认证与现有 Caddy / Cloudflare Origin Rule 接入。
