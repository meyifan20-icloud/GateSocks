# GateSocks

GateSocks 是一个面向个人 VPS 的 SOCKS5 出口筛选与管理项目。

当前版本：`v0.1.0-dev`。这一阶段先建立稳定的 Docker/GHCR 基础镜像与运行骨架，后续再接入节点筛选、OpenVPN 隧道管理、SOCKS5 实例生成与 Web 面板。

## Docker image

开发镜像：

```text
ghcr.io/meyifan20-icloud/gatesocks:latest-dev
```

提交到 `main` 会自动构建 `latest-dev`；Git tag 会发布对应版本标签。

## Runtime

默认设计：

- Python 3.12 slim
- OpenVPN
- iproute2 / iptables
- curl / ca-certificates
- `/dev/net/tun`
- `NET_ADMIN`
- host network

管理服务默认监听：

```text
127.0.0.1:19080
```

后续由现有 Caddy 反向代理；SOCKS5 实例将使用独立端口段。

## Start

```bash
docker compose pull
docker compose up -d
docker compose logs -f gatesocks
```

健康检查：

```bash
curl http://127.0.0.1:19080/health
```

> 当前为开发镜像，不视为正式版本。
