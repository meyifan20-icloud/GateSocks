# GateSocks

GateSocks 是一个面向个人 VPS 的 SOCKS5 出口筛选、验证与管理项目。Web 面板负责节点池、SOCKS5、OpenVPN 隧道、测试记录、日志和设置；OpenVPN 是底层出口隧道，SOCKS5 是主要使用入口。

当前开发版本：`v0.2.1-dev`。

## Docker image

```text
ghcr.io/meyifan20-icloud/gatesocks:latest-dev
```

## RN VPS deployment layout

GateSocks 使用普通 Docker bridge 网络，并加入现有 Sublink Caddy 所在的 `sublink-worker_default` 网络。这样现有 Caddy 可以直接通过容器名访问：

```text
gatesocks:19080
```

同时宿主机只保留本地健康检查：

```text
127.0.0.1:19080
```

如果实际 Sublink 网络名不同，可在启动前设置：

```bash
export SUBLINK_NETWORK=实际网络名
```

运行：

```bash
docker compose pull
docker compose up -d
curl http://127.0.0.1:19080/health
```

当前不会把 18001-18199 SOCKS5 端口直接暴露到公网；等用户名/密码认证和防火墙策略接入后再开放。

## Caddy

现有 Sublink Caddy 与 GateSocks 在同一个 Docker 网络后，新域名可以使用：

```caddy
gatesocks.zhangbao20.ccwu.cc:2096 {
    tls /certs/fullchain.cer /certs/zhangbao20.ccwu.cc.key
    reverse_proxy gatesocks:19080
}
```

证书文件名请以现有 Sublink Caddyfile 的实际路径为准，不要凭示例覆盖现有配置。
