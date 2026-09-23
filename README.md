# GateSocks

GateSocks 是一个面向个人 VPS 的 SOCKS5 出口筛选、验证与管理项目。Web 面板负责节点池、SOCKS5、OpenVPN 隧道、测试记录、日志和设置；OpenVPN 是底层出口隧道，SOCKS5 是主要使用入口。

当前开发版本：`v0.4.0-dev`。

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

运行前先设置管理员密码和 Session Secret：

```bash
export GATESOCKS_ADMIN_USER=admin
export GATESOCKS_ADMIN_PASS='请设置强密码'
export GATESOCKS_SESSION_SECRET="$(openssl rand -hex 32)"
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

## Web authentication

从 v0.3.0-dev 开始，管理页面与管理 API 默认需要登录；`/health` 保持公开供 Docker/Caddy 健康检查使用。

- `POST /api/login`：登录并签发 HttpOnly Session Cookie
- `POST /api/logout`：退出并删除 Cookie
- `GET /api/me`：读取当前登录状态
- Session 使用 HMAC-SHA256 签名并带过期时间，默认 12 小时
- 密码和 Session Secret 只从环境变量读取，不写入仓库
- 经 HTTPS 域名正式使用时设置 `GATESOCKS_COOKIE_SECURE=true`

不要在公网暴露未配置认证的管理面板。

## v0.3.1-dev

- 修复 `static/app.js` 中被误写为字面量 `\n` 导致的前端语法错误，菜单与页面切换恢复可用。
- 增加 GateSocks 品牌 favicon，并为 `/favicon.ico` 提供兼容入口，消除浏览器 404。
- 主面板恢复当前用户显示与退出按钮；API 遇到 401 时自动返回登录页。
- `.env` 与本地环境备份文件加入忽略规则，避免认证密码与 Session Secret 被误提交。

## v0.4.0-dev

- 接入 VPN Gate 官方 iPhone/API 候选节点池；首次打开面板会在缓存为空时自动拉取，也可在“节点池”手动刷新。
- 候选表中的 Ping/Speed 标记为公益源公布值，不冒充 GateSocks 本 VPS 的真实测速结果；OpenVPN 实连、出口 IP、ISP/ASN、住宅/风险、上传下载与稳定性仍按后续实测阶段处理。
- 节点缓存持久化到 `./data/vpngate_nodes.json`，OpenVPN 配置数据只保存在后端缓存，不下发到浏览器表格。
- “设置 → 管理员账号”新增修改用户名/密码；要求输入当前密码，新密码使用 PBKDF2-SHA256 哈希后保存到 `./config/auth.json`，不写入仓库；修改后旧 Session 自动失效并签发当前 Session。
- Docker 构建增加 Python 语法检查，工作流版本同步到 `v0.4.0-dev`。
