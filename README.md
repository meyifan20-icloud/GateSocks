# GateSocks

GateSocks 是一个面向个人 VPS 的 SOCKS5 出口筛选、验证与管理项目。Web 面板负责节点池、SOCKS5、OpenVPN 隧道、测试记录、日志和设置；OpenVPN 是底层出口隧道，SOCKS5 是主要使用入口。

当前开发版本：`v0.4.9-dev`。

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

正式 SOCKS5 端口池 18001–18099/tcp 会由 Compose 映射到宿主机；只有已生成且正在运行的实例实际监听对应端口，并强制用户名/密码认证。请同时使用 VPS 防火墙限制不需要的来源。

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

## v0.4.1-dev

- 启用“开始实测筛选”：默认对当前筛选结果前 5 个候选逐个建立临时 OpenVPN 隧道。
- 测试隧道使用独立 Linux UID 策略路由表，只把测速进程送入临时 TUN，避免修改 GateSocks Web/Caddy 的默认路由。
- 实测真实出口 IPv4、TLS 建连延迟、约 2 MB 下载、约 512 KB 上传、3 次出口连续性；结果持久化到 `./data/test_results.json`。
- 使用公开 IP 属性接口补充 ISP/ASN 与 hosting/proxy/mobile 信号；“住宅倾向”保留“需复核”标记，不把单一数据库信号当作住宅 IP 的绝对证明。
- OpenVPN 配置在执行前移除脚本、plugin、management、route/redirect-gateway 等会执行外部代码或改变全局路由的指令。
- 测试记录页同步展示成功与失败原因；实测按钮支持任务进度轮询。


## v0.4.2-dev

- 按 OpenVPN 官方文档修正临时设备：使用 `tun-gstest0` + `--dev-type tun`，解决自定义设备名无法识别的问题。
- 显式 `--disable-dco`，让临时测试固定走传统 TUN；为 VPN Gate / SoftEther 兼容显式加入 `AES-128-CBC` 到 `data-ciphers`。
- 删除过短的 TLS `hand-window` 覆盖，连接总等待改为 30 秒，降低高延迟公益节点的误判。
- 测速 curl 以独立低权限 UID 运行，并从 stdin 上传测试数据，避免低权限进程无法读取 root 私有临时目录。
- 延迟改为 3 次 TCP 建连时间中位数；Cloudflare `__down/__up` 只用于隧道吞吐抽样。
- 扩展 VPN Gate 配置清洗：拒绝嵌套 config、脚本、代理、daemon/chroot/log/user/group 等与候选测试无关或可能改变进程行为的指令。
- 住宅/风险只显示公开 IP 数据库的辅助信号，不再把“未发现 hosting/proxy 标记”直接等同于“低风险住宅 IP”。
- GitHub Actions 增加 Python 编译、单元测试、JavaScript 语法和 Compose 配置预检，避免仅靠镜像能否构建判断代码正确性。


## v0.4.3-dev

- 节点池所有节点均允许手动选择：候选、实测通过、本次实测失败都不会被禁用；测试结果仅作参考，最终选择权交给使用者。
- 当前选择持久化到 `./data/selected_node.json`，仪表盘“选择 / 更换节点”跳转后可直接选择任意候选，仪表盘同步显示当前选择。
- 测试记录增加数据来源与判定依据：VPN Gate 提供候选、源 Ping/Speed；ipify/icanhazip 确认真实出口；Cloudflare Speed Test 提供隧道吞吐抽样；ip-api.com 提供 ISP/ASN 与 `hosting/proxy/mobile` 信号。
- 每条测试记录可展开查看实际判据；`hosting=true` 或 `proxy=true` 标记为非住宅/代理倾向，`mobile=true` 标记为移动网络倾向，三者均 false 只代表“未发现相应标记”，不证明一定是住宅 IP。
- 节点表 ISP 与 ASN 同时展示；“不可用”文案改为“本次实测失败”，避免把一次测试结果解释为永久不可用。


## v0.4.4-dev

- 节点池彻底分开“公益源数据”和“本 VPS 实测数据”：源 Ping*、源线路速度* 使用 VPN Gate 数据；实测延迟、实测下载、实测上传只显示 GateSocks 实测结果，不再在同一列回退混显。
- 每个 IP 最前面增加独立“测试选择”复选框；可勾选 1 个、多个，也可使用“全选当前筛选”和“清空测试选择”。
- “开始实测”只测试手动勾选的节点；未勾选时不再默认取前 5 个。后端支持最多 200 个手动选择节点顺序实测。
- 测试选择与仪表盘“当前使用节点”完全独立：测试是多选临时集合；当前使用节点是单选、持久化选择。测试某个节点不会自动把它设为使用节点，设为使用节点也不会自动加入测试集合。
- 节点表最后一列明确标为“使用节点（单选）”，按钮改为“设为使用节点 / 当前使用”，避免和测试复选框混淆。


## v0.4.5-dev

- 明确两套选择机制：节点池最前面的复选框仅用于“测试选择”（可单选/多选/全选当前筛选）；仪表盘“当前使用节点”则通过直接点击节点 IP 设置，始终为单选且持久化。
- 移除单独的“使用节点”操作按钮列，避免与测试复选框混淆；当前使用节点在 IP 单元格旁显示“当前使用”标记。
- SOCKS5 外部访问增加二维码能力：正式实例每条文本信息同时显示同尺寸“复制 / 二维码”按钮，点击二维码弹出扫码窗口。
- “完整地址”二维码编码完整 SOCKS5 URI，供支持该 URI 的移动代理客户端扫码添加；二维码通过认证后的 POST `/api/qr` 生成 SVG，不把用户名/密码等凭据放进查询字符串。
- 增加 `qrcode` 依赖与 QR 生成单元测试；SOCKS5 尚未创建实例时仅展示能力说明，不生成虚假二维码。

## v0.4.6-dev

- 实现 SOCKS5 多实例后端：每个实例拥有独立 OpenVPN TUN、SOCKS5 端口、用户名/密码、策略路由表和 socket fwmark；管理面板/Caddy/OpenVPN 控制连接本身不切入实例 VPN。
- 新增持久化 data/socks_instances.json 与 data/socks/<实例ID>/，容器重启后会恢复此前处于启用状态的实例。
- 新增创建、启动、停止、重连、重新测试、删除 API；删除实例会终止 SOCKS/OpenVPN 进程、清理策略路由、删除 TUN 和实例配置并释放正式端口，但保留节点池及历史测试记录。
- 创建实例允许使用候选、已测试或测试失败节点，不以测试状态作为限制；同一节点默认只允许一个实例，避免误操作重复占用端口。
- 内置认证 SOCKS5 服务采用 Linux SO_MARK 只标记代理上游连接，从而避免把客户端到 SOCKS5 的入站会话回包错误送入 VPN；每个实例的上游连接再按 fwmark 进入自己的 TUN。
- Compose 映射 18001–18099/tcp 作为正式外部访问端口；GATESOCKS_PUBLIC_HOST 可手工指定外部地址，未设置时尝试从管理网络自动读取 VPS 公网 IPv4。

## v0.4.7-dev

- 将节点单选语义统一为“当前待生成节点”：点击节点 IP 只决定下一次准备生成哪个 SOCKS5，不占端口、不建立长期隧道，也不会替换或停止已运行实例。
- 仪表盘待生成节点卡片新增“生成并启用 SOCKS5”，真正执行长期 OpenVPN、正式端口分配、认证凭据生成、SOCKS5 启动和出口确认；测试状态不会限制用户尝试生成。
- SOCKS5 页面改为真实实例列表，显示所有已生成的在线/停止/异常实例，并分别展示接入节点、真实出口、ISP/ASN、TUN、端口和最近实例实测。
- 每个实例提供启动、停止、重新连接、重新测试和删除实例；删除带二次确认并完整释放端口/隧道/策略路由/实例配置，同时保留节点池和历史测试记录。
- 本地访问保留复制功能；外部访问的地址、端口、用户名、密码和完整 socks5:// URI 均提供同尺寸“复制 / 二维码”按钮。
- 仪表盘 SOCKS5 在线数和异常数改为读取真实实例运行状态，不再显示固定占位值。


## v0.4.8-dev

- 将“当前待生成节点（单选）”从仪表盘完整移动到 SOCKS5 页面顶部，节点信息、选择/更换、生成并启用 SOCKS5、取消待生成的操作逻辑保持不变。
- 仪表盘不再展示待生成节点区域，仅保留运行状态、端口规划等总览信息。
- 删除 SOCKS5 页面原有“SOCKS5 实例”说明标题、“新增 SOCKS5 实例”按钮以及新增流程说明，避免和顶部待生成节点区域重复。
- SOCKS5 已生成实例列表继续保留在待生成节点区域下方；节点池文案同步改为“点击 IP 设置 SOCKS5 页面顶部的待生成节点”。


## v0.4.9-dev

- 修复生成 SOCKS5 后长期 OpenVPN 在 TLS 已成功后出现 `AUTH_FAILED` 的问题。
- 继续禁止信任 VPN Gate 上游配置中的 `auth-user-pass <任意路径>`；GateSocks 会在自己的临时/实例目录生成权限为 0600 的受控认证文件，并通过命令行显式传给 OpenVPN。
- VPN Gate 默认凭据为 `vpn / vpn`，可通过 `GATESOCKS_VPNGATE_USERNAME` / `GATESOCKS_VPNGATE_PASSWORD` 覆盖；临时节点实测和长期 SOCKS5 隧道统一使用同一认证机制。
- 已存在的 v0.4.8 SOCKS5 实例不需要删除重建；升级后执行“启动”或“重新连接”时会自动生成受控认证文件并使用新认证逻辑。
- `AUTH_FAILED` 现在会明确标记为 OpenVPN 认证失败，便于与“节点不可达 / No route to host”区分。
