# Docker 部署管理端

## 一键部署

一台装有 Docker（含 `docker compose` 插件）的 Linux 服务器即可，PostgreSQL 一起在容器里运行。

1. 在 Releases 页面下载 `compliance-server-<版本>-deploy.tar.gz`（脚本和镜像都在里面），拷到服务器上解压并进入目录：

   ```bash
   tar xzf compliance-server-<版本>-deploy.tar.gz
   cd compliance-server-<版本>
   ```

   也可以直接用仓库里的本目录（`git clone` 后 `cd deploy/docker`），没有镜像包时脚本会从源码构建，需要几分钟和外网访问 Docker Hub、npm、NuGet。

2. 运行，`--domain` 填客户端访问管理端用的域名，证书用客户信任的泛域名证书（如 `*.example.com`，证书文件必须包含中间证书）：

   ```bash
   sudo ./install.sh --domain compliance.example.com --cert /path/to/fullchain.pem --key /path/to/privkey.key
   ```

   PFX 证书用 `--pfx 证书.pfx --pfx-password 密码`；端口不是 443 时加 `--port 8443`。先试用时可以不给证书，脚本会生成自签证书，之后再用 `--cert`、`--key` 运行一次即换成正式证书。

   脚本会生成 `.env`（随机的数据库密码和管理员密码）、放好证书、加载镜像、启动并确认能访问，最后显示地址、管理员账号和密码。密码同时保存在 `.env` 里，登录后请在右上角「修改密码」。

3. 给服务器加内网 DNS 记录，例如 `compliance.example.com` 指向这台服务器，浏览器打开显示的地址登录。

4. 立即做一次备份（见下）。

经网关转发到 HTTP（见下文“经网关反向代理”方式二）时不放证书，改为：`sudo ./install.sh --http --trusted-proxy 网关的IP --port 8443`。

`./install.sh --help` 列出全部选项。再次运行 `./install.sh` 是安全的：已有的 `.env`、证书、数据和签名密钥都保留，运行中的管理端会先自动备份。

### 手动部署

不用脚本时，按以下步骤操作（脚本做的就是这些）：

1. 放证书（经网关转发到 HTTP 时不需要）：

   ```bash
   mkdir certs
   cp /path/to/fullchain.pem certs/cert.pem   # 证书，必须包含中间证书
   cp /path/to/privkey.key   certs/key.pem    # 私钥
   sudo chown -R 1654:1654 certs && chmod 600 certs/*
   ```

   容器内以 uid 1654（非 root）运行，私钥要让它读得到。PFX 格式的证书见 `.env.example`。

2. 写配置：`cp .env.example .env && vi .env`。必填：`DB_PASSWORD`（只用字母数字）、`ADMIN_PASSWORD`（至少 16 位）。证书文件名不同时修改证书那两行。

3. 启动：`docker load -i compliance-server-<版本>.tar.gz && docker compose up -d`（或从源码构建 `docker compose up -d --build`），`docker compose logs -f server` 出现 `Now listening on` 即启动完成。

## 客户端

1. 管理端“终端登记”页生成登记码：填名称（如部门），可登记台数填这批电脑的数量，有效期选够安装用的时间（最长 7 天）。
2. 点“下载登记配置”得到 `登记配置.json`。管理端地址默认取当前浏览器访问的地址，经网关时填网关上的域名。
3. 安装（任选一种）：
   - **MSI（推荐）**：把 `compliance-client-<版本>-windows-x64.msi` 和 `登记配置.json` 放在同一个文件夹，拷到各台电脑双击 MSI，确认管理员提示。装完弹出“登记到管理端”窗口，地址和登记码已填好，点“登记”并再确认一次管理员提示。没有配置文件时在窗口里手动填写。
   - **批量静默安装**（域组策略、软件分发工具）：`msiexec /i compliance-client-<版本>-windows-x64.msi SERVERURL=https://compliance.example.com CODE=<登记码> /qn`。登记失败时整个安装回滚，msiexec 返回非 0。
   - **脚本方式**：把 `登记配置.json` 放进解压后的 zip 安装包根目录（与 `安装客户端（正式环境）.bat` 同一层），双击 `安装客户端（正式环境）.bat`。
4. 装完后在“终端登记”页撤销登记码，或等它到期。

客户端会校验证书，所以必须用证书覆盖的域名访问，不能用 IP。没登记的电脑（例如装完关掉了登记窗口）在托盘图标上显示“尚未登记”，右键“登记到管理端…”可以随时登记。MSI 未做代码签名，首次运行时 Windows 可能提示“未知发布者”，点“更多信息 → 仍要运行”。

服务器时间要准确（开启 NTP）：终端请求的时间与服务器相差超过 5 分钟会被拒绝。

## 经网关反向代理

可以。网关上的要求：

- **用独立的子域名，转发到根路径**，例如 `compliance.example.com/` → 管理端 `/`。不支持挂在子路径（如 `/compliance/`）下，也不要改写路径。
- **原样转发请求头和请求体**：终端的每个请求都带签名，覆盖了请求方法、路径、请求体和 `X-Device-Id`、`X-Timestamp`、`X-Nonce`、`X-Signature` 四个头；网关改动其中任何一项（去掉这些头、改路径、重新编码请求体）都会使终端请求被拒绝。
- 请求体上限不低于 2 MB。
- 网关自身使用的证书必须被终端信任（泛域名证书即可）。

转发到管理端有两种方式：

**方式一（推荐）：网关转发到 HTTPS。** 本目录配置不用改，网关的上游填 `https://服务器地址:HTTPS_PORT`。容器里也装着同一张泛域名证书；网关若校验上游证书，上游的主机名（SNI）要填证书覆盖的域名，或关闭上游证书校验。

**方式二：网关转发到 HTTP。** 容器里不放证书（不用建 `certs` 目录）。在 `.env` 中删掉 `Kestrel__Certificates__...` 几行，并加上：

```
ASPNETCORE_URLS=http://+:8443
Compliance__TrustedProxies__0=网关的 IP
```

网关必须带上 `X-Forwarded-Proto: https` 和 `X-Forwarded-For`。管理端只接受来自 `TrustedProxies` 中 IP 的这两个头，其他来源的 HTTP 请求一律拒绝（返回 “HTTPS is required”）。网关到管理端这一段是明文，两台机器之间应是机房内网或同一 VLAN。

`HTTPS_PORT` 只应让网关访问到：

- 网关与管理端在同一台机器：`HTTPS_PORT=127.0.0.1:8443`，`TrustedProxies` 填 Docker 网络的网关地址（启动后用 `docker network inspect compliance_default -f '{{(index .IPAM.Config 0).Gateway}}'` 查看，通常为 `172.18.0.1` 一类）。
- 网关在另一台机器：`HTTPS_PORT=8443`，`TrustedProxies` 填网关的内网 IP（中间有 NAT 时填 NAT 后的地址），并只允许网关访问 8443。Docker 映射的端口不受 ufw、firewalld 规则约束，要用 `DOCKER-USER` 链或云服务器安全组：

  ```bash
  sudo iptables -I DOCKER-USER -p tcp -m conntrack --ctorigdstport 8443 ! -s 网关的内网IP -j DROP
  ```

  （iptables 规则重启后丢失，Debian/Ubuntu 用 `iptables-persistent` 保存。）

Nginx 示例（方式二，网关在另一台机器）：

```nginx
server {
    listen 443 ssl;
    server_name compliance.example.com;
    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.key;
    client_max_body_size 2m;

    location / {
        proxy_pass http://管理端的内网IP:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

方式一把 `proxy_pass` 换成 `https://管理端IP:8443`，并加 `proxy_ssl_server_name on;` 和 `proxy_ssl_name compliance.example.com;`。

验证：在网关上 `curl -H 'X-Forwarded-Proto: https' http://管理端的内网IP:8443/api/status` 返回 JSON；浏览器打开域名能登录（只显示 “HTTPS is required” 时检查 `TrustedProxies` 和两个转发头）；再装一台客户端确认它在线并有检查结果。

**限制后台访问（可选）**：客户端只访问 `/api/agent/` 和 `/api/status`。可以让这两个路径对所有电脑开放，其余路径（管理页面和管理接口）只允许 IT 网段：

```nginx
    location /api/agent/ { proxy_pass http://管理端的内网IP:8443; ...同上的 proxy_set_header... }
    location = /api/status { proxy_pass http://管理端的内网IP:8443; ...同上... }
    location / {
        allow 192.168.10.0/24;   # IT 网段
        deny all;
        proxy_pass http://管理端的内网IP:8443; ...同上...
    }
```

也可以给后台单独一个网关端口（443 只转发上面两个路径，另开如 8444 转发全部并只对 IT 网段开放）。单纯换端口不增加安全性，关键是限制来源。用独立端口时，“终端登记”页下载登记配置前要把管理端地址改回客户端用的 `https://域名`（不带后台端口）。

**真实客户端 IP**：登录和终端登记分别按来源 IP 限速：登录（含修改密码）每个 IP 每分钟 20 次，终端登记每个 IP 每分钟 300 次，两者互不影响。另外同一账号 15 分钟内密码错误 10 次，会暂停该账号登录 15 分钟。不配置 `Compliance__TrustedProxies__0` 时，所有请求都算作网关的 IP，所有管理员共用这 20 次。方式一也可以加上这一行，并让网关带 `X-Forwarded-For`。网关与管理端在同一台机器、经 `localhost` 转发时，容器看到的来源是 Docker 网络的网关地址（查看方法见方式二），应填这个地址。

## 管理员密码与系统设置

**管理员密码**：`.env` 里的 `ADMIN_PASSWORD` 只在第一次启动时用来创建账号，之后再改 `.env` 不起作用。登录后点右上角「修改密码」修改，修改后其他浏览器上的登录会退出。

忘记密码时，删掉账号和所有登录会话再重启，管理端会按 `.env` 里的 `ADMIN_USER`、`ADMIN_PASSWORD` 重新创建账号。终端、策略、告警和审计记录都不受影响。下面的 `admin` 换成实际的账号名：

```bash
docker compose exec db psql -U compliance -d compliance -c "DELETE FROM sessions; DELETE FROM users WHERE username = 'admin'"
```

```bash
docker compose restart server
```

**告警推送**：在「系统设置」里填企业微信、钉钉或飞书的群机器人地址，新告警约 30 秒内推送到群里。管理端需要能访问外网上对应的地址（`qyapi.weixin.qq.com`、`oapi.dingtalk.com` 或 `open.feishu.cn`）。服务器只能经代理上网时，在 `compose.yml` 的 `server` 环境变量里加 `HTTPS_PROXY: http://代理地址:端口`。

**审计记录**：默认永久保留，可在「系统设置」中改为保留 180 天到 3 年，超期的记录每小时清理一次。

## 备份与恢复

```bash
./backup.sh
```

在 `backups/<时间>/` 下生成数据库备份 `compliance.dump` 和策略签名密钥 `signing.key`，请拷贝到别的机器保存。**签名密钥丢失后，所有已登记终端都会拒收新策略，只能逐台重新登记。**

恢复到新服务器：先按“手动部署”完成第 1–2 步但不要启动，然后：

```bash
docker compose up -d db
docker compose run --rm --no-deps -v "$PWD/backups/<时间>:/restore:ro" --entrypoint sh server \
  -c 'cp /restore/signing.key /var/lib/compliance/signing.key && chmod 600 /var/lib/compliance/signing.key'
docker compose exec -T db pg_restore -U compliance -d compliance --clean --if-exists < backups/<时间>/compliance.dump
docker compose up -d
```

## 版本与升级

积累一批改动后手动发布一个版本（Releases 页，版本号从 `0.2.0` 起每次加一），附带：

- `compliance-server-<版本>.tar.gz`：管理端 Docker 镜像，服务器上直接加载，不用在服务器上构建；
- `compliance-client-<版本>-windows.zip`：Windows 客户端安装包。

管理端当前版本显示在“系统”页。

**升级管理端**：在能访问 GitHub 的电脑上下载镜像 `compliance-server-<版本>.tar.gz`（或用 `gh release download v<版本> -p 'compliance-server-*'`），拷到服务器上的部署目录，然后：

```bash
sudo ./install.sh
```

脚本先备份，再加载目录里版本最新的镜像包并换成新版本；数据库结构在启动时自动升级。旧的镜像包可以删掉。还没有 `install.sh` 的部署（0.2.21 及以前），从新版本的 `-deploy.tar.gz` 里把 `install.sh` 拷到部署目录即可，已有的 `.env` 和证书照常使用；也可以照旧手动升级：

```bash
./backup.sh
docker load -i compliance-server-<版本>.tar.gz
docker compose up -d
```

`docker load` 会把镜像标记为 `compliance-server:latest`，`up -d` 即换成新版本。不要加 `--build`，否则会用服务器上的源码重新构建。

在服务器上从源码构建同样可用：更新源码后 `./install.sh --build`（或 `docker compose up -d --build`）。

**数据保留**：管理端每小时自动清理一次：检查结果的上报记录保留 1 天（每台设备最新的检查结果另存，不受影响），告警、违规等其他上报记录保留 90 天，已恢复的告警保留 180 天（未恢复的一直保留），过期的登录会话和检查请求也一并删除。保留天数可在 `compose.yml` 的 `server` 环境变量里调整，例如加 `Compliance__EventRetentionDays: "180"`、`Compliance__AlertRetentionDays: "365"`。管理页面 30 分钟未操作会自动退出（页面自动刷新不算操作），可用 `Compliance__SessionIdleMinutes` 调整，设为 `0` 关闭；无论是否操作，登录 8 小时后都需重新登录。告警中心默认列出未恢复的告警和最近 30 天恢复的，更早的在“已恢复”筛选下点“加载 30 天前恢复的告警”查看。

**容器日志**：管理端和数据库容器的输出各保留 3 个 10 MB 的文件，写满后滚动覆盖最旧的，不会占满磁盘。升级镜像不会改服务器上的 `compose.yml`：0.2.19 及以前部署的，把新版 `compose.yml` 开头的 `x-logging` 一段和 `db`、`server` 下的 `logging: *logging` 两行加到服务器上的文件里（或整个换成新版文件，保留自己改过的地方），再执行 `docker compose up -d`，容器重建后生效；查看用 `docker compose logs --tail 200 server`。0.2.8 及以前的版本不清理，升级后一天内旧记录会被删掉；PostgreSQL 会把腾出的空间留给新数据复用，如需立刻缩小磁盘占用，可在业务低峰执行一次（会短暂锁住该表）：

```bash
docker compose exec db psql -U compliance -d compliance -c 'VACUUM FULL events'
```

**升级客户端**：双击新版本的 MSI（或用 `msiexec /i 新版本.msi /qn` 批量下发），保留登记身份，不需要登记码；用脚本装过的电脑也可以直接装 MSI，登记身份同样保留。用脚本方式时，解压新的客户端包，在已安装的电脑上双击 `安装客户端（正式环境）.bat`，选“1 仅更新程序”。卸载：MSI 装的在“设置 → 应用”里卸载“终端合规客户端”，会同时删除登记身份和本地数据。

## 常用命令

| 用途 | 命令 |
| --- | --- |
| 查看状态 | `docker compose ps` |
| 查看日志 | `docker compose logs --tail 100 server` |
| 重启 | `docker compose restart server` |
| 停止 | `docker compose down`（数据保留在卷 `compliance_db`、`compliance_keys` 中；不要加 `-v`，否则数据和密钥会被删除） |
| 更换证书 | 替换 `certs` 里的文件后 `docker compose restart server` |
