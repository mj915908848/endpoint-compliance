# Docker 部署管理端

一台装有 Docker（含 `docker compose`）的 Linux 服务器即可，PostgreSQL 一起在容器里运行。

## 首次部署

1. 把仓库放到服务器上（`git clone` 或拷贝），进入本目录：

   ```bash
   cd deploy/docker
   ```

2. 放证书。泛域名证书（如 `*.example.com`）放进 `certs` 目录：

   ```bash
   mkdir certs
   cp /path/to/fullchain.pem certs/cert.pem   # 证书，必须包含中间证书
   cp /path/to/privkey.key   certs/key.pem    # 私钥
   sudo chown -R 1654:1654 certs && chmod 600 certs/*
   ```

   容器内以 uid 1654（非 root）运行，私钥要让它读得到。PFX 格式的证书见 `.env.example`。

3. 写配置：

   ```bash
   cp .env.example .env
   vi .env
   ```

   必填：`DB_PASSWORD`（只用字母数字）、`ADMIN_PASSWORD`（至少 16 位）。证书文件名不同时修改证书那两行。

4. 启动（第一次会构建镜像，需要几分钟和外网访问 Docker Hub、npm、NuGet）：

   ```bash
   docker compose up -d --build
   docker compose logs -f server
   ```

5. 给服务器加内网 DNS 记录，例如 `compliance.example.com` 指向这台服务器，然后浏览器打开 `https://compliance.example.com` 用管理员账号登录。端口不是 443 时加上 `:端口`。

6. 立即做一次备份（见下）。

## 客户端

1. 管理端“终端登记”页生成登记码：填名称（如部门），可登记台数填这批电脑的数量，有效期选够安装用的时间（最长 7 天）。
2. 点“下载登记配置”得到 `登记配置.json`，放进解压后的 Windows 安装包根目录（与 `安装客户端（正式环境）.bat` 同一层）。管理端地址默认取当前浏览器访问的地址，经网关时填网关上的域名。
3. 把这个目录拷到各台电脑（U 盘或共享文件夹），右键以管理员身份或直接双击 `安装客户端（正式环境）.bat`，确认管理员提示即可，无需输入。
4. 装完后在“终端登记”页撤销登记码，或等它到期。

客户端会校验证书，所以必须用证书覆盖的域名访问，不能用 IP。也可以不放配置文件，双击后手动输入地址和登记码。

服务器时间要准确（开启 NTP）：终端请求的时间与服务器相差超过 5 分钟会被拒绝。

## 经网关反向代理

可以。网关上的要求：

- **用独立的子域名，转发到根路径**，例如 `compliance.example.com/` → 管理端 `/`。不支持挂在子路径（如 `/compliance/`）下，也不要改写路径。
- **原样转发请求头和请求体**：终端的每个请求都带签名，覆盖了请求方法、路径、请求体和 `X-Device-Id`、`X-Timestamp`、`X-Nonce`、`X-Signature` 四个头；网关改动其中任何一项（去掉这些头、改路径、重新编码请求体）都会使终端请求被拒绝。
- 请求体上限不低于 2 MB。
- 网关自身使用的证书必须被终端信任（泛域名证书即可）。

转发到管理端有两种方式：

**方式一（推荐）：网关转发到 HTTPS。** 本目录配置不用改，网关的上游填 `https://服务器地址:HTTPS_PORT`。容器里也装着同一张泛域名证书；网关若校验上游证书，上游的主机名（SNI）要填证书覆盖的域名，或关闭上游证书校验。

**方式二：网关转发到 HTTP。** 在 `.env` 中删掉 `Kestrel__Certificates__...` 几行，并加上：

```
ASPNETCORE_URLS=http://+:8443
Compliance__TrustedProxies__0=网关的 IP
```

网关必须带上 `X-Forwarded-Proto: https` 和 `X-Forwarded-For`。管理端只接受来自 `TrustedProxies` 中 IP 的这两个头，其他来源的 HTTP 请求一律拒绝（返回 “HTTPS is required”）。这时 `HTTPS_PORT` 只应让网关访问到，不要对办公网开放。

**真实客户端 IP**：登录和终端登记按来源 IP 限速，每个 IP 每分钟 20 次。不配置 `Compliance__TrustedProxies__0` 时，所有请求都算作网关的 IP；平时没有影响，但一分钟内集中登记超过 20 台终端会被限速。方式一也可以加上这一行，并让网关带 `X-Forwarded-For`。网关与管理端在同一台机器、经 `localhost` 转发时，容器看到的来源是 Docker 网桥地址（通常为 `172.17.0.1` 一类），应填这个地址。

## 备份与恢复

```bash
./backup.sh
```

在 `backups/<时间>/` 下生成数据库备份 `compliance.dump` 和策略签名密钥 `signing.key`，请拷贝到别的机器保存。**签名密钥丢失后，所有已登记终端都会拒收新策略，只能逐台重新登记。**

恢复到新服务器：先按上面完成第 1–3 步但不要启动，然后：

```bash
docker compose up -d db
docker compose run --rm --no-deps -v "$PWD/backups/<时间>:/restore:ro" --entrypoint sh server \
  -c 'cp /restore/signing.key /var/lib/compliance/signing.key && chmod 600 /var/lib/compliance/signing.key'
docker compose exec -T db pg_restore -U compliance -d compliance --clean --if-exists < backups/<时间>/compliance.dump
docker compose up -d
```

## 升级

```bash
git pull
docker compose up -d --build
```

数据库结构在启动时自动升级。升级前先备份。

## 常用命令

| 用途 | 命令 |
| --- | --- |
| 查看状态 | `docker compose ps` |
| 查看日志 | `docker compose logs --tail 100 server` |
| 重启 | `docker compose restart server` |
| 停止 | `docker compose down`（数据保留在卷 `compliance_db`、`compliance_keys` 中；不要加 `-v`，否则数据和密钥会被删除） |
| 更换证书 | 替换 `certs` 里的文件后 `docker compose restart server` |
