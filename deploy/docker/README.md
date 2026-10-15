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

终端安装时 `-ServerUrl` 填上面的地址，例如 `https://compliance.example.com`，见 `deploy/windows/README.md`。客户端会校验证书，所以必须用证书覆盖的域名访问，不能用 IP。

服务器时间要准确（开启 NTP）：终端请求的时间与服务器相差超过 5 分钟会被拒绝。

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
