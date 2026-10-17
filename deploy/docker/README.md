# Docker 部署管理端

需要一台装了 Docker 的 Linux 服务器，能访问 `ghcr.io`。

## 部署

1. 新建目录 `compliance`，把下面的内容存为 `compose.yml`，改掉两处【改】：

   <!-- compose.yml: 下面这段由 CI 与 deploy/docker/compose.yml 逐字比对 -->
   ```yaml
   # 终端合规管理端。第一次启动前改掉两处【改】。
   name: compliance

   # 数据库密码，只用字母和数字。【改】
   x-db-password: &db-password 改成数据库密码

   x-logging: &logging
     driver: json-file
     options:
       max-size: 10m
       max-file: "3"

   services:
     db:
       image: postgres:18
       restart: unless-stopped
       logging: *logging
       environment:
         POSTGRES_DB: compliance
         POSTGRES_USER: compliance
         POSTGRES_PASSWORD: *db-password
       volumes:
         - db:/var/lib/postgresql
       healthcheck:
         test: ["CMD-SHELL", "pg_isready -U compliance -d compliance"]
         interval: 5s
         timeout: 5s
         retries: 20

     server:
       image: ghcr.io/mj915908848/compliance-server:latest
       restart: unless-stopped
       logging: *logging
       depends_on:
         db:
           condition: service_healthy
       ports:
         - "443:8443"
       environment:
         Compliance__Database: Host=db;Database=compliance;Username=compliance
         PGPASSWORD: *db-password
         # 管理员 admin 的初始密码，至少 16 位，不含 " 和 \ 。【改】
         Compliance__BootstrapUsers: '[{"username":"admin","password":"改成管理员密码","roles":["Reader","Operator","Publisher"]}]'
         Kestrel__Certificates__Default__Path: /certs/cert.pem
         Kestrel__Certificates__Default__KeyPath: /certs/key.pem
         TZ: Asia/Shanghai
       volumes:
         - ./certs:/certs:ro
         - keys:/var/lib/compliance

   volumes:
     db:
     keys:
   ```

2. 在旁边建 `certs` 目录，放入证书 `cert.pem`（含中间证书）和私钥 `key.pem`：

   ```bash
   mkdir certs
   cp /path/to/fullchain.pem certs/cert.pem
   cp /path/to/privkey.key   certs/key.pem
   sudo chown -R 1654:1654 certs && sudo chmod 600 certs/*
   ```

3. 启动：

   ```bash
   docker compose up -d
   ```

浏览器打开 `https://证书上的域名`，用 `admin` 和第 1 步设的密码登录。

## 升级

```bash
./backup.sh
docker compose pull
docker compose up -d
```

## 备份

第一次先下载备份脚本，以后每次运行 `./backup.sh`：

```bash
curl -fsSLO https://raw.githubusercontent.com/mj915908848/endpoint-compliance/main/deploy/docker/backup.sh && chmod +x backup.sh
./backup.sh
```

备份在 `backups/` 下，请拷到别的机器保存。里面的签名密钥丢了，所有终端都要重新登记。

## 客户端

1. 管理端“终端登记”页生成登记码，点“下载登记配置”得到 `登记配置.json`。
2. 把它和 Releases 页的 `compliance-client-<版本>-windows-x64.msi` 放在同一个文件夹，在各台电脑上双击 MSI 安装。

## 更多

没有证书、经网关转发、改端口、忘记密码、恢复备份、批量静默安装等，见 [ADVANCED.md](ADVANCED.md)。
