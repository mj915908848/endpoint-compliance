# Docker 部署管理端

需要一台装了 Docker 的 Linux 服务器。设置都写在 `.env` 里，`compose.yml` 不用改（只有固定版本时改它的 `image` 行，见 ADVANCED.md）。

## 部署

1. 准备部署目录（二选一）：

   - 用镜像仓库或打包好的镜像：新建目录 `compliance`，下载部署文件：

     ```bash
     mkdir compliance && cd compliance
     for f in compose.yml .env.example backup.sh; do
       curl -fsSLO "https://raw.githubusercontent.com/mj915908848/endpoint-compliance/main/deploy/docker/$f"
     done
     chmod +x backup.sh
     ```

   - 从源码构建：`git clone` 本仓库，部署目录就是 `deploy/docker`。

2. 写配置，填 `DB_PASSWORD` 和 `ADMIN_PASSWORD`：

   ```bash
   cp .env.example .env && chmod 600 .env && vi .env
   ```

   镜像来源：

   | 来源 | 怎么做 |
   | --- | --- |
   | 镜像仓库 `ghcr.io`（默认） | 什么都不用做 |
   | 打包好的镜像（Releases 页的 `compliance-server-<版本>.tar.gz`，服务器不能访问 `ghcr.io` 时用） | 先 `docker load -i compliance-server-<版本>.tar.gz` |
   | 从源码构建 | 在 `.env` 里去掉 `COMPOSE_FILE=compose.yml:compose.build.yml` 前面的 `#` |

3. 在旁边建 `certs` 目录，放入证书 `cert.pem`（含中间证书）和私钥 `key.pem`：

   ```bash
   mkdir certs
   cp /path/to/fullchain.pem certs/cert.pem
   cp /path/to/privkey.key   certs/key.pem
   sudo chown -R 1654:1654 certs && sudo chmod 600 certs/*
   ```

4. 启动：

   ```bash
   docker compose up -d
   ```

浏览器打开 `https://证书上的域名`，用 `admin` 和 `.env` 里的密码登录。

## 升级

先备份 `./backup.sh`，然后按镜像来源：

- 镜像仓库：`docker compose pull && docker compose up -d`
- 打包好的镜像：`docker load -i` 新版本的 `compliance-server-<版本>.tar.gz`，然后 `docker compose up -d`
- 从源码构建：`git pull && docker compose up -d`

## 备份

运行 `./backup.sh`，备份在 `backups/` 下，请拷到别的机器保存。里面的签名密钥丢了，所有终端都要重新登记。

## 客户端

1. 管理端“终端登记”页生成登记码，点“下载登记配置”得到 `登记配置.json`。
2. 把它和 Releases 页的 `compliance-client-<版本>-windows-x64.msi` 放在同一个文件夹，在各台电脑上双击 MSI 安装。

## 更多

没有证书、自己打包镜像、经网关转发、忘记密码、恢复备份、从旧版本迁移等，见 [ADVANCED.md](ADVANCED.md)。
