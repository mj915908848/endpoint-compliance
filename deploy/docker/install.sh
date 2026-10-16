#!/usr/bin/env bash
# 一键部署或升级管理端（PostgreSQL + 管理端）。用法见同目录 README.md，或运行 ./install.sh --help。
#
# 首次运行：生成 .env（随机数据库密码和管理员密码）、放好证书（没给证书时生成自签证书）、
# 加载或构建镜像、启动并确认可以访问。再次运行即升级：保留 .env 和证书，先备份再换成新镜像。
set -euo pipefail
cd "$(dirname "$0")"

usage() {
  cat <<'EOF'
用法: ./install.sh [选项]

  --domain 域名            客户端和浏览器访问管理端用的域名（默认取本机主机名）
  --cert 文件 --key 文件   PEM 证书（含中间证书的完整链）和私钥；不给时生成自签证书
  --pfx 文件 [--pfx-password 密码]
                           PFX 格式的证书
  --port 端口              对外端口（默认 443；可写成 127.0.0.1:8443 只在本机监听）
  --http --trusted-proxy IP
                           经网关转发到 HTTP：容器里不放证书，只接受该网关的请求
  --admin-user 名称        首个管理员账号名（默认 admin），只在首次部署时生效
  --build                  从源码构建镜像，即使本目录有镜像包或本机已有镜像
  -h, --help               显示本说明

首次部署后再运行一次即升级：把新的 compliance-server-<版本>.tar.gz 放进本目录，运行 ./install.sh。
EOF
}

domain="" cert="" key="" pfx="" pfx_password="" port="" http=0 proxy="" admin_user="" build=0
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) domain="$2"; shift 2 ;;
    --cert) cert="$2"; shift 2 ;;
    --key) key="$2"; shift 2 ;;
    --pfx) pfx="$2"; shift 2 ;;
    --pfx-password) pfx_password="$2"; shift 2 ;;
    --port) port="$2"; shift 2 ;;
    --http) http=1; shift ;;
    --trusted-proxy) proxy="$2"; shift 2 ;;
    --admin-user) admin_user="$2"; shift 2 ;;
    --build) build=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "未知选项: $1（--help 查看用法）" >&2; exit 2 ;;
  esac
done

step() { printf '\n==> %s\n' "$*"; }
fail() { printf '错误: %s\n' "$*" >&2; exit 1; }

# Root is needed to hand the private key to the container's user (uid 1654); sudo is used when not root.
as_root() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }

# Reads a value from .env; the file is ours to write, so a plain KEY=value line is all it holds.
env_get() { sed -n "s/^$1=//p" .env | tail -n 1; }

# Sets KEY=value in .env, replacing an existing (or commented-out) line or appending one.
env_set() {
  local k="$1" v="$2"
  if grep -qE "^#? ?$k=" .env; then
    awk -v k="$k" -v v="$v" 'BEGIN { done = 0 } {
      if (!done && ($0 ~ "^" k "=" || $0 ~ "^# ?" k "=")) { print k "=" v; done = 1 } else print
    }' .env > .env.tmp
    cat .env.tmp > .env && rm -f .env.tmp
  else
    printf '%s=%s\n' "$k" "$v" >> .env
  fi
}

env_del() { grep -vE "^$1=" .env > .env.tmp || true; cat .env.tmp > .env && rm -f .env.tmp; }

random() { LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1" || true; }

# --- 检查环境 ---------------------------------------------------------------
step "检查 Docker"
command -v docker > /dev/null || fail "没有找到 docker。先安装 Docker（含 compose 插件）：https://docs.docker.com/engine/install/"
docker compose version > /dev/null 2>&1 || fail "没有找到 docker compose 插件。安装 docker-compose-plugin 后重试。"
if ! docker info > /dev/null 2>&1; then
  fail "无法连接 Docker：请用 root 或 sudo 运行，或把当前用户加入 docker 组；并确认 Docker 已启动（systemctl start docker）。"
fi
docker compose version

[ -n "$cert" ] && [ -z "$key" ] && fail "--cert 需要同时给出 --key"
[ -n "$key" ] && [ -z "$cert" ] && fail "--key 需要同时给出 --cert"
[ -n "$proxy" ] && [ "$http" = 0 ] && fail "--trusted-proxy 只用于 --http 方式"
[ "$http" = 1 ] && [ -z "$proxy" ] && fail "--http 方式需要 --trusted-proxy 网关IP（网关与管理端同机时见 README）"
[ "$http" = 1 ] && { [ -n "$cert$pfx" ] && fail "--http 方式不放证书，不要同时给 --cert/--pfx"; }
for f in "$cert" "$key" "$pfx"; do [ -z "$f" ] || [ -r "$f" ] || fail "读不到文件 $f"; done

# --- 配置 -------------------------------------------------------------------
first=0
if [ ! -f .env ]; then
  first=1
  step "生成配置 .env"
  (umask 077 && cp .env.example .env)
  env_set DB_PASSWORD "$(random 32)"
  env_set ADMIN_USER "${admin_user:-admin}"
  env_set ADMIN_PASSWORD "$(random 20)"
  env_set HTTPS_PORT "${port:-$([ "$http" = 1 ] && echo 8443 || echo 443)}"
  [ -n "$domain" ] || domain="$(hostname -f 2> /dev/null || hostname)"
  env_set COMPLIANCE_DOMAIN "$domain"
else
  step "使用已有配置 .env（升级）"
  [ -n "$admin_user" ] && echo "提示: 管理员账号已存在，--admin-user 不起作用。"
  [ -n "$port" ] && env_set HTTPS_PORT "$port"
  if [ -n "$domain" ]; then env_set COMPLIANCE_DOMAIN "$domain"; else domain="$(env_get COMPLIANCE_DOMAIN)"; fi
  [ -n "$domain" ] || domain="$(hostname -f 2> /dev/null || hostname)"
fi
chmod 600 .env

if [ "$http" = 1 ]; then
  env_del Kestrel__Certificates__Default__Path
  env_del Kestrel__Certificates__Default__KeyPath
  env_del Kestrel__Certificates__Default__Password
  env_set ASPNETCORE_URLS "http://+:8443"
  env_set Compliance__TrustedProxies__0 "$proxy"
elif [ -n "$cert$pfx" ]; then
  env_del ASPNETCORE_URLS
fi

# --- 证书 -------------------------------------------------------------------
self_signed=0 cert_changed=0
if [ "$(env_get ASPNETCORE_URLS)" = "http://+:8443" ]; then
  mode=http
else
  mode=https
  mkdir -p certs
  if [ -n "$cert" ]; then
    step "放入证书"
    as_root cp "$cert" certs/cert.pem
    as_root cp "$key" certs/key.pem
    env_set Kestrel__Certificates__Default__Path /certs/cert.pem
    env_set Kestrel__Certificates__Default__KeyPath /certs/key.pem
    env_del Kestrel__Certificates__Default__Password
    cert_changed=1
  elif [ -n "$pfx" ]; then
    step "放入证书"
    as_root cp "$pfx" certs/cert.pfx
    env_set Kestrel__Certificates__Default__Path /certs/cert.pfx
    env_del Kestrel__Certificates__Default__KeyPath
    env_set Kestrel__Certificates__Default__Password "$pfx_password"
    cert_changed=1
  elif [ ! -e "certs/$(basename "$(env_get Kestrel__Certificates__Default__Path)")" ]; then
    step "生成自签证书（$domain）"
    command -v openssl > /dev/null || fail "没有找到 openssl，无法生成自签证书。安装 openssl，或用 --cert/--key 指定证书。"
    case "$domain" in
      *[!0-9.]*) san="DNS:$domain" ;;
      *) san="IP:$domain" ;;
    esac
    as_root openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$domain" \
      -addext "subjectAltName=$san" -keyout certs/key.pem -out certs/cert.pem 2> /dev/null
    env_set Kestrel__Certificates__Default__Path /certs/cert.pem
    env_set Kestrel__Certificates__Default__KeyPath /certs/key.pem
    self_signed=1
  fi
  # The container runs as uid 1654 (not root) and must be able to read the private key.
  as_root chown -R 1654:1654 certs
  as_root chmod 600 certs/*
  as_root chmod 755 certs
fi

# --- 镜像 -------------------------------------------------------------------
up_args=(up -d --wait --wait-timeout 180)
bundle="$(ls -1 compliance-server-*.tar.gz 2> /dev/null | grep -v -- '-deploy\.tar\.gz$' | sort -V | tail -n 1 || true)"
if [ "$build" = 1 ]; then
  step "从源码构建镜像（需要几分钟和外网访问 Docker Hub、npm、NuGet）"
  [ -f Dockerfile ] && [ -d ../../src ] || fail "本目录不在源码仓库中，无法构建；请使用发布的镜像包。"
  up_args+=(--build)
elif [ -n "$bundle" ]; then
  step "加载镜像 $bundle"
  docker load -i "$bundle"
elif docker image inspect compliance-server:latest > /dev/null 2>&1; then
  step "使用本机已有镜像 compliance-server:latest"
else
  [ -f Dockerfile ] && [ -d ../../src ] || fail "没有找到镜像：把发布的 compliance-server-<版本>.tar.gz 放进本目录后重试。"
  step "本目录没有镜像包，从源码构建（需要几分钟和外网访问 Docker Hub、npm、NuGet）"
  up_args+=(--build)
fi

# --- 升级前备份 -------------------------------------------------------------
if [ -n "$(docker compose ps -q --status running server 2> /dev/null)" ]; then
  step "升级前备份"
  ./backup.sh
fi

# --- 启动 -------------------------------------------------------------------
step "启动"
docker compose "${up_args[@]}" || { docker compose logs --tail 100; fail "启动失败，日志见上。"; }
# The certificate is read at startup; a container that up left running still has the old one.
[ "$first" = 1 ] || [ "$cert_changed" = 0 ] || docker compose restart server

step "等待管理端就绪"
host_port="$(env_get HTTPS_PORT)"
host_port="${host_port##*:}"
ready=0
for _ in $(seq 60); do
  if docker compose logs server 2> /dev/null | grep -q 'Now listening on'; then ready=1; break; fi
  sleep 2
done
[ "$ready" = 1 ] || { docker compose logs --tail 100 server; fail "管理端没有启动，日志见上。"; }
# In http mode the server only answers the trusted gateway, so it can only be checked from there.
if [ "$mode" = https ] && command -v curl > /dev/null; then
  ok=0
  for _ in $(seq 30); do
    curl -sfk --noproxy "*" --resolve "$domain:$host_port:127.0.0.1" "https://$domain:$host_port/api/status" > /dev/null 2>&1 && { ok=1; break; }
    sleep 2
  done
  [ "$ok" = 1 ] || { docker compose logs --tail 100 server; fail "无法访问 https://$domain:$host_port/api/status，日志见上。"; }
fi

# --- 结果 -------------------------------------------------------------------
url="https://$domain"
[ "$host_port" = 443 ] || [ "$mode" = http ] || url="$url:$host_port"
echo
echo "================================================================"
echo " 管理端已启动，版本 $(docker image inspect compliance-server:latest -f '{{index .Config.Labels "org.opencontainers.image.version"}}' 2> /dev/null || echo 未知)"
if [ "$mode" = https ]; then
  echo " 地址：  $url"
else
  echo " 地址：  经网关访问（上游 http://本机:$host_port，只接受 $(env_get Compliance__TrustedProxies__0) 的请求）"
fi
if [ "$first" = 1 ]; then
  echo " 账号：  $(env_get ADMIN_USER)"
  echo " 密码：  $(env_get ADMIN_PASSWORD)"
  echo "        （保存在 .env 里；登录后请在右上角「修改密码」）"
fi
echo "================================================================"
if [ "$mode" = https ]; then
  echo "- 给 $domain 加内网 DNS 记录指向这台服务器；客户端必须用这个域名访问，不能用 IP。"
fi
if [ "$self_signed" = 1 ]; then
  echo "- 使用的是自签证书，浏览器会提示不安全。客户端会校验证书，正式使用前请换成客户信任的证书："
  echo "  ./install.sh --cert 证书.pem --key 私钥.key；或把 certs/cert.pem 导入各终端的"
  echo "  「受信任的根证书颁发机构」（可用域组策略下发）。"
fi
echo "- 服务器时间要准确（开启 NTP）。"
echo "- 请立即备份并拷到别的机器保存：./backup.sh（签名密钥丢失后所有终端都要重新登记）。"
