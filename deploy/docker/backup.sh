#!/bin/sh
# 备份数据库和策略签名密钥到 backups/<时间>/。两者必须一起保存：只恢复数据库而丢了密钥，所有终端都会拒收新策略。
set -eu
cd "$(dirname "$0")"
dir="backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$dir"
docker compose exec -T db pg_dump -U compliance -d compliance -Fc > "$dir/compliance.dump"
docker compose exec -T server cat /var/lib/compliance/signing.key > "$dir/signing.key"
chmod 600 "$dir/signing.key"
echo "已备份到 $dir"
