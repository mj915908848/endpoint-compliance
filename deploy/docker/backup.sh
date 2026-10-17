#!/bin/sh
# 备份数据库和策略签名密钥到 backups/<时间>/。两者必须一起保存：只恢复数据库而丢了密钥，所有终端都会拒收新策略。
set -eu
# 备份里有签名密钥和整个数据库，只给当前用户读写，避免写入过程中被本机其他用户读到。
umask 077
cd "$(dirname "$0")"
dir="backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$dir"
docker compose exec -T db pg_dump -U compliance -d compliance -Fc > "$dir/compliance.dump"
docker compose exec -T server cat /var/lib/compliance/signing.key > "$dir/signing.key"
chmod 600 "$dir/signing.key"
# 更换密钥进行中时还有新密钥，一并保存，恢复后可以继续更换。
if docker compose exec -T server test -f /var/lib/compliance/signing.key.next; then
  docker compose exec -T server cat /var/lib/compliance/signing.key.next > "$dir/signing.key.next"
  chmod 600 "$dir/signing.key.next"
fi
echo "已备份到 $dir"
