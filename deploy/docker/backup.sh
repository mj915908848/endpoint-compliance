#!/bin/sh
# 备份数据库，以及管理端数据目录（策略签名密钥、正在更换和已换下的密钥、客户端安装包）到 backups/<时间>/。
# 两者必须一起保存：只恢复数据库而丢了密钥，所有终端都会拒收新策略；丢了安装包，远程升级会失败。
# 设置 KEEP=N（如 KEEP=14 ./backup.sh）只保留最近 N 份备份，默认全部保留。
set -eu
# 备份里有签名密钥和整个数据库，只给当前用户读写，避免写入过程中被本机其他用户读到。
umask 077
cd "$(dirname "$0")"
dir="backups/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$dir"
# 中途失败时删掉不完整的备份，免得以后误用。
trap 'rm -rf "$dir"; echo "备份失败，未生成备份" >&2' EXIT
# 密钥文件的内容和其余文件（安装包）的名字与大小；上传到一半的临时文件不算。
state() {
  docker compose exec -T server sh -c 'cd /var/lib/compliance && sha256sum signing.key* && find . -type f ! -name "signing.key*" ! -name "upload-*.tmp" -printf "%p %s\n" | sort'
}
# 先导出数据库再打包文件：安装包总是先写入文件再记入数据库、先从数据库删除再删文件，所以导出时数据库里有的安装包，
# 打包时文件都还在，除非中途被删除。导出期间若完成了更换密钥、上传或删除了安装包，前后文件不同，就重来。
for attempt in 1 2 3; do
  before=$(state)
  docker compose exec -T db pg_dump -U compliance -d compliance -Fc > "$dir/compliance.dump"
  docker compose exec -T server tar -C /var/lib/compliance -cf - . > "$dir/files.tar"
  [ "$(state)" = "$before" ] && break
  [ "$attempt" = 3 ] && { echo "签名密钥或客户端安装包一直在变化，请稍后再备份" >&2; exit 1; }
done
trap - EXIT
echo "已备份到 $dir"
if [ "${KEEP:-0}" -gt 0 ]; then
  ls -1d backups/*/ | sort | head -n "-$KEEP" | while read -r old; do rm -rf "$old"; done
fi
