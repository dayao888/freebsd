#!/bin/sh
# uninstall.sh - stop services and remove ferrbsd files (preserve certs)

set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "${SCRIPT_DIR}/common.sh"

require_freebsd_amd64

FERR_HOME="${HOME}/.local/ferrbsd"
CERT_DIR="${FERR_HOME}/certs"

printf "确定卸载 ferrbsd? 这将删除配置与二进制，但保留证书。 [y/N]: "
read -r ans || true
case "${ans:-N}" in
  y|Y) : ;; 
  *) echo "已取消。"; exit 0;;
esac

# Stop services
pkill -TERM -f "${SB_BIN}.*${FERR_HOME}/config.json" 2>/dev/null || true
pkill -TERM cloudflared 2>/dev/null || true
sleep 1

# Remove files except certs
if [ -d "${FERR_HOME}" ]; then
  find "${FERR_HOME}" -mindepth 1 -maxdepth 1 \
    ! -name certs \
    -exec rm -rf {} +
fi

echo "已卸载，证书保留在：${CERT_DIR}"
