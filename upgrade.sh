#!/bin/sh
# upgrade.sh - upgrade sing-box binary safely (FreeBSD 14, non-root)

set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "${SCRIPT_DIR}/common.sh"

require_freebsd_amd64
ensure_dirs

NEW_URL=${1:-${SB_URL_DEFAULT}}
TMP_BIN="${BIN_DIR}/sb-amd64.new"
OLD_BIN="${SB_BIN}"

info "下载新版本: ${NEW_URL}"
_fetch "${NEW_URL}" "${TMP_BIN}"
chmod +x "${TMP_BIN}"

# Basic sanity check: print version
if ! "${TMP_BIN}" version >/dev/null 2>&1; then
  err "新二进制无法运行，取消升级。"
  rm -f "${TMP_BIN}"
  exit 1
fi

# Stop running instance
pkill -TERM -f "${OLD_BIN}.*${CONF_DIR}/config.json" 2>/dev/null || true
sleep 1

# Backup and swap
BACKUP_BIN="${BIN_DIR}/sb-amd64.bak"
[ -f "${OLD_BIN}" ] && mv -f "${OLD_BIN}" "${BACKUP_BIN}" || true
mv -f "${TMP_BIN}" "${OLD_BIN}"

# Try start test (dry run)
if ! "${OLD_BIN}" version >/dev/null 2>&1; then
  err "升级后自检失败，回滚。"
  mv -f "${BACKUP_BIN}" "${OLD_BIN}"
  exit 1
fi

info "升级成功。可使用 ferrbsd.sh 重新启动服务。"
