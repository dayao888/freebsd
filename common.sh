#!/bin/sh
# common.sh - shared helpers for ferrbsd scripts (FreeBSD 14, non-root)
# POSIX sh compatible

set -eu

# Workdir layout
FERR_HOME="${HOME}/.local/ferrbsd"
BIN_DIR="${FERR_HOME}/bin"
CONF_DIR="${FERR_HOME}"
LOG_DIR="${FERR_HOME}/logs"
CERT_DIR="${FERR_HOME}/certs"
ARGO_DIR="${FERR_HOME}/argo"
RULE_DIR="${FERR_HOME}/rules"
ENV_FILE="${FERR_HOME}/.env"
SB_BIN="${BIN_DIR}/sb-amd64"

# Release URL (from your plan)
SB_URL_DEFAULT="https://github.com/dayao888/ferrbsd-sbx/releases/download/v1.10/sb-amd64"

# Colors (minimal)
info() { printf '%s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err()  { printf '[ERR ] %s\n' "$*" >&2; }

# Ensure directories
ensure_dirs() {
  mkdir -p "${BIN_DIR}" "${LOG_DIR}" "${CERT_DIR}" "${ARGO_DIR}" "${RULE_DIR}"
}

# Check platform
require_freebsd_amd64() {
  os=$(uname -s 2>/dev/null || true)
  arch=$(uname -m 2>/dev/null || true)
  if [ "${os}" != "FreeBSD" ]; then
    err "仅支持 FreeBSD。检测到: ${os}"
    exit 1
  fi
  case "${arch}" in
    amd64|x86_64) : ;;
    *) err "仅支持 amd64。检测到: ${arch}"; exit 1;;
  esac
  if [ "$(id -u)" = "0" ]; then
    err "请以非 root 用户运行。"
    exit 1
  fi
}

# Fetch wrapper (prefer fetch, fallback to curl/wget if installed)
_fetch() {
  url="$1"; out="$2"
  if command -v fetch >/dev/null 2>&1; then
    fetch -q -o "${out}" "${url}"
  elif command -v curl >/dev/null 2>&1; then
    curl -fsSL "${url}" -o "${out}"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "${out}" "${url}"
  else
    err "需要 fetch/curl/wget 之一以下载资源"
    return 1
  fi
}

# Download sing-box binary if missing
ensure_sb() {
  url="${1:-${SB_URL_DEFAULT}}"
  if [ ! -x "${SB_BIN}" ]; then
    info "下载 sing-box 二进制..."
    tmp="${BIN_DIR}/sb-amd64.tmp"
    _fetch "${url}" "${tmp}"
    chmod +x "${tmp}"
    mv "${tmp}" "${SB_BIN}"
  fi
}

# Random high port (not guaranteed free, but randomized)
rand_port_tcp() {
  awk 'BEGIN{srand(); printf "%d\n", 20000+int(rand()*30000)}'
}
rand_port_udp() {
  awk 'BEGIN{srand(); printf "%d\n", 20000+int(rand()*30000)}'
}

# UUID v4 (use sb if available, else fallback)
mk_uuid() {
  if [ -x "${SB_BIN}" ]; then
    out=$("${SB_BIN}" generate uuid 2>/dev/null || true)
    if [ -n "${out}" ]; then
      printf '%s' "${out}" | head -n1 | tr -d '\r\n[:space:]'
      return 0
    fi
  fi
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | head -n1 | tr -d '\r\n[:space:]'
  else
    dd if=/dev/urandom bs=16 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n' | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1\2\3\4-\5\6-\7\8-\9\10-\11\12\13\14\15\16/' | tr -d '\n'
  fi
}

# Generate Reality keypair using sing-box if available; else prompt
# Outputs two global vars: REALITY_PRIVATE_KEY, REALITY_PUBLIC_KEY
mk_reality_keys() {
  REALITY_PRIVATE_KEY=""; REALITY_PUBLIC_KEY=""
  if [ -x "${SB_BIN}" ]; then
    out=$("${SB_BIN}" generate reality-keypair --json 2>/dev/null || true)
    if [ -n "${out}" ]; then
      REALITY_PRIVATE_KEY=$(printf '%s' "${out}" | awk -F'"private_key" *: *"' '{print $2}' | awk -F'"' '{print $1}')
      REALITY_PUBLIC_KEY=$(printf '%s' "${out}" | awk -F'"public_key" *: *"' '{print $2}' | awk -F'"' '{print $1}')
    fi
  fi
  if [ -z "${REALITY_PRIVATE_KEY}" ] || [ -z "${REALITY_PUBLIC_KEY}" ]; then
    warn "无法自动生成 Reality 密钥，将交互询问。"
    printf "请输入 Reality 私钥 (key)："; read -r REALITY_PRIVATE_KEY
    printf "请输入 Reality 公钥 (pbk)："; read -r REALITY_PUBLIC_KEY
  fi
}

# External IP detection
ext_ip() {
  if command -v fetch >/dev/null 2>&1; then
    fetch -q -o - https://icanhazip.com 2>/dev/null | tr -d '\n' || true
  elif command -v curl >/dev/null 2>&1; then
    curl -fsSL https://icanhazip.com | tr -d '\n' || true
  else
    :
  fi
}

# Build URIs
# VLESS Reality URI
build_vless_reality_uri() {
  uuid="$1"; host_or_ip="$2"; port="$3"; sni="$4"; fp="$5"; pbk="$6"; tag="$7"
  printf 'vless://%s@%s:%s?security=reality&sni=%s&fp=%s&pbk=%s&type=tcp&encryption=none#%s\n' \
    "${uuid}" "${host_or_ip}" "${port}" "${sni}" "${fp}" "${pbk}" "${tag}"
}

# HY2 URI
build_hy2_uri() {
  pass="$1"; host_or_ip="$2"; port="$3"; mport="$4"; insecure="$5"; tag="$6"
  q=""; [ -n "${mport}" ] && q="mport=${mport}&"; [ "${insecure}" = "1" ] && q="${q}insecure=1" || q="${q%&}"
  q="$(printf '%s' "${q}" | sed 's/&$//')"
  if [ -n "${q}" ]; then
    printf 'hy2://%s@%s:%s?%s#%s\n' "${pass}" "${host_or_ip}" "${port}" "${q}" "${tag}"
  else
    printf 'hy2://%s@%s:%s#%s\n' "${pass}" "${host_or_ip}" "${port}" "${tag}"
  fi
}

# VMess URI (v2rayN standard base64 json)
# Fields: add(host), port, id(uuid), net(ws), type(none), host(sni/host), path, tls(optional)
build_vmess_ws_uri() {
  host="$1"; port="$2"; uuid="$3"; path="$4"; sni="$5"; tag="$6"
  # v2rayN JSON
  json=$(cat <<J
{
  "v": "2",
  "ps": "${tag}",
  "add": "${host}",
  "port": "${port}",
  "id": "${uuid}",
  "aid": "0",
  "net": "ws",
  "type": "none",
  "host": "${sni}",
  "path": "${path}",
  "tls": "tls"
}
J
)
  b64=$(printf '%s' "$json" | base64 | tr -d '\n')
  printf 'vmess://%s\n' "$b64"
}

# Ensure cloudflared availability (optional). Download static binary for FreeBSD amd64 if missing.
ensure_cloudflared() {
  if command -v cloudflared >/dev/null 2>&1; then
    return 0
  fi
  local cfb="${BIN_DIR}/cloudflared"
  if [ -x "${cfb}" ]; then
    PATH="${BIN_DIR}:$PATH"; export PATH
    return 0
  fi
  info "尝试下载 cloudflared 二进制(FreeBSD amd64)..."
  mkdir -p "${BIN_DIR}" || true
  # Try latest first, then a few pinned versions
  urls='
https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-freebsd-amd64
https://github.com/cloudflare/cloudflared/releases/download/2024.10.0/cloudflared-freebsd-amd64
https://github.com/cloudflare/cloudflared/releases/download/2024.9.1/cloudflared-freebsd-amd64
https://github.com/cloudflare/cloudflared/releases/download/2024.7.0/cloudflared-freebsd-amd64
'
  tmp="${cfb}.tmp"
  echo "$urls" | while read -r url; do
    [ -z "$url" ] && continue
    if _fetch "$url" "$tmp" 2>/dev/null; then
      chmod +x "$tmp" && mv "$tmp" "$cfb"
      break
    fi
  done
  if [ -x "${cfb}" ]; then
    PATH="${BIN_DIR}:$PATH"; export PATH
    info "cloudflared 已安装到 ${cfb}"
    return 0
  fi
  warn "无法自动下载 cloudflared，请手动安装或放置到 PATH。"
  return 1
}

# Save .env helper
save_env() {
  umask 077
  {
    printf 'SERVER_IP=%s\n' "${SERVER_IP:-}"
    printf 'VLESS_REALITY_PORT=%s\n' "${VLESS_REALITY_PORT:-}"
    printf 'HY2_PORT=%s\n' "${HY2_PORT:-}"
    printf 'HY2_MPORT=%s\n' "${HY2_MPORT:-}"
    printf 'VMESS_WS_PORT=%s\n' "${VMESS_WS_PORT:-}"
    printf 'WSPATH=%s\n' "${WSPATH:-/ws}"
    printf 'REALITY_SNI=%s\n' "${REALITY_SNI:-addons.mozilla.org}"
    printf 'REALITY_FP=%s\n' "${REALITY_FP:-chrome}"
    printf 'ARGO_MODE=%s\n' "${ARGO_MODE:-fixed}"
    printf 'ARGO_DOMAIN=%s\n' "${ARGO_DOMAIN:-}"
    printf 'ARGO_TUN_NAME=%s\n' "${ARGO_TUN_NAME:-}"
    printf 'ARGO_TUN_ID=%s\n' "${ARGO_TUN_ID:-}"
    printf 'ARGO_CRED_FILE=%s\n' "${ARGO_CRED_FILE:-}"
    printf 'ACME_ENABLE=%s\n' "${ACME_ENABLE:-1}"
    printf 'ACME_PROVIDER=%s\n' "${ACME_PROVIDER:-cloudflare}"
    printf 'ACME_DOMAIN=%s\n' "${ACME_DOMAIN:-}"
    printf 'ACME_EMAIL=%s\n' "${ACME_EMAIL:-}"
    printf 'CF_API_TOKEN=%s\n' "${CF_API_TOKEN:-}"
    printf 'CF_ZONE_ID=%s\n' "${CF_ZONE_ID:-}"
    printf 'CF_ACCOUNT_ID=%s\n' "${CF_ACCOUNT_ID:-}"
    printf 'WG_ENABLED=%s\n' "${WG_ENABLED:-0}"
    printf 'WG_PRIVATE_KEY=%s\n' "${WG_PRIVATE_KEY:-}"
    printf 'WG_PEER=%s\n' "${WG_PEER:-}"
    printf 'WG_PUBKEY=%s\n' "${WG_PUBKEY:-}"
    printf 'WG_ALLOWED_IPS=%s\n' "${WG_ALLOWED_IPS:-}"
    printf 'WG_MTU=%s\n' "${WG_MTU:-1280}"
  } > "${ENV_FILE}"
}
