#!/bin/sh
# ferrbsd.sh - ferrbsd one-click (FreeBSD 14 amd64, non-root)
# Features: VLESS-Reality (TCP), Hysteria2 (UDP), VMess+WS (for Argo fixed tunnel),
# optional WireGuard outbound, DNS/routing/rule-sets, clean URI output only at end.

set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "${SCRIPT_DIR}/common.sh"

require_freebsd_amd64
ensure_dirs

# Load .env if exists
if [ -f "${ENV_FILE}" ]; then
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
fi

# Interactive inputs
printf "是否从官方发行地址下载 sing-box 二进制？[Y/n]: "
read -r ans || true
case "${ans:-Y}" in
  n|N) printf "请输入自定义下载 URL: "; read -r SB_URL ;; 
  *) SB_URL="${SB_URL_DEFAULT}" ;;
esac

SERVER_IP=${SERVER_IP:-$(ext_ip)}
[ -n "${SERVER_IP:-}" ] || SERVER_IP="127.0.0.1"

# Use fixed defaults unless user overrides via .env or input
VLESS_REALITY_PORT=${VLESS_REALITY_PORT:-22099}
VMESS_WS_PORT=${VMESS_WS_PORT:-33088}
HY2_PORT=${HY2_PORT:-33366}
HY2_MPORT=${HY2_MPORT:-}
WSPATH=${WSPATH:-/ws}
REALITY_SNI=${REALITY_SNI:-addons.mozilla.org}
REALITY_FP=${REALITY_FP:-chrome}

printf "使用官方证书(ACME DNS-01)？[Y/n]: "
read -r ans || true
case "${ans:-Y}" in
  n|N) ACME_ENABLE=0 ;;
  *) ACME_ENABLE=1 ;;
esac
if [ "${ACME_ENABLE}" = "1" ]; then
  printf "请输入证书域名(供需要 TLS 的入站使用，可留空跳过)："
  read -r ACME_DOMAIN || true
  printf "ACME 邮箱（可留空）："; read -r ACME_EMAIL || true
  printf "Cloudflare API Token（DNS-01，用于自动签发；留空则跳过）："; read -r CF_API_TOKEN || true
fi

# Argo fixed tunnel config — 优先 token 模式，最简
ARGO_MODE=${ARGO_MODE:-fixed}
printf "使用 Cloudflare 固定隧道？[Y/n] (临时隧道仅测试用) : "
read -r ans || true
case "${ans:-Y}" in
  n|N) ARGO_MODE="quick" ;;
  *) ARGO_MODE="fixed" ;;
esac
if [ "${ARGO_MODE}" = "fixed" ]; then
  printf "如已创建固定隧道，优先粘贴 ARGO_TOKEN（最简）。留空则走凭据文件模式：\nARGO_TOKEN："
  read -r ARGO_TOKEN || true
  if [ -z "${ARGO_TOKEN}" ]; then
    printf "未提供 Token，将使用凭据文件方式。\n隧道名称（任意名称，用于标识）："; read -r ARGO_TUN_NAME || true
    printf "隧道 ID（UUID）："; read -r ARGO_TUN_ID || true
    printf "隧道凭据 JSON 文件路径（可留空，按你系统默认）："; read -r ARGO_CRED_FILE || true
    printf "用于公开访问的自有域名（CNAME 至隧道，可留空稍后再绑定）："; read -r ARGO_DOMAIN || true
  fi
else
  ARGO_TUN_NAME=""; ARGO_TUN_ID=""; ARGO_CRED_FILE=""; ARGO_TOKEN="${ARGO_TOKEN:-}"
  printf "将使用临时隧道(trycloudflare.com)。可输入用于显示的域名(留空跳过)："; read -r ARGO_DOMAIN || true
fi

# WireGuard outbound optional
printf "启用 WireGuard 出站以尝试提速？[y/N]: "
read -r ans || true
case "${ans:-N}" in
  y|Y)
    WG_ENABLED=1
    printf "WG 私钥："; read -r WG_PRIVATE_KEY
    printf "WG Peer (ip:port)："; read -r WG_PEER
    printf "WG 对端公钥："; read -r WG_PUBKEY
    printf "WG AllowedIPs (逗号分隔)："; read -r WG_ALLOWED_IPS
    printf "WG MTU [1280]："; read -r tmp; WG_MTU=${tmp:-1280}
    ;;
  *) WG_ENABLED=0 ;;
esac

# Persist env for re-runs
save_env

# Ensure sing-box binary
ensure_sb "${SB_URL}"

# Fallbacks if helper functions not present in older common.sh
command -v ensure_acme_sh >/dev/null 2>&1 || ensure_acme_sh() {
  # Try to install acme.sh non-root
  if [ -x "$HOME/.acme.sh/acme.sh" ]; then return 0; fi
  if command -v curl >/dev/null 2>&1; then
    sh -c "$(curl -fsSL https://get.acme.sh)" || return 1
  elif command -v fetch >/dev/null 2>&1; then
    tmp="/tmp/acme.sh.install.sh"; fetch -q -o "${tmp}" https://get.acme.sh && sh "${tmp}" || return 1
  elif command -v wget >/dev/null 2>&1; then
    sh -c "$(wget -qO- https://get.acme.sh)" || return 1
  else
    return 1
  fi
}
command -v ensure_cloudflared >/dev/null 2>&1 || ensure_cloudflared() {
  if command -v cloudflared >/dev/null 2>&1; then return 0; fi
  local cfb="${BIN_DIR}/cloudflared"; mkdir -p "${BIN_DIR}" || true
  if [ -x "${cfb}" ]; then PATH="${BIN_DIR}:$PATH"; export PATH; return 0; fi
  ver="2024.8.1"; url="https://github.com/cloudflare/cloudflared/releases/download/${ver}/cloudflared-freebsd-amd64"
  tmp="${cfb}.tmp"; if _fetch "${url}" "${tmp}"; then chmod +x "${tmp}" && mv "${tmp}" "${cfb}" && PATH="${BIN_DIR}:$PATH"; export PATH; return 0; fi
  return 1
}

# Helper: OpenSSL fallback to create Reality keypair (base64url, no padding)
openssl_reality_keypair() {
  # outputs two global vars: REALITY_PRIVATE_KEY, REALITY_PUBLIC_KEY
  REALITY_PRIVATE_KEY=""; REALITY_PUBLIC_KEY=""
  # temp files
  kf="/tmp/reality_key.pem"; pf="/tmp/reality_pub.pem"
  [ -f "$kf" ] || openssl genpkey -algorithm X25519 -out "$kf" >/dev/null 2>&1
  [ -f "$pf" ] || openssl pkey -in "$kf" -pubout -out "$pf" >/dev/null 2>&1
  REALITY_PRIVATE_KEY=$(openssl pkey -in "$kf" -text -noout \
    | sed -n '/priv:/,/pub:/p' | sed '1d;$d' | tr -d ':\n ' \
    | xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '=')
  REALITY_PUBLIC_KEY=$(openssl pkey -pubin -in "$pf" -text -noout \
    | sed -n '/pub:/,/^$/p' | sed '1d' | tr -d ':\n ' \
    | xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '=')
}

# Small helper to sanitize (strip CR/LF and trim spaces)
sanitize() { printf '%s' "$1" | tr -d '\r' | awk '{$1=$1}1'; }

# Generate UUIDs and keys
UUID_MAIN=$(mk_uuid | head -n1 | tr -d '\r')
UUID_MAIN=$(sanitize "${UUID_MAIN}")
HY2_PASS="${UUID_MAIN}"
mk_reality_keys || true
# If keys are empty, try OpenSSL fallback automatically
if [ -z "${REALITY_PRIVATE_KEY:-}" ] || [ -z "${REALITY_PUBLIC_KEY:-}" ]; then
  openssl_reality_keypair
fi
# Sanitize Reality keys
REALITY_PRIVATE_KEY=$(sanitize "${REALITY_PRIVATE_KEY}")
REALITY_PUBLIC_KEY=$(sanitize "${REALITY_PUBLIC_KEY}")

# Build sing-box config.json (define before ACME to avoid unset in reloadcmd)
CONFIG_JSON="${CONF_DIR}/config.json"

# Normalize frequently used fields before templating
REALITY_SNI=$(sanitize "${REALITY_SNI}")
REALITY_FP=$(sanitize "${REALITY_FP}")
WSPATH=$(sanitize "${WSPATH}")
ACME_DOMAIN=$(sanitize "${ACME_DOMAIN:-}")
ACME_EMAIL=$(sanitize "${ACME_EMAIL:-}")
ARGO_DOMAIN=$(sanitize "${ARGO_DOMAIN:-}")

# ACME: issue/renew using acme.sh DNS-01 (Cloudflare)
setup_acme() {
  [ "${ACME_ENABLE:-0}" = "1" ] || return 0
  [ -n "${ACME_DOMAIN:-}" ] || { warn "未提供 ACME_DOMAIN，跳过证书签发"; return 0; }
  if [ -z "${CF_API_TOKEN:-}" ]; then
    warn "未提供 CF_API_TOKEN，跳过证书签发"
    return 0
  fi
  ensure_acme_sh || { warn "acme.sh 安装失败，跳过证书签发"; return 0; }
  ACME_BIN="$HOME/.acme.sh/acme.sh"
  # Force Let's Encrypt (avoid ZeroSSL email requirement)
  "$ACME_BIN" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  if ! "$ACME_BIN" --list | grep -q "ACCOUNT_.*LETSENCRYPT" 2>/dev/null; then
    if [ -n "${ACME_EMAIL:-}" ]; then
      "$ACME_BIN" --register-account -m "${ACME_EMAIL}" >/dev/null 2>&1 || true
    else
      # Try register without email (LE allows), ignore failure
      "$ACME_BIN" --register-account >/dev/null 2>&1 || true
    fi
  fi
  export CF_Token="${CF_API_TOKEN:-}"
  export CF_Zone_ID="${CF_ZONE_ID:-}"
  export CF_Account_ID="${CF_ACCOUNT_ID:-}"
  mkdir -p "${CERT_DIR}"
  if ! "$ACME_BIN" --list | grep -q "${ACME_DOMAIN}.*ECC"; then
    info "申请证书: ${ACME_DOMAIN} (Let’s Encrypt / DNS-01)"
    "$ACME_BIN" --issue --dns dns_cf -d "${ACME_DOMAIN}" --keylength ec-256 || {
      warn "证书申请失败，稍后可重试"
      return 0
    }
  fi
  "$ACME_BIN" --install-cert -d "${ACME_DOMAIN}" --ecc \
    --fullchain-file "${CERT_DIR}/fullchain.cer" \
    --key-file "${CERT_DIR}/private.key" \
    --reloadcmd "pkill -HUP -f '${SB_BIN}.*${CONFIG_JSON}' || true" || true
  "$ACME_BIN" --install-cronjob >/dev/null 2>&1 || true
}

# Run ACME issuance first (might provide certs for HY2)
setup_acme

# TLS for HY2 if cert present
HY2_TLS_ENABLED=0
CERT_PATH="${CERT_DIR}/fullchain.cer"
KEY_PATH="${CERT_DIR}/private.key"
if [ -f "${CERT_PATH}" ] && [ -f "${KEY_PATH}" ]; then
  HY2_TLS_ENABLED=1
fi

# DNS and routing with rule-sets (use local resolver to avoid address_resolver issues)
DNS_JSON=$(cat <<D
  "dns": {
    "servers": [
      {"tag": "local", "address": "local"}
    ],
    "final": "local",
    "strategy": "ipv4_only"
  },
D
)

ROUTE_JSON=$(cat <<R
  "route": {
    "rule_set": [
      {"tag": "geosite-category-ads-all", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs", "download_detour": "direct"},
      {"tag": "geosite-cn", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs", "download_detour": "direct"},
      {"tag": "geoip-cn", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", "download_detour": "direct"}
    ],
    "rules": [
      {"protocol": "dns", "outbound": "dns-out"},
      {"ip_is_private": true, "outbound": "direct"},
      {"rule_set": ["geosite-category-ads-all"], "outbound": "block"},
      {"rule_set": ["geosite-cn", "geoip-cn"], "outbound": "direct"}
    ],
    "final": "direct"
  }
R
)

# Inbounds
VLESS_IN=$(cat <<V
    {
      "tag": "vless-reality-in",
      "type": "vless",
      "listen": "::",
      "listen_port": ${VLESS_REALITY_PORT},
      "users": [{"uuid": "${UUID_MAIN}", "flow": ""}],
      "tls": {
        "enabled": true,
        "server_name": "${REALITY_SNI}",
        "reality": {
          "enabled": true,
          "handshake": {"server": "${REALITY_SNI}", "server_port": 443},
          "private_key": "${REALITY_PRIVATE_KEY}",
          "short_id": [""]
        }
      }
    }
V
)

HY2_IN=$(cat <<H
    {
      "tag": "hysteria-in",
      "type": "hysteria2",
      "listen": "::",
      "listen_port": ${HY2_PORT},
      "users": [{"password": "${HY2_PASS}"}],
      "masquerade": "https://www.bing.com",
      "tls": {
        "enabled": $( [ ${HY2_TLS_ENABLED} -eq 1 ] && printf true || printf false ),
        "alpn": ["h3"],
        "certificate_path": "${CERT_PATH}",
        "key_path": "${KEY_PATH}"
      }
    }
H
)

VMESS_IN=$(cat <<M
    {
      "tag": "vmess-ws-in",
      "type": "vmess",
      "listen": "::",
      "listen_port": ${VMESS_WS_PORT},
      "users": [{"uuid": "${UUID_MAIN}"}],
      "transport": {"type": "ws", "path": "${WSPATH}", "early_data_header_name": "Sec-WebSocket-Protocol"}
    }
M
)

# Optional WireGuard outbound JSON
WG_OUTBOUND=""
if [ "${WG_ENABLED}" = "1" ]; then
  WG_OUTBOUND=$(cat <<W
    ,{
      "type": "wireguard",
      "tag": "wireguard-out",
      "server": "$(printf '%s' "${WG_PEER}" | cut -d: -f1)",
      "server_port": $(printf '%s' "${WG_PEER}" | cut -d: -f2),
      "local_address": ["172.16.0.2/32"],
      "private_key": "${WG_PRIVATE_KEY}",
      "peer_public_key": "${WG_PUBKEY}",
      "reserved": [26,21,228],
      "mtu": ${WG_MTU}
    }
W
)
fi

# Assemble full config
cat > "${CONFIG_JSON}" <<JSON
{
  "log": {"disabled": false, "level": "info", "timestamp": true},
  ${DNS_JSON}
  "inbounds": [
${VLESS_IN},
${HY2_IN},
${VMESS_IN}
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"},
    {"type": "dns", "tag": "dns-out"}
    ${WG_OUTBOUND}
  ],
  ${ROUTE_JSON}
}
JSON

# Quick JSON sanity (avoid silent broken file)
if ! grep -q '"inbounds"' "${CONFIG_JSON}"; then
  err "生成的 config.json 异常，请检查变量是否含有非法字符。"; exit 1
fi

# Start sing-box (restart if running)
kill -TERM $(pgrep -f "${SB_BIN}.*${CONFIG_JSON}" || true) 2>/dev/null || true
nohup "${SB_BIN}" run -c "${CONFIG_JSON}" >"${LOG_DIR}/singbox.out" 2>&1 &

# Cloudflared: create/route/run fixed tunnel, or run with token
setup_argo() {
  [ "${ARGO_MODE:-fixed}" = "fixed" ] || return 0
  ensure_cloudflared || { warn "cloudflared 不可用，跳过隧道启动"; return 0; }
  mkdir -p "${ARGO_DIR}" "${LOG_DIR}" || true
  # Token mode is preferred (no cred path required)
  if [ -n "${ARGO_TOKEN:-}" ]; then
    info "使用 Token 运行固定隧道"
    nohup cloudflared tunnel --no-autoupdate run --token "${ARGO_TOKEN}" >"${LOG_DIR}/cloudflared.out" 2>&1 &
    return 0
  fi
  # Cred-file mode (optional)
  if [ -n "${ARGO_TUN_NAME:-}" ] && [ -n "${ARGO_TUN_ID:-}" ] && [ -n "${ARGO_CRED_FILE:-}" ] && [ -n "${ARGO_DOMAIN:-}" ]; then
    CFG_FILE="${ARGO_DIR}/config.yml"
    cat >"${CFG_FILE}" <<Y
`tunnel`: ${ARGO_TUN_NAME}
`credentials-file`: ${ARGO_CRED_FILE}

ingress:
  - hostname: ${ARGO_DOMAIN}
    service: http://127.0.0.1:${VMESS_WS_PORT}
  - service: http_status:404
Y
    cloudflared tunnel --config "${CFG_FILE}" route dns "${ARGO_TUN_NAME}" "${ARGO_DOMAIN}" >/dev/null 2>&1 || true
    nohup cloudflared --config "${CFG_FILE}" tunnel run "${ARGO_TUN_NAME}" >"${LOG_DIR}/cloudflared.out" 2>&1 &
  fi
}

# Start/ensure Cloudflare tunnel per configuration
setup_argo

# Build URIs and print as the ONLY final output (single-line)
VMESS_HOST="${ARGO_DOMAIN:-${SERVER_IP}}"
VLESS_URI=$(build_vless_reality_uri "${UUID_MAIN}" "${SERVER_IP}" "${VLESS_REALITY_PORT}" "${REALITY_SNI}" "${REALITY_FP}" "${REALITY_PUBLIC_KEY}" "vless-reality")
HY2_URI=$(build_hy2_uri "${HY2_PASS}" "${SERVER_IP}" "${HY2_PORT}" "${HY2_MPORT}" "$( [ ${HY2_TLS_ENABLED} -eq 1 ] && printf 0 || printf 1 )" "hysteria2")
VMESS_URI=$(build_vmess_ws_uri "${VMESS_HOST}" "443" "${UUID_MAIN}" "${WSPATH}" "${VMESS_HOST}" "argo-vmess")

# Clean output only
printf '%s\n' "${VLESS_URI}" | tr -d '\r'
printf '%s\n' "----------------------------"
printf '%s\n' "${HY2_URI}" | tr -d '\r'
printf '%s\n' "----------------------------"
printf '%s\n' "${VMESS_URI}" | tr -d '\r'
