#!/bin/sh
# FreeBSD 14.x amd64 非root一键脚本：安装/配置 sing-box 三协议 + Cloudflare 固定/临时隧道
# 目标：复制粘贴运行，输出 v2rayN 可用节点信息；用户态安装；可彻底清理；保留二进制与证书/Token。

set -eu

# ========== 可按需修改的变量区（预留修改位） ==========
# 基础域名与子域
DOMAIN_BASE="1988518.xyz"           # 申请证书用的基础域名（例：1988518.xyz）
HY2_HOST="hy2.${DOMAIN_BASE}"       # HY2 使用的证书域名（可改）
CF_TUNNEL_HOST="ww.1988518.xyz}"  # 固定隧道对外域名（你提供的：ww.1988518.xyz）

# DNS-01（Cloudflare）API 凭据（首次写入 secret.env 后续自动读取）
# 仅示例名称，值从 secret.env 读取，不在脚本中明文硬编码
CF_TOKEN_PLACEHOLDER=""
CF_ACCOUNT_ID_PLACEHOLDER=""

# 端口（默认满足计划书，可修改）
PORT_VLESS_REALITY=22099   # TCP
PORT_HY2=33366             # UDP
PORT_VMESS_WS=33088        # 本地 WS 仅供隧道回源

# VLESS Reality 伪装站
REALITY_SNI="www.bing.com"   # 你确认使用 www.bing.com
FP="chrome"

# HY2 建议带宽（按物理带宽的 90% 左右，可自行调整）
HY2_UP_MBPS=${HY2_UP_MBPS:-95}
HY2_DOWN_MBPS=${HY2_DOWN_MBPS:-95}

# 隧道与加速参数（可 AB 测试）
CF_EDGE_IP_VERSION="4"     # 仅 IPv4（设备无 IPv6）
CF_PROTOCOL="quic"         # quic 优先
CF_HA_CONN="4"             # 并发连接数（4~8 建议）
CF_REGION_HINT=""          # 可留空或填区域短码

# 节点备注前缀（随机生成，不固定）
TAG_PREFIX=""

# ========== 固定路径与内部变量 ==========
BASE_DIR="$HOME/.config/sbx"
BIN_DIR="$HOME/.local/bin"
CACHE_DIR="$HOME/.cache/sbx"
CERT_DIR="$BASE_DIR/certs"
LOG_DIR="$BASE_DIR/logs"
SB_BIN="$BIN_DIR/sb"
CF_BIN="$BIN_DIR/cloudflared"
SECRET_ENV="$BASE_DIR/secret.env"
SB_CONF="$BASE_DIR/sing-box.json"
CLOUDFLARED_MODE_FILE="$BASE_DIR/.tunnel_mode"     # fixed 或 ephemeral
WS_PATH_FILE="$BASE_DIR/.ws_path"
HY2_CERT="$CERT_DIR/hy2.crt"
HY2_KEY="$CERT_DIR/hy2.key"
CF_LOG="$LOG_DIR/cloudflared.log"
SB_LOG_ERR="$LOG_DIR/sing-box.err"
INSTALL_LOG="$LOG_DIR/install.log"
LOG_ROTATE_SIZE_BYTES=${LOG_ROTATE_SIZE_BYTES:-1048576}
LOG_ROTATE_BACKUPS=${LOG_ROTATE_BACKUPS:-3}

# 下载地址（按计划书固定版本）
SB_URL="https://github.com/dayao888/ferrbsd-sbx/releases/download/v1.10/sb-amd64"
CF_URL="https://github.com/dayao888/ferrbsd-sbx/releases/download/v1.10/cloudflared"

# FreeBSD 工具
FETCH() { command -v fetch >/dev/null 2>&1 && fetch "$@" || curl -L -o "${2:-}" "$1"; }

rand_hex() { hexdump -vn16 -e '16/1 "%02x"' /dev/urandom 2>/dev/null || openssl rand -hex 16; }
rand_tag() { echo "${TAG_PREFIX:-asfxcx}-$(rand_hex | cut -c1-6)"; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "缺少依赖：$1"; exit 1; }; }
mkdirs() { mkdir -p "$BASE_DIR" "$BIN_DIR" "$CACHE_DIR" "$CERT_DIR" "$LOG_DIR"; }

# 简易日志轮转（copytruncate），避免文件句柄问题
log_size_bytes() { [ -f "$1" ] || { echo 0; return; }; wc -c < "$1" 2>/dev/null || echo 0; }
rotate_copytruncate() {
  f="$1"; max="${2:-3}"
  # 级联备份：.2 -> .3, .1 -> .2
  i=$max
  while [ $i -ge 2 ]; do
    prev=$((i-1))
    [ -f "$f.$prev" ] && mv -f "$f.$prev" "$f.$i" || true
    i=$((i-1))
  done
  [ -f "$f" ] && cp -f "$f" "$f.1" 2>/dev/null || true
  : > "$f"
}
rotate_if_oversize() {
  f="$1"; thr="${2:-$LOG_ROTATE_SIZE_BYTES}"; keeps="${3:-$LOG_ROTATE_BACKUPS}"
  [ -f "$f" ] || return 0
  sz=$(log_size_bytes "$f")
  [ "${sz:-0}" -ge "${thr:-1048576}" ] && rotate_copytruncate "$f" "$keeps" || true
}
ext_ip() {
  ip=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)
  [ -n "$ip" ] || ip=$(fetch -q -T 5 -o - https://api.ipify.org 2>/dev/null || true)
  printf '%s' "${ip:-127.0.0.1}"
}

save_secret() {
  # 首次运行写入 secret.env（敏感信息仅本地保存，权限 600）
  [ -f "$SECRET_ENV" ] || {
    umask 077
    cat >"$SECRET_ENV" <<EOF
# 仅本机使用，切勿外传
CF_Token=
CF_Account_ID=
CF_Tunnel_Token=
API_DOMAIN_BASE=${DOMAIN_BASE}
HY2_HOST=${HY2_HOST}
CF_TUNNEL_HOST=${CF_TUNNEL_HOST}
REALITY_SNI=${REALITY_SNI}
EOF
  };
}

load_secret() {
  [ -f "$SECRET_ENV" ] && . "$SECRET_ENV" || true
}

install_bins() {
  mkdirs
  # sing-box 二进制
  if [ ! -x "$SB_BIN" ]; then
    echo "下载 sing-box..."
    FETCH "$SB_URL" "$SB_BIN"
    chmod +x "$SB_BIN"
  fi
  # cloudflared 二进制
  if [ ! -x "$CF_BIN" ]; then
    echo "下载 cloudflared..."
    FETCH "$CF_URL" "$CF_BIN"
    chmod +x "$CF_BIN"
  fi
}

ensure_acme() {
  if [ ! -x "$HOME/.acme.sh/acme.sh" ]; then
    echo "安装 acme.sh (用户态)..."
    FETCH "https://get.acme.sh" "$CACHE_DIR/get.acme.sh"
    sh "$CACHE_DIR/get.acme.sh" -q >/dev/null 2>&1 || sh "$CACHE_DIR/get.acme.sh"
  fi
}

issue_cert_hy2() {
  ensure_acme
  load_secret
  if [ -z "${CF_Token:-}" ]; then
    echo "未在 $SECRET_ENV 中找到 CF_Token，将尝试自签证书作为临时方案。"
    return 1
  fi
  export CF_Token
  [ -n "${CF_Account_ID:-}" ] && export CF_Account_ID || true
  "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  "$HOME/.acme.sh/acme.sh" --issue --dns dns_cf -d "$HY2_HOST" --keylength ec-256 || return 1
  mkdir -p "$CERT_DIR"
  "$HOME/.acme.sh/acme.sh" --install-cert -d "$HY2_HOST" --ecc \
    --key-file "$HY2_KEY" --fullchain-file "$HY2_CERT" --reloadcmd "sh -c 'pkill -f \"${SB_BIN} run\" 2>/dev/null || true; sleep 0.3; nohup \"${SB_BIN}\" run -c \"${SB_CONF}\" >/dev/null 2>>\"${SB_LOG_ERR}\" &'"
  [ -s "$HY2_CERT" ] && [ -s "$HY2_KEY" ]
}

self_signed_cert_hy2() {
  mkdir -p "$CERT_DIR"
  # 自签 ECDSA 证书（1年，有效即可），仅 HY2 使用
  openssl ecparam -genkey -name prime256v1 -out "$HY2_KEY"
  openssl req -new -x509 -key "$HY2_KEY" -out "$HY2_CERT" -days 365 -subj "/CN=${HY2_HOST}"
}

# 生成 Reality 密钥对与短 ID
gen_reality_materials() {
  need_cmd "$SB_BIN"
  RE_OUT="$("$SB_BIN" generate reality-keypair)"
  REALITY_PRIVATE_KEY=$(echo "$RE_OUT" | awk -F': ' '/PrivateKey/{print $2}')
  REALITY_PUBLIC_KEY=$(echo "$RE_OUT" | awk -F': ' '/PublicKey/{print $2}')
  SHORT_ID=$(rand_hex | cut -c1-8)
}

# 生成 UUID 与 WS 路径
prepare_id_and_ws() {
  UUID_VLESS=$(uuidgen)
  UUID_VMESS=$(uuidgen)
  if [ -f "$WS_PATH_FILE" ]; then WS_PATH=$(cat "$WS_PATH_FILE"); else WS_PATH="/ws-$(rand_hex | cut -c1-8)"; echo "$WS_PATH" > "$WS_PATH_FILE"; fi
  HY2_PASSWORD=$(uuidgen)
}

# 写入 sing-box 服务端配置
write_singbox_config() {
  mkdirs
  cat >"$SB_CONF" <<JSON
{
  "log": {"level": "warn", "timestamp": true},
  "inbounds": [
    {
      "type": "vless",
      "listen": "0.0.0.0:${PORT_VLESS_REALITY}",
      "users": [{"uuid": "${UUID_VLESS}", "flow": "xtls-rprx-vision"}],
      "decryption": "none",
      "tls": {
        "enabled": true,
        "reality": {
          "enabled": true,
          "handshake": {"server": "${REALITY_SNI}", "server_port": 443},
          "private_key": "${REALITY_PRIVATE_KEY}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    },
    {
      "type": "hysteria2",
      "listen": "0.0.0.0:${PORT_HY2}",
      "users": [{"name": "u", "password": "${HY2_PASSWORD}"}],
      "up_mbps": ${HY2_UP_MBPS},
      "down_mbps": ${HY2_DOWN_MBPS},
      "tls": {"enabled": true, "certificate_path": "${HY2_CERT}", "key_path": "${HY2_KEY}"}
    },
    {
      "type": "vmess",
      "listen": "127.0.0.1:${PORT_VMESS_WS}",
      "users": [{"uuid": "${UUID_VMESS}", "alterId": 0}],
      "transport": {"type": "ws", "path": "${WS_PATH}"}
    }
  ]
}
JSON
}

bump_nofile() {
  old=$(ulimit -n 2>/dev/null || echo)
  ulimit -n 4096 2>/dev/null || ulimit -n 2048 2>/dev/null || true
  echo "nofile: ${old:-unset} -> $(ulimit -n 2>/dev/null || echo unknown)"
}

start_singbox() {
  bump_nofile
  rotate_if_oversize "$SB_LOG_ERR"
  nohup "$SB_BIN" run -c "$SB_CONF" >/dev/null 2>>"$SB_LOG_ERR" & echo $! > "$CACHE_DIR/sb.pid"
  sleep 0.8
}

stop_singbox() {
  [ -f "$CACHE_DIR/sb.pid" ] && kill "$(cat "$CACHE_DIR/sb.pid")" 2>/dev/null || true
}

start_tunnel_fixed() {
  load_secret
  [ -n "${CF_Tunnel_Token:-}" ] || { echo "未在 $SECRET_ENV 配置 CF_Tunnel_Token（固定隧道 Token）。"; return 1; }
  : >"$CF_LOG"
  bump_nofile
  nohup "$CF_BIN" tunnel --no-autoupdate run \
    --token "$CF_Tunnel_Token" \
    --edge-ip-version "$CF_EDGE_IP_VERSION" \
    --protocol "$CF_PROTOCOL" \
    --ha-connections "$CF_HA_CONN" \
    ${CF_REGION_HINT:+--region $CF_REGION_HINT} \
    >"$CF_LOG" 2>&1 & echo $! > "$CACHE_DIR/cf.pid"
  echo fixed > "$CLOUDFLARED_MODE_FILE"
}

start_tunnel_ephemeral() {
  : >"$CACHE_DIR/ephemeral.log"
  bump_nofile
  nohup "$CF_BIN" tunnel --no-autoupdate \
    --edge-ip-version "$CF_EDGE_IP_VERSION" \
    --protocol "$CF_PROTOCOL" \
    --url "http://127.0.0.1:${PORT_VMESS_WS}" \
    >"$CACHE_DIR/ephemeral.log" 2>&1 & echo $! > "$CACHE_DIR/cf.pid"
  echo ephemeral > "$CLOUDFLARED_MODE_FILE"
  # 等待生成 URL
  for i in 1 2 3 4 5; do
    sleep 1
    EP_URL=$(awk '/trycloudflare.com/{print $NF}' "$CACHE_DIR/ephemeral.log" | tail -n1 || true)
    [ -n "$EP_URL" ] && break || true
  done
}

stop_tunnel() {
  [ -f "$CACHE_DIR/cf.pid" ] && kill "$(cat "$CACHE_DIR/cf.pid")" 2>/dev/null || true
}

# 后台启动健康守护（若已运行则跳过）
start_watch_bg() {
  if [ -f "$CACHE_DIR/watch.pid" ] && kill -0 "$(cat "$CACHE_DIR/watch.pid" 2>/dev/null)" 2>/dev/null; then
    return 0
  fi
  nohup sh -c "$0 watch" > "$LOG_DIR/watch.log" 2>&1 & echo $! > "$CACHE_DIR/watch.pid"
}

watch_health() {
  WATCH_INTERVAL=${WATCH_INTERVAL:-5}
  BAD_THRESHOLD=${BAD_THRESHOLD:-10}    # 连续 BAD 次数触发切换（约 50 秒）
  RETRY_FIXED_AFTER=${RETRY_FIXED_AFTER:-300}  # 回探固定间隔（秒）
  OF_LIMIT_THRESHOLD=${OF_LIMIT_THRESHOLD:-3}  # FD 自愈阈值（近窗触发）
  HA_CUR=${CF_HA_CONN:-4}
  bad=0
  last_switch_ts_file="$CACHE_DIR/last_switch.ts"
  last_reason_file="$CACHE_DIR/switch_reason"
  last_fd_fix_ts=0
  touch "$CF_LOG" || true
  echo "watch 健康守护已启动，间隔 ${WATCH_INTERVAL}s；阈值 ${BAD_THRESHOLD}；回探 ${RETRY_FIXED_AFTER}s"
  while :; do
    # 进程自拉起
    if ! pgrep -f "$SB_BIN run" >/dev/null 2>&1; then
      echo "[watch] 检测到 sing-box 未运行，尝试拉起"
      start_singbox
    fi
    if ! pgrep -f "$CF_BIN" >/dev/null 2>&1; then
      echo "[watch] 检测到 cloudflared 未运行，尝试拉起"
      mode=$(cat "$CLOUDFLARED_MODE_FILE" 2>/dev/null || echo fixed)
      if [ "$mode" = "fixed" ]; then start_tunnel_fixed; else start_tunnel_ephemeral; fi
    fi

    mode=$(cat "$CLOUDFLARED_MODE_FILE" 2>/dev/null || echo fixed)
    if [ "$mode" = "fixed" ]; then
      proto=$(grep -aE 'protocol=(quic|http2)' "$CF_LOG" | tail -n1 | sed -E 's/.*protocol=([a-z0-9]+).*/\1/' || true)
      if [ "$proto" = "quic" ]; then
        bad=0
      else
        bad=$((bad+1))
      fi
      if ! pgrep -f "$CF_BIN" >/dev/null 2>&1; then
        bad=$((bad+1))
      fi
      if [ "$bad" -ge "$BAD_THRESHOLD" ]; then
        echo "[watch] 固定隧道异常（连续$bad次：协议非quic或进程异常），切换至临时隧道"
        echo "fixed->ephemeral due to non-quic or down" > "$last_reason_file" || true
        date +%s > "$last_switch_ts_file" || true
        stop_tunnel || true
        start_tunnel_ephemeral || true
        bad=0
      fi
    else
      # 处于临时隧道：时间到则尝试回探固定
      now=$(date +%s)
      last=$(cat "$last_switch_ts_file" 2>/dev/null || echo 0)
      if [ $((now - last)) -ge "$RETRY_FIXED_AFTER" ]; then
        echo "[watch] 回探固定隧道..."
        stop_tunnel || true
        start_tunnel_fixed || true
        # 回探后立即检查一次日志
        sleep "$WATCH_INTERVAL"
        proto=$(grep -aE 'protocol=(quic|http2)' "$CF_LOG" | tail -n1 | sed -E 's/.*protocol=([a-z0-9]+).*/\1/' || true)
        if [ "$proto" = "quic" ] && pgrep -f "$CF_BIN" >/dev/null 2>&1; then
          echo "[watch] 固定隧道恢复 QUIC，切回 fixed"
          echo "ephemeral->fixed recovered quic" > "$last_reason_file" || true
          date +%s > "$last_switch_ts_file" || true
        else
          echo "[watch] 固定隧道仍不达标，保持临时"
          stop_tunnel || true
          start_tunnel_ephemeral || true
          date +%s > "$last_switch_ts_file" || true
        fi
      fi
    fi

    # FD 自愈：检测 EMFILE，降级 ha-connections 并重启 cloudflared（加入冷却，避免抖动）
    oferr=$(tail -n 200 "$SB_LOG_ERR" 2>/dev/null | grep -ciE 'too many open files|EMFILE' || echo 0)
    if [ "${oferr:-0}" -ge "$OF_LIMIT_THRESHOLD" ]; then
      now_ts=$(date +%s)
      if [ $((now_ts - last_fd_fix_ts)) -lt 60 ]; then
        : # 冷却窗口内，跳过本次降级
      else
        if [ "$HA_CUR" -le 2 ]; then NEW_HA=2; else NEW_HA=$(( HA_CUR / 2 )); [ "$NEW_HA" -lt 2 ] && NEW_HA=2; fi
        echo "[watch] 检测到文件描述符耗尽(${oferr})，降级 ha-connections: ${HA_CUR} -> ${NEW_HA} 并重启 cloudflared"
        stop_tunnel || true
        bump_nofile
        CF_HA_CONN="$NEW_HA"
        start_tunnel_fixed || true
        HA_CUR="$NEW_HA"
        last_fd_fix_ts=$now_ts
        sleep 2
      fi
    fi

    # 对守护及关键日志做简易轮转，避免长时间增长
    rotate_if_oversize "$LOG_DIR/watch.log"
    rotate_if_oversize "$CF_LOG"
    rotate_if_oversize "$SB_LOG_ERR"

    sleep "$WATCH_INTERVAL"
  done
}

print_nodes() {
  load_secret
  # 计算 Reality 公钥（pbk）
  PBK="$REALITY_PUBLIC_KEY"
  TAG_VLESS=$(rand_tag)
  TAG_HY2=$(rand_tag)
  TAG_VMESS=$(rand_tag)

  # VLESS Reality（直连 IP 或域名）
  HOST_VLESS=$(ext_ip)
  echo "vless://${UUID_VLESS}@${HOST_VLESS}:${PORT_VLESS_REALITY}?security=reality&sni=${REALITY_SNI}&fp=${FP}&pbk=${PBK}&type=tcp&encryption=none#${TAG_VLESS}"
  echo "----------------------------"

  # HY2
  if openssl x509 -in "$HY2_CERT" -noout >/dev/null 2>&1; then
    # 官方证书，正常输出
    echo "hy2://${HY2_PASSWORD}@${HOST_VLESS}:${PORT_HY2}?mport=30000-30600#${TAG_HY2}"
  else
    # 自签证书（兜底）
    echo "hy2://${HY2_PASSWORD}@${HOST_VLESS}:${PORT_HY2}?mport=30000-30600&insecure=1#${TAG_HY2}"
  fi
  echo "----------------------------"

  # VMess over (Fixed or Ephemeral) Cloudflare Tunnel
  MODE="$(cat "$CLOUDFLARED_MODE_FILE" 2>/dev/null || echo fixed)"
  if [ "$MODE" = "ephemeral" ]; then
    EP_URL=$(awk '/trycloudflare.com/{print $NF}' "$CACHE_DIR/ephemeral.log" | tail -n1 | sed 's#https://##' || true)
    VM_HOST="$EP_URL"
  else
    VM_HOST="$CF_TUNNEL_HOST"
  fi
  VM_JSON=$(cat <<EOT
{"v":"2","ps":"${TAG_VMESS}","add":"${VM_HOST}","port":"443","id":"${UUID_VMESS}","aid":"0","scy":"auto","net":"ws","type":"none","host":"${VM_HOST}","path":"${WS_PATH}","tls":"tls","sni":"${VM_HOST}"}
EOT
)
  VM_B64=$(printf '%s' "$VM_JSON" | base64 | tr -d '\n')
  echo "vmess://${VM_B64}"
}

print_metrics() {
  mode=$(cat "$CLOUDFLARED_MODE_FILE" 2>/dev/null || echo fixed)
  proto=$(grep -aE 'protocol=(quic|http2)' "$CF_LOG" | tail -n1 | sed -E 's/.*protocol=([a-z0-9]+).*/\1/' || echo unknown)
  last_reason=$(cat "$CACHE_DIR/switch_reason" 2>/dev/null || echo none)
  last_switch_ts=$(cat "$CACHE_DIR/last_switch.ts" 2>/dev/null || echo 0)
  if [ -f "$CACHE_DIR/ephemeral.log" ]; then
    ep_host=$(awk '/trycloudflare.com/{print $NF}' "$CACHE_DIR/ephemeral.log" | tail -n1 | sed 's#https://##' || true)
  else
    ep_host=""
  fi
  echo "模式: $mode"
  echo "最近协议: $proto"
  [ -n "$ep_host" ] && echo "临时域名: $ep_host" || true
  [ "$last_switch_ts" -gt 0 ] && echo "最近切换: $(date -r "$last_switch_ts" '+%F %T')" || true
  echo "切换原因: $last_reason"
}

status() {
  echo "sing-box: $(pgrep -f "$SB_BIN run" >/dev/null && echo running || echo stopped)"
  echo "cloudflared: $(pgrep -f "$CF_BIN" >/dev/null 2>&1 && echo running || echo stopped)" 2>/dev/null || true
  echo "隧道模式: $(cat "$CLOUDFLARED_MODE_FILE" 2>/dev/null || echo fixed)"
}

switch_mode() {
  CUR=$(cat "$CLOUDFLARED_MODE_FILE" 2>/dev/null || echo fixed)
  stop_tunnel || true
  if [ "$CUR" = "fixed" ]; then
    start_tunnel_ephemeral
  else
    start_tunnel_fixed
  fi
}

clean_uninstall() {
  stop_tunnel || true
  stop_singbox || true
  # 保留：二进制、证书、secret.env
  find "$BASE_DIR" -type f ! -name 'secret.env' ! -name 'hy2.crt' ! -name 'hy2.key' -delete 2>/dev/null || true
  find "$BASE_DIR" -type f -name 'sing-box.json' -delete 2>/dev/null || true
  rm -f "$CACHE_DIR"/*.pid "$CACHE_DIR"/*.log "$CF_LOG" 2>/dev/null || true
  echo "已清理（保留：二进制/证书/secret.env）"
}

purge_uninstall() {
  clean_uninstall || true
  rm -f "$SB_BIN" "$CF_BIN" 2>/dev/null || true
  echo "已彻底卸载（删除二进制）"
}

install_all() {
  mkdirs; save_secret; load_secret; install_bins >/dev/null 2>&1 || true
  rotate_if_oversize "$INSTALL_LOG"
  : > "$INSTALL_LOG"
  {
    prepare_id_and_ws; gen_reality_materials
    # 证书：优先官方（DNS-01），失败则自签兜底
    if issue_cert_hy2; then echo "HY2 证书：官方签发完成"; else echo "HY2 证书：使用自签兜底"; self_signed_cert_hy2; fi
    write_singbox_config
    stop_singbox || true; start_singbox
    # 隧道：若配置了固定隧道 Token 则优先固定，否则使用临时隧道
    if [ -n "${CF_Tunnel_Token:-}" ]; then
      stop_tunnel || true; start_tunnel_fixed || true
    else
      stop_tunnel || true; start_tunnel_ephemeral || true
    fi
    start_watch_bg || true
  } >> "$INSTALL_LOG" 2>&1
  # 标准输出打印三种协议节点
  print_nodes
}

case "${1:-}" in
  install) install_all ;;
  start) stop_singbox 2>/dev/null || true; start_singbox; stop_tunnel 2>/dev/null || true; start_tunnel_fixed || true; start_watch_bg || true ;;
  stop) stop_tunnel || true; stop_singbox || true ;;
  restart) stop_tunnel || true; stop_singbox || true; start_singbox; start_tunnel_fixed || true; start_watch_bg || true ;;
  start-ephemeral) stop_tunnel || true; start_tunnel_ephemeral ;;
  switch) switch_mode ;;
  status) status ;;
  watch) watch_health ;;
  print-nodes) print_nodes ;;
  print-metrics) print_metrics ;;
  uninstall)
    if [ "${2:-}" = "--purge" ]; then
      purge_uninstall
    else
      clean_uninstall
    fi
    ;;
  *) echo "用法: $0 {install|start|stop|restart|start-ephemeral|switch|status|watch|print-nodes|print-metrics|uninstall [--purge]}" ;;
 esac