#!/system/bin/sh
# =====================================================
# files/scripts/start.sh —— 启动 DNS 防火墙
# 调用方: service.sh（开机）或控制脚本（手动）
# 约定: 成功返回 0；已运行时同样返回 0（可重复执行）
#
# 顺序要求: 先确认 dnsfw 真的在 1053 上跑起来，再装重定向规则。
#           反过来会在服务还没就绪的窗口里把 53 端口流量全接到空端口上，
#           结果是整机断 DNS。
# =====================================================

MODDIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$MODDIR/files/lib/common.sh"

ensure_dirs
rotate_log "$LOGFILE"

# ---------- 1. 前置检查（缺任何一样都不装规则，保持 DNS 原样可用） ----------
[ -x "$DNSFW_BIN" ] || { log "缺少可执行 $DNSFW_BIN（files/src 下 make 后拷入 files/bin/）"; exit 1; }
[ -n "$IPT4" ] || { log "找不到 iptables（模块内 files/bin/iptables 或系统 /system/bin/iptables）"; exit 1; }

_nup=$(conf_entries "$CONFDIR/upstream.txt" | wc -l)
if [ "${_nup:-0}" -lt 1 ]; then
  log "$CONFDIR/upstream.txt 没有有效上游，拒绝启动（否则放行的域名全解析不了）"
  exit 1
fi

# ---------- 2. 启动本地服务 ----------
if is_running; then
  log "dnsfw 已在运行 (pid $(cat "$PIDFILE"))"
elif start_daemon; then
  log "dnsfw 已启动 (pid $(cat "$PIDFILE"))"
else
  log "dnsfw 启动失败，未改动任何 iptables 规则"
  exit 1
fi

# ---------- 3. 装重定向规则 ----------
rc=0
if apply_rules 4; then
  log "IPv4 规则生效: nat/OUTPUT udp dport 53 -> nat/$IPT_CHAIN -> 127.0.0.1:$DNS_PORT"
else
  rc=1
  log "IPv4 规则安装失败（反读 nat 表没看到 REDIRECT/$IPT_CHAIN）"
fi

if apply_rules 6; then
  log "IPv6 规则生效"
elif [ -z "$IPT6" ]; then
  log "警告: 找不到 ip6tables，IPv6 侧不过滤（本机 53 的 v6 查询会直发出去）"
else
  # 内核没编 ip6table_nat 时 ip6tables 直接报 "Table does not exist"。
  # v6 查询重定向不了，就退一步把它那台 v6 解析器打成不可用，让 netd 用同网络的 v4 解析器。
  if v6fb_apply; then
    log "IPv6 nat 表缺失，已装 v6 回落规则（该网络的 v6 解析器不可用，查询改走 IPv4 才会被过滤）"
  else
    v6fb_del
    log "警告: IPv6 规则安装失败，v6 回落也不适用（没有同时带 v4+v6 解析器的网络），v6 查询不过滤"
  fi
fi

# ---------- 4. 失败回滚: 只有 IPv4 没装上才撤，不能让 DNS 断在那儿 ----------
if [ "$rc" -ne 0 ]; then
  log "IPv4 规则未生效，撤销已装的规则以保持 DNS 可用"
  del_rules 4
  del_rules 6
  v6fb_del
  exit 1
fi

exit 0
