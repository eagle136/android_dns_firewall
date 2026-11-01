#!/system/bin/sh
# =====================================================
# files/scripts/stop.sh —— 停止 DNS 防火墙
# 顺序: 先删 iptables 规则（让 53 端口流量立刻恢复原路），再杀进程。
#       反过来会有一段"规则还在、后端已死"的窗口，期间 DNS 全断。
# 约定: 幂等，未运行也返回 0
# =====================================================

MODDIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$MODDIR/files/lib/common.sh"

ensure_dirs
rotate_log "$LOGFILE"

# ---------- 0. 先停看门狗（否则它 10 s 内会把服务再拉起来） ----------
stop_watchdog

# ---------- 1. 撤销重定向规则 ----------
for _t in 4 6; do
  del_rules "$_t"
  rules_present "$_t"
  _rc=$?
  case "$_rc" in
    0) log "警告: IPv$_t 规则仍然存在，请手动检查 nat/OUTPUT 与 nat/$IPT_CHAIN" ;;
    2) log "IPv$_t 侧没有可用的 iptables 二进制，无规则可删" ;;
    *) log "IPv$_t 规则已撤销（-S 反读确认）" ;;
  esac
done

# ---------- 1b. 撤销 v6 回落规则（filter 表，和 nat 那两条不是一回事） ----------
v6fb_del
if v6fb_present; then
  log "警告: IPv6 回落规则仍然存在，请手动检查 filter/OUTPUT 与 filter/$V6FB_CHAIN"
else
  log "IPv6 回落规则已撤销（-S 反读确认）"
fi

# ---------- 2. 停止服务 ----------
stop_daemon

exit 0
