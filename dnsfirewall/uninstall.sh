#!/system/bin/sh
# =====================================================
# uninstall.sh —— 模块卸载前由 Magisk 执行（root）
# 职责: 先停看门狗（否则它会把服务再拉起来）、撤规则、停服务
#       再把模块目录里的配置备份到 /data/adb/dnsfirewall/conf（模块目录会被整体删掉）
# =====================================================

MODDIR="${0%/*}"
. "$MODDIR/files/lib/common.sh"

# ---------- 1. 先断掉看门狗 ----------
stop_watchdog

# ---------- 2. 撤规则（先规则后进程，避免中间断 DNS） ----------
for _t in 4 6; do
  del_rules "$_t"
  rules_present "$_t"
  [ $? -eq 0 ] && echo "警告: IPv$_t 规则没删干净，请手工检查 nat/OUTPUT 与 nat/$IPT_CHAIN"
done

v6fb_del
v6fb_present && echo "警告: IPv6 回落规则没删干净，请手工检查 filter/OUTPUT 与 filter/$V6FB_CHAIN"

# ---------- 3. 停服务 ----------
stop_daemon

# ---------- 4. 备份配置，删运行期产物 ----------
mkdir -p "$PERSIST/conf"
for _f in blocklist.txt whitelist.txt upstream.txt; do
  [ -f "$CONFDIR/$_f" ] && cp -f "$CONFDIR/$_f" "$PERSIST/conf/$_f"
done
rm -rf "$RUNDIR" "$LOGDIR"
echo "已备份名单与上游配置到: $PERSIST/conf（要彻底清除请手动 rm -rf $PERSIST）"

exit 0
