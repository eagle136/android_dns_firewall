#!/system/bin/sh
# =====================================================
# service.sh —— 每次开机由 Magisk/KernelSU 执行（root，late_start 阶段）
# 职责: 等开机完成 -> 按开关决定启停 -> 起主服务并装规则 -> 挂看门狗
# =====================================================

MODDIR="${0%/*}"
. "$MODDIR/files/lib/common.sh"

ensure_dirs
rotate_log "$LOGFILE"
stop_watchdog            # 手动重复执行本脚本时不要叠两个看门狗

# ---------- 0. late_start 是非阻塞阶段，会和开机余下流程并行 ----------
# 网络栈/netd 还没起来就装规则、起服务，容易出现"服务绑上了但规则没装上"
_i=0
while [ "$_i" -lt 120 ]; do
  [ "$(read_prop sys.boot_completed)" = "1" ] && break
  sleep 1
  _i=$((_i + 1))
done
[ "$_i" -lt 120 ] || log "等 sys.boot_completed 超时(120s)，仍继续尝试"

# ---------- 1. 启停开关（持久目录，模块升级不丢） ----------
# 1=开机启动(默认)  其它值=不启动。改这个文件不会立刻生效，
# 想马上停请执行 files/scripts/stop.sh
[ -f "$STATEFILE" ] || echo 1 >"$STATEFILE"
if [ "$(cat "$STATEFILE" 2>/dev/null)" != "1" ]; then
  log "state=$(cat "$STATEFILE")，不启动；顺手确保规则是干净的"
  sh "$MODDIR/files/scripts/stop.sh" >>"$LOGFILE" 2>&1
  exit 0
fi

# ---------- 2. 启动 ----------
if sh "$MODDIR/files/scripts/start.sh" >>"$LOGFILE" 2>&1; then
  log "service.sh: 启动成功"
else
  log "service.sh: 启动失败（详见上面几行；失败时规则已撤销，DNS 保持直连）"
  exit 1
fi

# ---------- 3. 看门狗 ----------
# 覆盖两种"静默失效": 进程没了（不拉起就一直断 DNS），
# 以及进程还在但 nat 规则被别的模块/清理动作冲掉（不补就等于不过滤了）。
# 两种情况走同一条修复路径，失败次数一起计，避免修不好时每 10 秒空转到天荒地老。
watchdog() {
  _fails=0
  _tick=0
  while :; do
    sleep 10
    [ -d "$MODDIR" ] || return 0        # 模块被删/被卸载，退出不再折腾
    _tick=$((_tick + 1))
    if is_running && rules_present 4 && v6fb_ok; then
      _fails=0
      # 网络是开机之后才接入的（本机常见），或者中途换了 Wi-Fi：
      # 每 60 s 对一次当前解析器集合，补装/重建/撤掉回落规则
      [ $((_tick % 6)) -eq 0 ] && v6fb_sync
      rotate_log "$LOGFILE"
      continue
    fi
    log "看门狗: 服务或规则缺失（含 v6 回落规则），重新装配"
    if sh "$MODDIR/files/scripts/start.sh" >>"$LOGFILE" 2>&1; then
      _fails=0
    else
      _fails=$((_fails + 1))
      if [ "$_fails" -ge 3 ]; then
        log "看门狗: 连续 3 次修复失败，撤销规则让 DNS 恢复直连，看门狗退出"
        sh "$MODDIR/files/scripts/stop.sh" >>"$LOGFILE" 2>&1
        return 0
      fi
    fi
    rotate_log "$LOGFILE"
  done
}

watchdog </dev/null >>"$LOGFILE" 2>&1 &
echo $! >"$WDOGFILE"
exit 0
