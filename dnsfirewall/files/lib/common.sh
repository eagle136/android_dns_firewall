#!/system/bin/sh
# =====================================================
# files/lib/common.sh —— 路径、端口常量与共用函数
# 由 start.sh / stop.sh / service.sh 以 source 方式引入
# 约定: 调用方在 source 之前先设好 MODDIR（模块根目录）
# 全部语法保持 POSIX sh，兼容 Magisk 的 busybox ash standalone 模式
# =====================================================

if [ -z "$MODDIR" ]; then
  echo "common.sh: MODDIR 未设置" >&2
  return 1
fi

# 运行期数据（pid/log）放在模块目录之外: 模块升级/重装会替换 /data/adb/modules/<id>
# 配置放在模块目录 files/conf：dnsfw 用 inotify 监听该目录，改完立即生效；
# 升级/卸载时由 customize.sh / uninstall.sh 负责把它迁进来、备份出去
# DNSFW_PERSIST 只用于在没有 root、没有内核 netfilter 的机器上跑脚本层自测
PERSIST=${DNSFW_PERSIST:-/data/adb/dnsfirewall}
BASEDIR="$MODDIR/files"
BINDIR="$BASEDIR/bin"
DEFCONF="$BASEDIR/conf"
CONFDIR="$DEFCONF"
RUNDIR="$PERSIST/run"
LOGDIR="$PERSIST/logs"
LOGFILE="$LOGDIR/dnsfw.log"
# 解析记录放模块根目录（按约定，方便和模块文件一起直接翻）；升级/重装会把它清掉
QLOGFILE="$MODDIR/dnsfw_queries.log"
PIDFILE="$RUNDIR/dnsfw.pid"
WDOGFILE="$RUNDIR/watchdog.pid"
STATEFILE="$PERSIST/state"     # 1=开机启动(默认) 0=不启动
V6FBFILE="$PERSIST/v6fb"       # 存在=正在用 v6 回落（这条机器没有 ip6table_nat）

DNSFW_BIN="$BINDIR/dnsfw"

# 以下三组常量必须与 src/dnsfw.c 保持一致
DNS_PORT=1053                  # dnsfw.c: DNS_PORT
SPORT_LO=1054                  # dnsfw.c: UP_SPORT_BASE
SPORT_HI=1153                  # dnsfw.c: UP_SPORT_BASE + MAX_INFLIGHT - 1
IPT_CHAIN=DNSFW
# v6 回落链（filter 表）: 内核没有 ip6table_nat 的机器上用它把 v6 解析器打成不可用，
# 逼 netd 改用同一网络的 v4 解析器，dnsfw 才有查询可过滤
V6FB_CHAIN=DNSFW6

# dnsfw 自己发出的查询从 SPORT_LO..SPORT_HI 出网；nat/OUTPUT 里这条 RETURN
# 让它的包不被重定向回 1053，从而既避免回环、又不需要按上游 IP 放行
# （按上游 IP 放行等于给任何把 DNS 指向该 IP 的应用留了后门）

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

ensure_dirs() {
  mkdir -p "$RUNDIR" "$LOGDIR"
}

# 逐个候选找可执行文件: 绝对路径直接测，裸名字走 PATH
find_bin() {
  for _cand in "$@"; do
    case "$_cand" in
      */*) [ -x "$_cand" ] && { echo "$_cand"; return 0; } ;;
      *)   _p=$(command -v "$_cand" 2>/dev/null)
           [ -n "$_p" ] && { echo "$_p"; return 0; } ;;
    esac
  done
  return 1
}

IPT4=$(find_bin "$BINDIR/iptables" /system/bin/iptables /vendor/bin/iptables iptables)
IPT6=$(find_bin "$BINDIR/ip6tables" /system/bin/ip6tables /vendor/bin/ip6tables ip6tables)
DS=$(find_bin /system/bin/dumpsys /vendor/bin/dumpsys dumpsys)

ipt_bin() {              # ipt_bin <4|6>
  case "$1" in
    4) [ -n "$IPT4" ] && { echo "$IPT4"; return 0; } ;;
    *) [ -n "$IPT6" ] && { echo "$IPT6"; return 0; } ;;
  esac
  return 1
}

read_prop() {            # read_prop <name>
  _gp=$(find_bin /system/bin/getprop /vendor/bin/getprop /system/xbin/getprop getprop) || return 1
  $_gp "$1" 2>/dev/null
}

# 只看 /proc/<pid>/exe 指向的是不是 dnsfw。
# kill -0 会被 PID 复用骗过去（老 pid 恰好被别的进程占用时误判"还在跑"）；
# 僵尸进程的 exe 读不出来，正好判为未运行。
pid_alive() {            # pid_alive <pid> <exe 里必须出现的名字>
  _p="$1"
  _n="$2"
  case "$_p" in
    '' | *[!0-9]*) return 1 ;;
  esac
  [ -d "/proc/$_p" ] || return 1
  _exe=$(readlink "/proc/$_p/exe" 2>/dev/null)
  case "$_exe" in
    *"$_n"*) return 0 ;;
    *)       return 1 ;;
  esac
}

is_running() {
  [ -f "$PIDFILE" ] || return 1
  pid_alive "$(cat "$PIDFILE" 2>/dev/null)" dnsfw
}

rotate_log() {           # rotate_log <file> [max_bytes]
  _f="$1"
  _max=${2:-524288}
  [ -f "$_f" ] || return 0
  _sz=$(wc -c < "$_f" 2>/dev/null) || return 0
  [ "${_sz:-0}" -gt "$_max" ] || return 0
  tail -c $((_max / 2)) "$_f" > "$_f.rot" 2>/dev/null && mv "$_f.rot" "$_f"
}

conf_entries() {         # conf_entries <file> —— 去注释、去空白的有效条目
  _f="$1"
  [ -f "$_f" ] || return 0
  sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$_f" 2>/dev/null |
    grep -v '^$'
}

# ---- 规则装配 ----------------------------------------------------
# 只重定向 UDP 53: dnsfw 没有 TCP 监听器，把 TCP 53 也重定向会直接断掉
# 依赖 TCP DNS 的解析（大应答、某些 DNS64 场景）。TCP 不过滤属已知限制。

apply_rules() {          # apply_rules <4|6> ；返回 0=规则已生效
  _t="$1"
  _b=$(ipt_bin "$_t") || return 3
  "$_b" -t nat -N "$IPT_CHAIN" >/dev/null 2>&1
  "$_b" -t nat -F "$IPT_CHAIN" >/dev/null 2>&1
  "$_b" -t nat -A "$IPT_CHAIN" -p udp -m udp --sport "$SPORT_LO:$SPORT_HI" -j RETURN >/dev/null 2>&1 || return 1
  "$_b" -t nat -A "$IPT_CHAIN" -p udp -m udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT" >/dev/null 2>&1 || return 1
  "$_b" -t nat -C OUTPUT -p udp -m udp --dport 53 -j "$IPT_CHAIN" >/dev/null 2>&1 ||
    "$_b" -t nat -A OUTPUT -p udp -m udp --dport 53 -j "$IPT_CHAIN" >/dev/null 2>&1 || return 1
  rules_present "$_t"
}

# 以 -S 的反读为准（不看单条命令的退出码）：链里没有 REDIRECT 就是没生效
# 返回 0=在, 1=不在, 2=这一族根本没有 iptables 二进制
rules_present() {        # rules_present <4|6>
  _t="$1"
  _b=$(ipt_bin "$_t") || return 2
  "$_b" -t nat -S OUTPUT 2>/dev/null | grep -q -- "-j $IPT_CHAIN" || return 1
  "$_b" -t nat -S "$IPT_CHAIN" 2>/dev/null | grep -q -- "--to-ports $DNS_PORT" || return 1
  "$_b" -t nat -S "$IPT_CHAIN" 2>/dev/null | grep -q -- "--sport $SPORT_LO:$SPORT_HI" || return 1
  return 0
}

del_rules() {            # del_rules <4|6> —— 幂等，没装过也不报错
  _t="$1"
  _b=$(ipt_bin "$_t") || return 0
  _i=0
  while [ "$_i" -lt 20 ] &&
        "$_b" -t nat -C OUTPUT -p udp -m udp --dport 53 -j "$IPT_CHAIN" >/dev/null 2>&1; do
    "$_b" -t nat -D OUTPUT -p udp -m udp --dport 53 -j "$IPT_CHAIN" >/dev/null 2>&1 || break
    _i=$((_i + 1))
  done
  "$_b" -t nat -F "$IPT_CHAIN" >/dev/null 2>&1
  "$_b" -t nat -X "$IPT_CHAIN" >/dev/null 2>&1
  return 0
}

# ---- v6 回落 ----------------------------------------------------
# 内核没编进 ip6table_nat 的机器上（本机 4.14 只有 raw/mangle/filter），v6 查询没法重定向。
# 与其让 dnsfw"进程在、规则在、一条查询也收不到"，不如把该网络那台 v6 解析器打成不可用，
# 逼 netd 用同一个网络的 v4 解析器。
# 门控: 只有「同一个网络里既有 v6 解析器又有 v4 解析器」才装，且只针对那台 v6 解析器的地址。
# 切成 v6-only 的网络一条规则都不会命中——不拦截，但也绝不会把那个网络的 DNS 关掉。
# 规则装的地址写进 V6FBFILE；看门狗拿它和当前网络对账——开机后才接入网络、换了 Wi-Fi，
# 都能发现并重建（本机 2026-11-01 就是启动 15 分钟后才连上 Wi-Fi，回落错过就再没装上）。

sys_dns_blocks() {           # 每个网络的 DnsAddresses 内容，一行一个网络
  [ -n "$DS" ] || return 1
  $DS connectivity 2>/dev/null |
    grep -oE 'DnsAddresses:[[:space:]]*\[[^]]*\]' |
    sed -e 's/^DnsAddresses:[[:space:]]*\[//' -e 's/\]$//'
}

v6fb_present() {             # 0=回落规则在, 1=不在, 2=没有 ip6tables
  _b=$(ipt_bin 6) || return 2
  "$_b" -t filter -S OUTPUT 2>/dev/null | grep -q -- "-j $V6FB_CHAIN" || return 1
  "$_b" -t filter -S "$V6FB_CHAIN" 2>/dev/null | grep -q -- "--dport 53" || return 1
  return 0
}

# 当前网络里「同时带 v4 解析器和 v6 解析器」的那台 v6 解析器地址，
# 去重排序后空格分隔输出；没有这样的网络返回 1
v6fb_targets() {
  ipt_bin 6 >/dev/null 2>&1 || return 1
  _blocks=$(sys_dns_blocks) || return 1
  [ -n "$_blocks" ] || return 1
  _out=''
  _oifs=$IFS
  IFS='
'
  for _blk in $_blocks; do
    [ -n "$_blk" ] || continue
    _v4=0
    _v6=''
    for _raw in $(echo "$_blk" | tr -d ' ' | tr ',' '\n'); do
      _a=${_raw#/}          # dumpsys 里每个地址都写成 /1.2.3.4 或 /fe80::1%wlan0
      _a=${_a%\%*}          # 去掉 zone id，ip6tables 的 -d 不认 %wlan0
      [ -n "$_a" ] || continue
      case "$_a" in
        *:*) _v6="$_v6 $_a" ;;
        *.*) _v4=$((_v4 + 1)) ;;
      esac
    done
    [ "$_v4" -gt 0 ] && [ -n "$_v6" ] || continue
    _out="$_out $_v6"
  done
  IFS=$_oifs
  [ -n "$_out" ] || return 1
  _out=$(printf '%s\n' $_out | sort -u | tr '\n' ' ')
  echo "${_out% }"
}

v6fb_apply() {               # 0=已装上并反读确认; 1=不该装或装不上
  _b=$(ipt_bin 6) || return 1
  _targets=$(v6fb_targets) || { rm -f "$V6FBFILE"; return 1; }

  "$_b" -t filter -N "$V6FB_CHAIN" >/dev/null 2>&1
  "$_b" -t filter -F "$V6FB_CHAIN" >/dev/null 2>&1 || return 1
  for _s in $_targets; do
    "$_b" -t filter -A "$V6FB_CHAIN" -p udp -m udp --dport 53 -d "$_s" \
      -j REJECT --reject-with icmp6-adm-prohibited >/dev/null 2>&1 ||
      "$_b" -t filter -A "$V6FB_CHAIN" -p udp -m udp --dport 53 -d "$_s" -j DROP >/dev/null 2>&1 ||
      { "$_b" -t filter -F "$V6FB_CHAIN" >/dev/null 2>&1
        "$_b" -t filter -X "$V6FB_CHAIN" >/dev/null 2>&1
        return 1; }
  done
  "$_b" -t filter -C OUTPUT -p udp -m udp --dport 53 -j "$V6FB_CHAIN" >/dev/null 2>&1 ||
    "$_b" -t filter -A OUTPUT -p udp -m udp --dport 53 -j "$V6FB_CHAIN" >/dev/null 2>&1 ||
    { v6fb_del; return 1; }
  v6fb_present || { v6fb_del; return 1; }
  printf '%s\n' $_targets >"$V6FBFILE"
  return 0
}

v6fb_del() {                 # 幂等，没装过也不报错
  _b=$(ipt_bin 6) || { rm -f "$V6FBFILE"; return 0; }
  _i=0
  while [ "$_i" -lt 20 ] &&
        "$_b" -t filter -C OUTPUT -p udp -m udp --dport 53 -j "$V6FB_CHAIN" >/dev/null 2>&1; do
    "$_b" -t filter -D OUTPUT -p udp -m udp --dport 53 -j "$V6FB_CHAIN" >/dev/null 2>&1 || break
    _i=$((_i + 1))
  done
  "$_b" -t filter -F "$V6FB_CHAIN" >/dev/null 2>&1
  "$_b" -t filter -X "$V6FB_CHAIN" >/dev/null 2>&1
  rm -f "$V6FBFILE"
  return 0
}

v6fb_ok() {                  # 看门狗用: 不在回落模式就算健康
  [ -f "$V6FBFILE" ] || return 0
  v6fb_present
}

# 看门狗每 60 s 调一次: 拿当前网络的解析器集合和 v6fb 快照对账。
# 开机时 start.sh 跑在网络接入之前（本机 2026-11-01：06:05 启动，06:20 才出第一条查询），
# 那一次装不上；等网络起来后靠这里补装。换 Wi-Fi 导致 v6 解析器地址变化时也在这里重建。
v6fb_sync() {
  _want=$(v6fb_targets) || {
    if [ -f "$V6FBFILE" ]; then
      v6fb_del
      log "看门狗: 当前网络没有 v4+v6 解析器并存，已撤 v6 回落"
    fi
    return 0
  }
  _want=$(echo $_want)
  _have=''
  [ -f "$V6FBFILE" ] && _have=$(echo $(cat "$V6FBFILE" 2>/dev/null))
  if [ "$_want" = "$_have" ] && v6fb_present; then
    return 0
  fi
  log "看门狗: 解析器集合与 v6 回落规则不一致（当前: $_want），重建"
  if v6fb_apply; then
    log "看门狗: v6 回落已同步"
  else
    v6fb_del
    log "看门狗: v6 回落重建失败，v6 查询暂不过滤"
  fi
  return 0
}

stop_daemon() {
  if is_running; then
    _pid=$(cat "$PIDFILE")
    kill "$_pid" 2>/dev/null
    _i=0
    while [ "$_i" -lt 3 ] && is_running; do
      sleep 1
      _i=$((_i + 1))
    done
    is_running && kill -9 "$_pid" 2>/dev/null
    log "dnsfw 已停止 (pid $_pid)"
  fi
  rm -f "$PIDFILE"
  sweep_orphans
}

# PID 文件只记最后一次启动的那个 pid: 有人手工跑过 serve、或上一代模块残留的
# 实例都不在里面。dnsfw 不再设 SO_REUSEADDR，端口同一时刻只能有一个持有者，
# 那种野实例不清掉，本模块永远起不来（表现是"启动失败"但没人知道被谁占了）。
# 认 exe 链接的绝对路径，只动本模块自己的二进制。
sweep_orphans() {
  _want=$(readlink -f "$DNSFW_BIN" 2>/dev/null)
  [ -n "$_want" ] || _want="$DNSFW_BIN"
  for _d in /proc/[0-9]*; do
    _e=$(readlink "$_d/exe" 2>/dev/null) || continue
    case "$_e" in
      "$DNSFW_BIN" | "$_want") : ;;
      *) continue ;;
    esac
    _pid=${_d#/proc/}
    [ "$_pid" = "$$" ] && continue
    kill -9 "$_pid" 2>/dev/null && log "清理 PID 文件之外的 dnsfw 实例: pid $_pid"
  done
  return 0
}

# 看门狗是个后台子 shell，父进程退出后只剩它；不先停它，卸载/停服后它会把
# 服务再拉起来。pid 复用风险用 cmdline 里必须是本模块的 service.sh 来挡。
stop_watchdog() {
  [ -f "$WDOGFILE" ] || return 0
  _w=$(cat "$WDOGFILE" 2>/dev/null)
  rm -f "$WDOGFILE"
  case "$_w" in
    '' | *[!0-9]*) return 0 ;;
  esac
  [ -r "/proc/$_w/cmdline" ] || return 0
  grep -q "service.sh" "/proc/$_w/cmdline" 2>/dev/null || return 0
  kill "$_w" 2>/dev/null
  log "看门狗已停止 (pid $_w)"
}

start_daemon() {
  ensure_dirs
  export DNSFW_CONF="$CONFDIR"
  export DNSFW_QLOG="${DNSFW_QLOG:-$QLOGFILE}"
  is_running || sweep_orphans
  nohup "$DNSFW_BIN" serve </dev/null >>"$LOGFILE" 2>&1 &
  echo $! >"$PIDFILE"
  sleep 1
  is_running
}
