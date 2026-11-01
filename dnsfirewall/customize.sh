#!/system/bin/sh
# =====================================================
# customize.sh —— 模块安装/更新时由 Magisk 执行（root）
# 注意: 本脚本是被 update-binary **source** 的，不是单独执行。
#       所以结束时不要写 exit（安装器还要做收尾清理），要终止安装用 abort。
# =====================================================

SKIPUNZIP=0
BOOTMODE=${BOOTMODE:-false}
MODPATH="${MODPATH:-$(cd "$(dirname "$0")" && pwd)}"
FILES="$MODPATH/files"

ui_print "- DNS Firewall: 开始装配"

# ---------- 1. 二进制检查 ----------
DNSFW_BIN="$FILES/bin/dnsfw"
if [ ! -f "$DNSFW_BIN" ]; then
  abort "! 缺少 $DNSFW_BIN
  先在 files/src 下交叉编译再拷进来:
      cd files/src && make android && cp dnsfw_a64 ../bin/dnsfw"
fi

# 架构对不对: ELF 头 offset 18 是 e_machine 的低字节
#   40=ARM 183=AArch64 3=x86 62=x86-64
_arch_id=$(od -An -tu1 -j18 -N1 "$DNSFW_BIN" 2>/dev/null | tr -d ' \n')
_case="$ARCH"
[ -n "$_case" ] || _case=$(uname -m 2>/dev/null)
ui_print "- 设备架构: ${_case:-未知}, 二进制 e_machine: ${_arch_id:-未知}"
case "$_case" in
  arm64)        _want=183 ;;
  arm)          _want=40 ;;
  x64|x86_64)   _want=62 ;;
  x86)          _want=3 ;;
  *)            _want="" ;;
esac
if [ -n "$_want" ] && [ -n "$_arch_id" ] && [ "$_arch_id" != "$_want" ]; then
  ui_print "! 警告: dnsfw 的架构与设备不符，开机启动会失败（失败时不装规则，DNS 不受影响）"
fi

# ---------- 2. 权限与上下文（安装器默认给的是 0755 目录 / 0644 文件） ----------
if type set_perm >/dev/null 2>&1; then
  set_perm "$DNSFW_BIN" 0 0 0755
  [ -f "$FILES/bin/iptables" ]  && set_perm "$FILES/bin/iptables"  0 0 0755
  [ -f "$FILES/bin/ip6tables" ] && set_perm "$FILES/bin/ip6tables" 0 0 0755
else
  chmod 755 "$DNSFW_BIN" 2>/dev/null
  [ -f "$FILES/bin/iptables" ]  && chmod 755 "$FILES/bin/iptables"
  [ -f "$FILES/bin/ip6tables" ] && chmod 755 "$FILES/bin/ip6tables"
fi
chmod 755 "$FILES/lib/common.sh" "$FILES/scripts/start.sh" "$FILES/scripts/stop.sh" 2>/dev/null
chmod 755 "$MODPATH/service.sh" "$MODPATH/uninstall.sh" 2>/dev/null

# ---------- 3. 配置: 模块目录 files/conf（dnsfw 用 inotify 实时监听） ----------
# 升级时新包的默认 conf 已经解压进来了；用旧模块目录里的同名文件覆盖它，
# 保住用户改过的配置。首次升级（老版本配置在 /data/adb/dnsfirewall/conf）走迁移分支。
# 之后一直以模块目录为准，卸载时 uninstall.sh 会把它备份回持久目录。
PERSIST=${DNSFW_PERSIST:-/data/adb/dnsfirewall}
mkdir -p "$PERSIST/run" "$PERSIST/logs"
_oldconf=/data/adb/modules/dnsfirewall/files/conf
[ "$_oldconf" = "$FILES/conf" ] && _oldconf=""      # recovery 下 MODPATH 就是模块目录
for _f in blocklist.txt whitelist.txt upstream.txt; do
  if [ -n "$_oldconf" ] && [ -f "$_oldconf/$_f" ]; then
    cp -f "$_oldconf/$_f" "$FILES/conf/$_f" 2>/dev/null && ui_print "- 保留已有配置: $_f"
  elif [ -f "$PERSIST/conf/$_f" ]; then
    cp -f "$PERSIST/conf/$_f" "$FILES/conf/$_f" 2>/dev/null && ui_print "- 迁移旧配置: $_f"
  else
    ui_print "- 使用包内默认配置: $_f"
  fi
done
[ -f "$PERSIST/state" ] || echo 1 >"$PERSIST/state"

# ---------- 4. 升级时让新二进制立刻接管，不必等重启 ----------
# 旧进程是"模块目录里那个已被替换掉的文件"，pid 文件在持久目录下还找得到；
# stop.sh 用 /proc/<pid>/exe 判活，能认出它并停掉
# 只在 Magisk app 里做（BOOTMODE=true）；recovery 环境里网络栈与 iptables
# 后端不一定可用，装完重启自然会由 service.sh 拉起
if [ "$BOOTMODE" = "true" ]; then
  sh "$FILES/scripts/stop.sh" >/dev/null 2>&1
  if sh "$FILES/scripts/start.sh" >/dev/null 2>&1; then
    ui_print "- 服务已在新版本下启动"
  else
    ui_print "- 本次未能启动服务（未装规则，DNS 直连）；重启后由 service.sh 再试"
  fi
fi

ui_print "- DNS Firewall: 装配完成"
