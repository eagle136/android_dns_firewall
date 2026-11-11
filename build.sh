#!/usr/bin/env sh
# =====================================================
# build.sh —— 将 dnsfirewall/ 打包为 Magisk 可安装的 zip
# 用法: ./build.sh
# 输出: output/dnsfirewall-v<版本>-<日期-时间>.zip（历史包不会被删）
#
# 打包前做四件事: 语法自检、确认二进制在位、核对 ELF 架构、按目标权限写入；
# 打包后从 zip 自己存的 external_attr 反读权限，不合规就判定失败。
# =====================================================
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$DIR/dnsfirewall"
OUT="$DIR/output"
BIN="$SRC/files/bin/dnsfw"

PY=""
for _c in python3 python; do
  command -v "$_c" >/dev/null 2>&1 && { PY="$_c"; break; }
done

[ -f "$SRC/module.prop" ] || { echo "错误: 找不到 $SRC/module.prop"; exit 1; }
VERSION="$(sed -n 's/^version=//p' "$SRC/module.prop" | head -n1)"
[ -n "$VERSION" ] || VERSION="0.0"

# ---- 1) 模块里每个 shell 脚本先过语法检查 ----
_ifs=$IFS; IFS='
'
for f in $(find "$SRC" -name '*.sh' -not -path '*/output/*'); do
  sh -n "$f" || { echo "错误: 语法检查失败: $f"; exit 1; }
  echo "  语法 OK: ${f#"$SRC"/}"
done
IFS=$_ifs

# ---- 2) 二进制必须已经在位（缺了就打出一个装不上的包没有意义）----
[ -f "$BIN" ] || {
  echo "错误: 缺少 $BIN"
  echo "      先编译: cd $SRC/files/src && make android && make install"
  echo "      （或设备上 Termux: pkg install clang && make install）"
  exit 1
}

# ---- 3) 核对 ELF 架构: e_machine 在偏移 18 ----
magic="$(od -An -tx1 -N4 "$BIN" | tr -d ' \n')"
if [ "$magic" = "7f454c46" ]; then
  em="$(od -An -tu1 -j18 -N1 "$BIN" | tr -d ' ')"
  case "$em" in
    183) echo "  dnsfw: ELF aarch64（e_machine=183）" ;;
    40)  echo "  dnsfw: ELF arm 32 位（e_machine=40）" ;;
    62)  echo "  警告: dnsfw 是 x86-64 宿主机产物（e_machine=62），手机上会被 customize.sh 判为架构不符" ;;
    3)   echo "  警告: dnsfw 是 x86 宿主机产物（e_machine=3），手机上大概率用不了" ;;
    *)   echo "  警告: 未知 ELF 架构 e_machine=$em" ;;
  esac
else
  echo "  警告: $BIN 不是 ELF（magic=$magic），确认这是编译产物而不是占位文件"
fi

# 宿主机上的执行位（zip 会带上），python 不在时也靠它保底
find "$SRC" -name '*.sh' -exec chmod 755 {} \;
find "$SRC/files/bin" -type f -exec sh -c 'case "$1" in *.*) : ;; *) chmod 755 "$1" ;; esac' _ {} \;

# ---- 3b) 二进制新鲜度: 比源码旧就是上一版源码的产物 ----
# 打出去照样能装、行为却是旧的（本轮的「解析记录改到模块根目录」就被静默丢掉过）。
# mtime 是最一般的时间线信号，但整树拷贝/检出会把 mtime 拉平，所以再加一条内容核对:
# 二进制里必须能找到源码当前的默认解析记录路径（.rodata 里的字符串，strip 也 strip 不掉）
if [ -n "$(find "$SRC/files/src/dnsfw.c" -newer "$BIN" 2>/dev/null)" ]; then
  echo "错误: $BIN 比 files/src/dnsfw.c 旧（源码改过没重编）"
  echo "      重编并拷入: cd $SRC/files/src && make && make install"
  echo "      （设备上 Termux: make install 同理）"
  exit 1
fi
# 三个默认记录路径都核一遍（解析 / 拦截 / 实时），任何一路换了名字都得重编
for _def in QLOG_PATH BLOG_PATH RLOG_PATH; do
  want="$(sed -n "s/^[[:space:]]*#[[:space:]]*define[[:space:]]*${_def}[[:space:]]*\"\([^\"]*\)\".*/\1/p" \
             "$SRC/files/src/dnsfw.c" | head -1)"
  [ -n "$want" ] || continue
  if ! grep -a -q -F -- "$want" "$BIN" 2>/dev/null; then
    echo "错误: $BIN 里没有源码当前的 $_def「$want」—— 是上一版源码编的"
    echo "      重编并拷入: cd $SRC/files/src && make && make install"
    exit 1
  fi
done
# 配置目录同理: 路径换了还装旧二进制，dnsfw 会去监听已经不用的目录
want_conf="$(sed -n 's/^CONFDIR[[:space:]]*?=[[:space:]]*//p' "$SRC/files/src/Makefile" | head -1)"
if [ -n "$want_conf" ] && ! grep -a -q -F -- "$want_conf" "$BIN" 2>/dev/null; then
  echo "错误: $BIN 里没有 Makefile 当前的配置目录「$want_conf」—— 是上一版路径编的"
  echo "      重编并拷入: cd $SRC/files/src && make && make install"
  exit 1
fi

# ---- 4) META-INF 只在 recovery 刷机时需要，缺了就提示一下 ----
if [ ! -f "$SRC/META-INF/com/google/android/update-binary" ]; then
  echo "  提示: 没有 META-INF/com/google/android/update-binary"
  echo "        Magisk App 安装不需要它；要用 TWRP 类 recovery 刷机才得补上"
fi

mkdir -p "$OUT"                                  # 不清空: 历史包按文件名区分留着
NAME="dnsfirewall-v${VERSION}-$(date +%Y%m%d-%H%M%S)"
ZIP="$OUT/$NAME.zip"

echo "--- 打包 $SRC -> $ZIP ---"
if [ -n "$PY" ]; then
  "$PY" - "$SRC" "$ZIP" <<'PYEOF'
import os, sys, time, zipfile

src, dst = sys.argv[1], sys.argv[2]
# files/src 只放源码与 Makefile；树里那些调试期的旧产物不进包
SRC_KEEP = ("files/src/dnsfw.c", "files/src/Makefile")
TOP_SKIP = ("output", ".git", "META")
# META/skip-mount 是历史遗留: Magisk 认的是模块根目录下的 skip_mount，
# 这个名字和位置都不对，装进包里也只是误导；本模块没有需要屏蔽的 magic mount 内容

def excluded(rel):
    if rel.split("/")[0] in TOP_SKIP:
        return True
    if rel.startswith("files/src/"):
        return rel not in SRC_KEEP
    # 设备上的服务日志/解析记录一旦落进模块目录就会被当模块内容打包
    # （dnsfw_queries.log 就写在模块根目录），必须挡在门外
    if rel.endswith(".log"):
        return True
    return rel.endswith((".o", ".zip", ".pyc"))

def mode_of(rel):
    if rel.endswith(".sh"):
        return 0o755
    base = rel.rsplit("/", 1)[-1]
    if rel.startswith("files/bin/") and "." not in base:
        return 0o755
    return 0o644

def stamp(path):
    t = time.localtime(os.stat(path).st_mtime)[:6]
    return t if t[0] >= 1980 else (1980, 1, 1, 0, 0, 0)

skipped = []
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk(src):
        dirs.sort(); files.sort()
        rel_root = os.path.relpath(root, src).replace(os.sep, "/")
        if rel_root == ".":
            rel_root = ""
        dirs[:] = [d for d in dirs
                   if not excluded((rel_root + "/" + d).lstrip("/"))]
        if rel_root:
            zi = zipfile.ZipInfo(rel_root + "/", date_time=stamp(root))
            zi.create_system = 3
            zi.external_attr = (0o40755) << 16
            zf.writestr(zi, b"")
        for fn in files:
            rel = (rel_root + "/" + fn).lstrip("/")
            full = os.path.join(root, fn)
            if excluded(rel):
                skipped.append(rel)
                continue
            m = mode_of(rel)
            zi = zipfile.ZipInfo(rel, date_time=stamp(full))
            zi.create_system = 3
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = m << 16
            with open(full, "rb") as fh:
                zf.writestr(zi, fh.read())

# ---- 反读: 以 zip 里存的 external_attr 为准，不看写入时以为是什么 ----
want = {}
for rel in zipfile.ZipFile(dst).namelist():
    want[rel] = (0o755 if (rel.endswith("/") or rel.endswith(".sh")
                           or (rel.startswith("files/bin/")
                               and "." not in rel.rsplit("/", 1)[-1])) else 0o644)
bad = []
for info in zipfile.ZipFile(dst).infolist():
    got = (info.external_attr >> 16) & 0o7777
    w = want[info.filename]
    if got != w:
        bad.append("%s 存的是 %04o 应为 %04o" % (info.filename, got, w))
for rel in sorted(want):
    if rel.endswith("/"):
        continue
    info = zipfile.ZipFile(dst).getinfo(rel)
    print("  %04o  %s" % (((info.external_attr >> 16) & 0o7777), rel))
print("  跳过未入包: " + (", ".join(sorted(skipped)) if skipped else "无"))
for need in ("module.prop", "customize.sh", "service.sh", "files/bin/dnsfw",
             "webroot/index.html"):
    if need not in want:
        bad.append("缺少必需条目: " + need)
for rel in sorted(want):
    if rel.endswith(".log"):
        bad.append("运行期日志混进了包: " + rel)
if bad:
    for b in bad:
        print("错误: " + b)
    sys.exit(1)
print("  权限反读校验通过（%d 个条目）" % len(want))
PYEOF
elif command -v zip >/dev/null 2>&1; then
  echo "  注意: 没有 python，改用 zip 打包 —— 权限直接取宿主机文件位，且本次不做反读校验"
  echo "        （Windows/Git Bash 上文件位不代表 unix 权限；最终以 customize.sh 的 set_perm 为准）"
  ( cd "$SRC" && zip -r -q -X "$ZIP" . -x 'output/*' -x 'META/*' -x '*.zip' -x '*.log' \
      -x 'files/src/*' \
      && zip -q -X "$ZIP" files/src/dnsfw.c files/src/Makefile )
else
  echo "错误: 需要 python3 或 zip（Termux: pkg install zip）"
  exit 1
fi

echo "--- 完成: $ZIP ---"
if command -v unzip >/dev/null 2>&1; then
  echo "  zip 内条目数: $(unzip -Z1 "$ZIP" | wc -l | tr -d ' ')"
fi
