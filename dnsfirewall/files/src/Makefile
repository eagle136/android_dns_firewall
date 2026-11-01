# dnsfw 构建
#
#   make            本机编译（宿主机调试用；Windows 上没有 sys/select.h，编不过，用 NDK）
#   make android    NDK 交叉编译 aarch64 + armv7
#   make install    编 aarch64 并装到模块的 files/bin/dnsfw（0755）
#   make clean
#
# NDK 定位优先级（都能用）:
#   make NDK=/opt/android-ndk-r26d android   显式指定
#   export ANDROID_NDK_HOME=...              Android Studio / sdkmanager 装的 NDK 默认用这个
#   把 NDK 目录放进 PATH                     例如 C:\android-ndk\android-ndk-r27c
#
# 模块里只放一个 files/bin/dnsfw（手机都是 aarch64），装机时 customize.sh 会核对架构
# 改过 CC / CFLAGS / CONFDIR 之后先 make clean，否则目标比源文件新、不会重编

CC      ?= cc
API     ?= 21
CONFDIR ?= /data/adb/modules/dnsfirewall/files/conf
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11 -pthread -s
# gnu11 而不是 c11: c11 下 clock_gettime 成了隐式声明，实测编不过
CPPFLAGS += -DCONFDIR='"$(CONFDIR)"'

# ---- NDK 定位 ----
NDK_ENV := $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT),$(NDK_HOME))
NDK ?= $(if $(NDK_ENV),$(NDK_ENV),$(shell for d in $$(echo "$$PATH" | tr ':' '\n'); do [ -d "$$d/toolchains/llvm/prebuilt" ] && { echo "$$d"; break; }; done))

# 直接用 clang + --target，不走 aarch64-linux-android<API>-clang 包装脚本:
# Windows 上只有 .cmd 版本、*nix 上是无扩展名 shim，用 --target 两边都通
EXE       = $(if $(filter Windows_NT,$(OS)),.exe,)
# host 目录名（windows-x86_64 / linux-x86_64 / darwin-aarch64）用 shell 读:
# mingw 版 make 的 $(wildcard) 不认 MSYS 的 /c/... 路径，会读出空值
NDK_HOST ?= $(if $(NDK),$(shell ls -1 "$(NDK)/toolchains/llvm/prebuilt" 2>/dev/null | head -n1))
CLANG     = $(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST)/bin/clang$(EXE)
# 抹 .comment 只能用 llvm-objcopy: MSYS/minGW 自带的 objcopy 只认 x86 目标，
# 碰到 aarch64 直接报 "Unable to recognise the architecture"
OBJCOPY   = $(shell c="$(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST)/bin/llvm-objcopy$(EXE)"; [ -x "$$c" ] && echo "$$c" || echo objcopy)
T64       = aarch64-linux-android$(API)
T32       = armv7a-linux-androideabi$(API)
BIN       = ../bin/dnsfw

# recipe 一律写单行: mingw 版 make 的续行是 "\<CR>"，sh 收到转义 CR 后
# 多行 if/then 会报 unexpected EOF
tidy = @$(OBJCOPY) --remove-section=.comment --remove-section=.note.android.ident $(1) 2>/dev/null || echo "  objcopy 不可用，跳过收尾"

# MSYS(Git Bash / MSYS2) 会把 -DCONFDIR="/data/adb/..." 里的 /data/... 当成
# 本机绝对路径改写成 C:/Users/.../data/adb/...，宏体就废了。编译这行关掉路径转换；
# 其它参数都是相对路径，关掉没有副作用，Linux/macOS 上这个变量没人看。
MSYS = MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

dnsfw: dnsfw.c
	$(MSYS) $(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $<
	$(call tidy,$@)

install: android-a64
	@mkdir -p $(dir $(BIN))
	cp -f dnsfw_a64 $(BIN)
	chmod 755 $(BIN)
	@echo "已安装到 $(BIN)"

android: android-a64 android-arm

android-a64: dnsfw.c
	@test -x "$(CLANG)" || { echo "错误: 找不到 NDK 的 clang: $(CLANG)"; echo "      指定方式: make NDK=/path/to/ndk android，或 export ANDROID_NDK_HOME，或把 NDK 目录放进 PATH"; echo "      没有 NDK 也能在设备上用 Termux: pkg install clang && make install"; exit 1; }
	$(MSYS) $(CLANG) --target=$(T64) $(CFLAGS) $(CPPFLAGS) -o dnsfw_a64 $<
	$(call tidy,dnsfw_a64)
	@echo "产物 dnsfw_a64；装进模块: make install"

android-arm: dnsfw.c
	@test -x "$(CLANG)" || { echo "错误: 找不到 NDK 的 clang: $(CLANG)"; exit 1; }
	$(MSYS) $(CLANG) --target=$(T32) $(CFLAGS) $(CPPFLAGS) -o dnsfw_arm $<
	@echo "产物 dnsfw_arm（32 位设备用）"

clean:
	rm -f dnsfw dnsfw_a64 dnsfw_arm *.o

.PHONY: install android android-a64 android-arm clean
