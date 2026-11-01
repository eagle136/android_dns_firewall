# =====================================================
# files/bin/ —— 二进制存放处
#
# 需要放入（文件名固定，lib/common.sh 按这些名字找）:
#   dnsfw      DNS 防火墙核心。没有它 customize.sh 直接 abort，build.sh 拒绝打包
#   iptables   可选。放了就优先用；没放则按 /system/bin → /vendor/bin → PATH 顺序找
#   ip6tables  可选。找不到就只过滤 IPv4，并在日志里说明
#
# 构建 dnsfw（源码在 ../src/）:
#   PC 交叉编译:  cd ../src && make NDK=/path/to/ndk android && make install
#   设备上编译:   Termux 里 pkg install clang && cd .../files/src && make install
#   `make install` 会把产物以 0755 写到 ../bin/dnsfw（注意是 ../bin，不是 ../../bin）
#
# 产物架构: 手机要 aarch64（armv7 老机用 32 位 ARM）。宿主机 make 出来的 x86-64
# 只能用来跑测试；装机时 customize.sh 会读 ELF e_machine 告警。
#
# 权限: build.sh 会把 .sh 与 bin 下的可执行文件按 0755 写进 zip 并反读校验；
# Magisk 装机统一给 0644，所以 customize.sh 还会再 set_perm 一次，两处都覆盖到了
# =====================================================
