# android_dns_fire（DNS Firewall）

本地安卓 DNS 网络防火墙，拦截有害网站，支持 WebUI 配置、数据导入导出。

- 把本机（`nat OUTPUT`）发往 **UDP 53** 的查询重定向到 `127.0.0.1:1053` 上的自研 C 程序
  `dnsfw`：命中黑名单的 A 查询直接回本地 Sink 地址 `127.0.0.1`（其它类型回 **NXDOMAIN**），
  未命中的查询原样转发给配置的上游并透传应答。
- 黑名单 / 白名单 / 自定义上游，保存即热加载；解析过哪些域名可在 WebUI 里查看。
- 配置可一键备份到 `/sdcard/Download/dnsfirewall-backup.tar`，也可以一键还原。
- 开机自启、规则/进程看门狗；内核没有 `ip6table_nat` 时自动走 IPv6 回落。

**不覆盖**：TCP 53、DoT(853)、DoH(443)。dnsfw 只有 UDP 监听器。

内核没有 `ip6table_nat` 的机器（不少 4.x perf 内核没有）上 IPv6 查询重定向不了，模块改走
「IPv6 回落」：把那台网络的 v6 解析器打成不可用，让查询改走同网络的 v4 解析器再被过滤，详见
[IPv6 回落](#ipv6-回落内核没有-ip6table_nat-时)。

## 安装

1. 从 [Releases](../../releases) 下载最新的 `dnsfirewall-v*.zip`。
2. Magisk / KernelSU 管理器 → 模块 → 从本地安装 → 选择 zip。
3. 重启设备（不重启时模块会暂存在 `modules_update`，服务与 WebUI 可能不按预期生效）。
4. KernelSU 用户可在模块页面打开 **WebUI** 管理名单、查看解析记录、备份/还原配置；
   Magisk 原生没有 WebUI。

## 反馈

- 有问题请提交 [Issues](../../issues)。
- 也欢迎 Fork 后直接提交 Pull Request。
- 讨论：797433615

## 构建与发布

- 本机：`make -C dnsfirewall/files/src install` 编出 aarch64 二进制，再 `./build.sh` 打包到 `output/`。
- GitHub Actions：推送 `v*` 标签（或在 Actions 里手动触发）会自动编译、打包并创建 Release，
  工作流见 [.github/workflows/release.yml](.github/workflows/release.yml)。
  标签会同步进 `module.prop`：`v1.2` → `version=1.2`，`versionCode=10200`（主 *10000 + 次 *100 + 修订）。

## 目录结构

```
dnsfirewall/                      # zip 根目录
├── module.prop                   # 只保留 Magisk 认的键
├── customize.sh                  # 安装/更新：权限、迁移配置、架构告警
├── service.sh                    # 开机入口 + 看门狗
├── uninstall.sh                  # 看门狗 → 规则 → 进程 → 备份 conf → 删 run/logs
├── webroot/index.html            # KernelSU WebUI：名单增删 + 浅/深色
└── files/
    ├── src/dnsfw.c  Makefile     # 源码与构建
    ├── bin/dnsfw                 # ★ 由 make install 产出的二进制（源码树里预置只有 README）
    ├── conf/*.txt                # 生效配置（dnsfw 用 inotify 实时监听这一类文件）
    ├── lib/common.sh             # 路径/端口常量与共用函数
    └── scripts/{start,stop}.sh
build.sh                          # 打包（语法自检 + 架构/新鲜度核对 + 权限写入 + 反读校验）
output/                           # 历史包，不删
```

`files/bin/dnsfw` 比 `files/src/dnsfw.c` 旧时 `build.sh` 直接报错退出；mtime 不可信时（整树拷贝
或检出把时间拉平）还有第二道核对——二进制里必须能找到源码当前的默认解析记录路径字符串。
打出去照样能装、行为却是上一版的（本轮就出现过：`output/` 里两个 v1.1 包的二进制仍带旧表头
和 `/tmp` 路径，已用 `zipfile` 逐包读出字节确认）。改完源码要 `make && make install` 再打包。

`files/src/` 下若有调试期的旧产物（`dnsfw_O0`、`dnsfw_id*` 等）不会进 zip；`*.log` 一律排除
（解析记录就写在模块根目录，设备上的这份一旦跟着树打包就把历史带到别的机器上）；
`META/skip-mount` 同样被排除——Magisk 认的是模块根目录下的 `skip_mount`，
这个名字和位置都不对，而本模块也没有需要屏蔽的 magic mount 内容。

## 配置与运行期数据

| 路径 | 作用 |
| --- | --- |
| `<模块根>/files/conf/blocklist.txt` | 黑名单（**生效配置**，保存即热加载） |
| `<模块根>/files/conf/whitelist.txt` | 白名单（同上） |
| `<模块根>/files/conf/upstream.txt` | 上游（同上） |
| `/data/adb/dnsfirewall/logs/dnsfw.log` | 服务日志，超 512 KiB 截尾保留 256 KiB |
| `/data/adb/dnsfirewall/run/dnsfw.pid`、`watchdog.pid` | 进程登记 |
| `/data/adb/dnsfirewall/state` | `1`=开机启动（默认），`0`=开机不启动 |
| `/data/adb/dnsfirewall/v6fb` | IPv6 回落生效中的快照：一行一个被拒的 v6 解析器地址（存在即回落生效，见「IPv6 回落」） |
| `/data/adb/dnsfirewall/conf/` | 卸载时备份的配置；首次升级时也从这里迁进模块目录 |
| `<模块根>/dnsfw_queries.log` | 解析域名记录（见下节） |
| `/sdcard/Download/dnsfirewall-backup.tar` | WebUI 备份/还原的固定文件名（备份即覆盖） |

**改名单/上游保存即生效**：dnsfw 另起一个线程用 inotify 监听 `files/conf` 目录，
`IN_CLOSE_WRITE / IN_MOVED_TO / IN_CREATE / IN_DELETE / IN_ATTRIB` 任一命中后安静 150 ms 再重载一次
（适配「写临时文件 + rename」的编辑器），日志会打 `配置已重载: 黑名单 N 条, 白名单 M 条, 上游 K 个`。
不用重启服务。

重载的失败保护：某个文件打不开时保留旧表；上游解析出 0 个时保留旧上游；
坏行按行跳过（见「名单语法」），不会因为一次半截保存就把过滤清空。
手工跑 `dnsfw` 时可用 `DNSFW_CONF` 覆盖配置目录，`DNSFW_PERSIST` 只影响脚本层的 run/logs。

## WebUI（KernelSU）

模块根目录的 `webroot/index.html` 是 KernelSU 的模块 WebUI 页面，在 KernelSU 管理器里打开本模块
即可进入；Magisk 原生没有 WebUI，普通浏览器打开会提示未检测到环境（只能看，不能读写）。

- 三个标签页：黑名单 / 白名单 / DNS服务器。列表里直接增删条目，写入的就是 `files/conf/*.txt`。
- 读写走 `window.ksu.exec()`：KSU 回传 stdout 会吃掉末尾换行（`cat` 1108 字节只能拿回 1107），
  所以读改成整文件 `base64 -w0`，页面解码后与 `wc -c` 精确比字节数，对不上就锁定该页只读
  （防止输出被截断后把半截内容写回去）；写按 1200 字符分块的 base64 落到 `.tmp`，核对字节数后
  `chmod` + `mv -f` 原子替换，保留文件里的注释。落的是最终文件名，dnsfw 的 inotify 照常触发重载。
- 提交前按 dnsfw 的规则先校验：域名只允许 `字母/数字/-/_/./*`、标签 1..63、整串 ≤253；
  黑名单拒收无点单标签、`*.com`、纯 `*`；上游校验 IPv4/IPv6 与 `#端口`。
  校验不过只提示、不写文件；就算绕过页面写进去，dnsfw 也会按行跳过。
- 保存后约 0.2 s 生效，不需要重启。
- 页面底部两个入口：**查询解析记录**弹出 `dnsfw_queries.log` 最近 400 条（自动隐藏表头注释行，
  重复域名在 dnsfw 侧已只留一份）；**关闭记录 / 开启记录**是同一个按钮的两种状态，
  对应 `files/conf/qlog.off` 的存在与删除。
- **备份配置 / 还原配置**：备份把三个配置文件打成 tar 写到
  `/sdcard/Download/dnsfirewall-backup.tar`（固定文件名，重复备份直接覆盖）；还原读取该文件
  覆盖三个配置并触发热加载。两个操作都会先弹确认框。
- 页面假设模块安装在 KernelSU 的标准路径 `/data/adb/modules/dnsfirewall`。
- 浅色 / 深色两套主题，选择记在 `localStorage`；深色是纯黑背景、白色文本，按钮用彩色。

## 解析记录（解析过哪些域名）

一行一个被解析过的域名，其它一概不写。默认 `/data/adb/modules/dnsfirewall/dnsfw_queries.log`：

```
# dnsfw 解析域名记录: 一行一个被解析过的域名（拦截与透传都记，重复域名只留一份）
api.example.com
ads.example.com
```

- 拦截与放行的查询都算「解析过」，所以要看某个域名有没有经手，直接 `grep` 这个文件。
- **同一域名只记一份**（大小写不敏感）：重复查询不再追加；启动时会把已有文件里的重复行
  压缩掉（读原文件 → 写 `.tmp` → rename，失败则保留原文件）。
- **可以关闭**：WebUI 底部「关闭记录」会写入 `files/conf/qlog.off`，dnsfw 通过 inotify 感知，
  约 0.2 s 后停止追加（`logs/dnsfw.log` 打 `解析记录已关闭`）；再点「开启记录」删掉该文件即恢复。
  开关关闭期间查询照常处理，只是不写这个文件。
- 判定结果、命中的名单条目、应答地址、耗时都不在这里——判定用 `dnsfw test <域名>` 看，
  服务过程看 `logs/dnsfw.log`。
- 路径由 `start_daemon` 导出 `DNSFW_QLOG="$MODDIR/dnsfw_queries.log"`，跟着实际安装目录走；
  编译期默认值是同一个模块根路径，只给「没走脚本、手工跑 `dnsfw serve`」兜底。
- `DNSFW_QLOG` 设成别处可换位置；设成 `off` 或 `0` 就完全不记录（启动期开关，优先于 WebUI）。
- 文件超过 2 MiB 会被**整份截断重建**，宁丢历史也不能把盘吃到没边。要长期保留就指到别处，
  再自己配轮转。
- **这份记录跟着模块目录走**：升级/重装会替换模块目录，记录不保证留存（本机没有 Magisk 可实测
  它到底是被清掉还是原地保留）。要跨升级留档就把 `DNSFW_QLOG` 指到 `/data/adb/dnsfirewall/` 下。
- 打不开就退到 `/data/local/tmp/dnsfw_queries.log`，仍然打不开就只告警一次、不记录。**记录功能失败绝不影响解析**。
- 只在 `serve` 下写；`dnsfw test` / `lists` 不碰这个文件。畸形包没有域名可记，只在服务日志里留痕。

## 名单语法（黑白名单一致）

| 条目 | 匹配 |
| --- | --- |
| `test.com` | test.com 本身 + 任意深度子域（`a.b.test.com`） |
| `*.test.com` | 与上一行**完全等价**，折叠进精确集合，不重复计一条 |
| `ad*.com` | 以 `ad` 开头且以 `.com` 结尾（`*` 可匹配空串） |
| `*tracker*` | 域名中包含 `tracker` |

- `#` 之后是行内注释；大小写不敏感；自动去重；首尾空格与尾点去掉（`example.com.` 等价）
- 只有 `*` 是通配符；其余字符只接受字母、数字、`-`、`_`、`.`（标签 1..63 字节、整串 ≤253）。
  含其它字符、空标签、超长标签的**格式不正确条目整条跳过**，日志告警，不影响同文件其它条目
- 黑名单拒收无点的单标签（`com`）、TLD 通配（`*.com`）和纯 `*`（会拦掉整个 TLD/全部域名）；
  白名单这一侧不拦单标签写法，但不建议
- 白名单**只豁免黑名单命中项**，不单独放行任何东西

`dnsfw test <域名>...` 逐条打印流水线判定，改名单前先用它验。

## 拦截与透传的行为

命中黑名单按查询类型分两种应答，两者都不碰上游：

- **A 查询 → 回一条指向本地 Sink v4 地址的应答**：`rcode=0`、`ANCOUNT=1`、`NSCOUNT=ARCOUNT=0`，
  答案名用压缩指针 `0xC00C` 指回问题段（问题名在应答里固定在偏移 12），
  `TYPE=A CLASS=IN RDLENGTH=4`，地址 `127.0.0.1`（源码里的 `BLOCK_A`），**TTL=1 s**（`BLOCK_A_TTL`
  ——给 1 不给大值，就是不让 netd/浏览器把 Sink 地址缓存下来）。应答长度 = 查询长度 + 16。
  头部的 ID 与 RD 回显、`QR=1`、`RA=1`、opcode 归零，与 NXDOMAIN 路径完全一致。
- **其它类型（AAAA / MX / TXT / …）→ 回 NXDOMAIN**：`rcode=3`、`ANCOUNT=0`，应答与查询等长。
  Sink 只对 v4 有意义，给 AAAA 编一个本地 v6 地址只会多出一层暴露面。

口径来源：这个工具的用途就是「命中黑名单回一个本地 v4 地址，其它直接透传」。
早先的实现是统一回 NXDOMAIN，理由是「应用无从分辨真伪、连接 53 端口以外的逻辑可能把它当真答案」——
这句权衡依然成立，见下面这条代价：本机如果真在 `127.0.0.1:80/443` 上跑了服务，被拦的域名就会
连到那个本地服务上（暴露面量化写在「已知限制」）。想换 Sink 地址或改回 NXDOMAIN，改 `BLOCK_A` /
`build_block_a()` 这一处即可。

- 放行 → 查询原样发到上游，应答**字节级透传**，不解析、不改写、不缓存。
- 应答必须是「来自本槽正在等的那个上游地址 + QR=1 + 事务 ID 与查询一致 + ≥12 字节」，
  否则只丢弃并记日志；0 字节或短包**不**算上游故障（不触发 failover），槽位留着继续等真应答。

## 并发与容错

单线程 `select` 事件循环，无 fork。监听口非阻塞，每轮最多收 256 条新查询（避免饿死上游应答）。

| 参数 | 值 | 位置 |
| --- | --- | --- |
| 监听端口 | 127.0.0.1:1053 与 [::1]:1053 | `DNS_PORT` |
| 并发在途上限 | 100（满则回 SERVFAIL） | `MAX_INFLIGHT` |
| 上游源端口 | 1054 + 槽位号（1054..1153） | `UP_SPORT_BASE` |
| 单上游超时 | 8 s，超时 failover 到下一个 | `UPSTREAM_TIMEOUT_MS` |
| 熔断 | 同一上游连续 3 次无响应 → 冷却 60 s | 上游健康度 |
| 全上游不可用 | 回 SERVFAIL（不伪造应答） | — |
| 上游数量上限 | 16 行 | `MAX_UPSTREAMS` |

上游 socket 故意 **不 connect**：部分 OEM 的 `dns_proxyd` 会改写 connected UDP socket 的出口。
源端口固定分配 + `nat` 里的源端口豁免规则，替代了早先「按上游 IP 放行」的做法——
后者等于给任何把 DNS 指向该 IP 的应用留了旁路。

**单实例**由内核保证：监听 socket 不设 `SO_REUSEADDR`，端口被占时 `bind` 直接失败并退出。
`common.sh` 的 `sweep_orphans()` 会按 `/proc/<pid>/exe` 清掉 PID 文件之外的本模块实例，
否则那种残留进程会让服务永远起不来。

## iptables 规则

```
*t nat
DNSFW 链:  -p udp --sport 1054:1153 -j RETURN        # dnsfw 自己的出网查询，不回环
           -p udp --dport 53 -j REDIRECT --to-ports 1053
OUTPUT:    -p udp --dport 53 -j DNSFW                 # 只装一条，-C 判过再加
```

- IPv4 必装；IPv6 侧装不上不撤 IPv4 规则，改走下一节的回落
- 生效与否以 `iptables -S` 的**反读**为准，不看单条命令的退出码
- 失败回滚的判据只看 IPv4：IPv6 装不上时撤掉 IPv4 等于把「过滤失效」变成「整机断网」
  （本轮真机上就是这个 bug：内核没有 ip6table_nat → `apply_rules 6` 失败 → 把已经生效的
  IPv4 规则一起撤了）
- 任一步失败 → 立刻撤销已装规则（fail-open：宁可这次不拦截，也不让整机 DNS 挂掉）
- 只重定向 UDP：dnsfw 没有 TCP 监听器，把 TCP 53 也转走会直接断掉依赖 TCP DNS 的解析

## IPv6 回落：内核没有 ip6table_nat 时

现象（Redmi M2007J22C / kernel 4.14.186-perf）：`iptables -t nat -S` 正常，
`ip6tables -t nat -S` 报 `Table 'nat' does not exist`——这个内核只编了
`ip6table_raw/mangle/filter`，没有 `ip6table_nat`。而 WLAN 的解析器是

```
DnsAddresses: [ /fe80::5288:11ff:feb1:cebc%wlan0, /192.168.5.1 ]
```

bionic 按顺序用第一个，也就是那台路由器链路本地 v6 地址。v6 报文进不了 IPv4 nat 表，
于是「规则装上了、名单也非空，就是没有任何效果」。

做法不是重定向 v6，而是把这台 v6 解析器打成不可用，让 netd 自己退到**同一网络**的 v4 解析器——
v4 的 53 会被 nat 重定向，查询就进入过滤了。规则落在 filter 表（跟 nat 那两条不是一回事）：

```
filter DNSFW6:  -p udp --dport 53 -d <该网络的 v6 解析器>/128 -j REJECT --reject-with icmp6-adm-prohibited
filter OUTPUT:  -p udp --dport 53 -j DNSFW6
```

门控（`v6fb_apply()`，三条同时满足才装）：

1. `apply_rules 6` 失败，即本机确实用不了 ip6table_nat；
2. `dumpsys connectivity` 能读到 `DnsAddresses`；
3. **同一个网络里既有 v6 解析器、又有至少一个 v4 解析器**。规则只针对那台网络自己的 v6
   解析器；只有 v6 解析器的网络一条都不加——那种情况撤掉 v6 就是真的断 DNS，宁可不拦。

实现细节：

- 地址从 dumpsys 的 `/fe80::1%wlan0` 里剥掉前导 `/` 和 `%zone`（`ip6tables -d` 不认 zone id）
- `REJECT ... icmp6-adm-prohibited` 让 netd 立刻判该服务器不可用并切换；内核不认这个
  reject-with 时退化成 `DROP`，netd 靠超时切换，慢一点但结果一致
- 装成功才写快照 `/data/adb/dnsfirewall/v6fb`（一行一个被拒地址）；`v6fb_ok()` 只在快照存在时
  才要求回落规则在位，所以「本来不需要回落」的机器不会被看门狗误判成缺规则
- 回落只在 `start.sh` 里试一次是不够的：本机 2026-11-01 就是 06:05 启动、06:20 才连上 Wi-Fi，
  那一次 `dumpsys` 读不到解析器，回落没装上，此后一直静默失效。看门狗每 60 s 调
  `v6fb_sync()` 拿当前网络的解析器集合和快照对账：没有就补装，地址变了就重建，没有 v4+v6
  并存的网络就撤掉（同时处理换 Wi-Fi 的情况）
- `stop.sh` / `uninstall.sh` / 失败回滚都调 `v6fb_del`：撤 OUTPUT 跳转、`-F` 再 `-X` 掉
  `DNSFW6`、删标记
- 这是「把查询引到能被过滤的那条路上」，不是「拦 v6 DNS」：v6 侧仍然没有内容级过滤

## 启停流程

`service.sh`（late_start）：等 `sys.boot_completed`（最多 120 s）→ 读 `state`，为 `0` 就 `stop.sh` 退出
→ `start.sh` → 起后台看门狗。看门狗每 10 s 检查一轮「进程在 + IPv4 规则在 + 回落规则在位（仅当
`v6fb` 快照存在）」，每 60 s 再对一次当前网络的解析器集合（`v6fb_sync()`，补装/重建/撤掉回落）；
连续 3 次修复失败就 `stop.sh` 并收手（同样是为了不让模块变成 DNS 故障源）。

`start.sh`：预检（`dnsfw`、`iptables` 缺任一个 → 记日志、退出 1，一条规则都不碰）→
`upstream.txt` 没有有效条目就拒绝启动（否则放行域名全部解析不了）→ **先起进程再装规则** → 反读校验。

`stop.sh`：先停看门狗 → **先撤规则再杀进程**（反了会有一段时间 53 被重定向到已关闭的端口），逐族用反读确认。
`uninstall.sh`：先看门狗（否则它会把服务拉回来）→ 规则 → 进程 → 删 `run`/`logs`，保留 `conf`。

## 构建与打包

```sh
# 1) 产出 files/bin/dnsfw（模块里只放一个，手机要 aarch64）
cd dnsfirewall/files/src
make install          # = 编 aarch64 + 拷到 ../bin/dnsfw，NDK 自动探测
#   NDK 定位优先级: make NDK=/path/to/ndk > $ANDROID_NDK_HOME > $ANDROID_NDK_ROOT
#                   > PATH 里第一个带 toolchains/llvm/prebuilt 的目录
#   没有 NDK 就在设备上: Termux pkg install clang && make install

# 2) 打包（/storage 是 noexec，用 sh 跑）
cd ../../.. && sh build.sh
```

Windows/Git Bash 上编这一条命令踩过的三个坑（Makefile 里都处理了，改之前先看）：

| 坑 | 现象 | 处理 |
| --- | --- | --- |
| MSYS 路径转换 | `-DCONFDIR="/data/adb/..."` 被改写成 `C:/Users/.../data/adb/...`，宏体编成语法错误 | 编译行加 `MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'` |
| mingw make 的续行 | recipe 里多行 `if/then` 报 `unexpected EOF while looking for matching '"'` | recipe 全写单行 |
| mingw objcopy | 只认 x86，碰 aarch64 报 `Unable to recognise the architecture` | 用 NDK 自带的 `llvm-objcopy` |

`build.sh` 会依次：`sh -n` 检查模块里每个脚本 → `files/bin/dnsfw` 不在位就**直接失败**
（打出一个装上不用的包没意义）→ 读 ELF `e_machine`（偏移 18）报告架构，宿主机产物会警告 →
写 zip 时显式给权限（目录/`.sh`/`bin` 下无扩展名文件 = 0755，其余 0644）→
**从 zip 自己存的 `external_attr` 反读校验**，不合规就退出 1。历史包不删，文件名带到秒。

Magisk 装机时把模块文件统一给 0644，所以 `customize.sh` 还会再 `set_perm` 一次；两处都覆盖到了。

**装机迭代走热替换，不走安装流程**（约定：测试期直接杀进程换文件）：

```sh
# 设备上，root
MODDIR=/data/adb/modules/dnsfirewall
. $MODDIR/files/lib/common.sh
stop_watchdog && stop_daemon        # 先断看门狗，否则 10 s 内它把旧二进制又拉起来
cp -f /data/local/tmp/dnsfw.new $MODDIR/files/bin/dnsfw   # 进程没停就覆盖会 ETXTBSY
chmod 755 $MODDIR/files/bin/dnsfw
nohup sh $MODDIR/service.sh >> /data/adb/dnsfirewall/logs/dnsfw.log 2>&1 &
```

推上去的每个文件都要 `md5sum` 与本地对一遍再往下走。

`magisk --install-module` 只在正式换版时用，而且要留意它在 `versionCode` 没变时**只更新
`module.prop`、写一个空的 `update` 标记，模块文件不会替换**——测试包按「只改文件名、不动
versionCode」的习惯分发时，装上去跑的还是上一版；真要换版就递增 `versionCode`。

## 验证到哪一步

- 核心：34 个重放用例（透传/伪造应答丢弃/NXDOMAIN 字节/截断包/空包不吞查询/上游熔断与
  冷却/名单语法/源端口分配/IPv6 上游/解析记录格式），源码 `gcc -O2 -std=gnu11 -Wall -Wextra`
  **零警告**。
- 拦截应答改成「A 查询回 Sink 地址」这一版另跑一套重放：用 WSL 里**同一份源码**编出的 host 产物
  + 一个只回定制品应答的假上游，40 条断言按类分（sinkA 11、sinkOther 6、passthru 4、pipeline 2、
  wildcard 2、robust 4、edns 1、multi 7、alive 1、qlog 2）全通过；
  负控取改前的基线源码（`backup/pre-v6fb-20261031-120736`，与改动前逐字节相同）编出来跑同一套：
  **Sink 类 16 条里 13 条失败，而透传/健壮性类 24 条仍全通过**——既证明断言抓得到行为差异，
  也证明不是环境自己坏了。`multi` 那 7 条是连续换 7 个被拦域名，逐个核答案指针与长度，防串名。
- 脚本层：48 条断言，用一份按 `iptables -S` 语义建模的假 iptables 驱动真实脚本 ——
  冷启动、幂等（跳转规则恰好一条、链内两条且豁免在前）、停服两族清干净、缺二进制/缺有效上游
  时拒绝且不留规则、内核装配失败时回滚、看门狗拉起被 SIGKILL 的服务、卸载停看门狗并保留 conf、
  野实例被清理后仍能正常启动并服务、解析记录由 `start_daemon` 导出到模块根目录且每行只有域名。
- 同一套核心断言在 **aarch64 产物**上也全跑通（`aarch64-linux-gnu-gcc -static`，`e_machine=183`，
  经 binfmt `qemu-aarch64` 执行，含解析记录那 5 条）。这说明目标指令集上行为一致，但它是
  glibc 静态 + 用户态模拟，不等于设备上的 bionic + 真内核。
- 脚本层的 48 条只在本机 x86-64 产物上跑：把 aarch64 产物放进假模块目录时，`pid_alive()` 读
  `/proc/<pid>/exe` 只能看到解释器 `/usr/bin/qemu-aarch64`，判活必然为假——这是模拟环境的限制，
  不是模块缺陷（真机上那条符号链接就是二进制本身）。
- IPv6 回落另有 31 条断言，用按 `iptables -S` / `dumpsys connectivity` 语义建模的假二进制驱动
  真实脚本：门控三条逐一做负控（去掉「同网络必须有 v4」这一条，纯 v6 网络就会去装规则）、
  多网络只对带 v4 的那台下规则、`%wlan0` 与前导 `/` 要剥掉、`REJECT` 不被支持时退化 `DROP`、
  中途装不上不留半成品、撤干净同时删标记。
- **真机已验（2026-10-31，Redmi M2007J22C / Magisk 30.7 / kernel 4.14.186-perf，无 ip6table_nat）**：
  `start.sh` 自动落回落规则并反读确认；人为 `ip6tables -t filter -F DNSFW6` 后，看门狗 2 s 内记
  「服务或规则缺失（含 v6 回落规则），重新装配」并把规则补回；`stop.sh` 撤干净后 DNS 恢复不拦截。
  Sink 应答也在真机上按字节验过：热替换新二进制后，用 `nc -u` 直连 127.0.0.1:1053 发手工查询，
  把应答 `od` 成 hex 回传逐字段核（47 条断言全过）——`www.baidu.com/A` 回 47 字节（查询 31 + 16），
  `8180 / ANCOUNT=1 / 0xC00C / TTL=1 / 7f000001`；`news.baidu.com/A` 同样回 Sink（证明不串名）；
  `www.baidu.com/AAAA` 与 `/MX` 回 31 字节、`rcode=3`、`ANCOUNT=0`；`www.taobao.com/A` 拿到 112 字节
  真应答（CNAME 展开 `danuoyi.tbcache.com` + 两个 A，TTL 26 s，是上游的值不是本地的 1 s）。
  走真实解析链路（bionic → netd → nat 重定向）`ping www.baidu.com` 解析成 `127.0.0.1`、
  `ping www.taobao.com` 解析成 112.45.115.86；Via 里 `https://www.baidu.com` 显示
  `net::ERR_CONNECTION_REFUSED`（拿到 Sink 地址后连接被拒），`https://www.taobao.com` 页面正常渲染。
- **仍未在真机验证**：本机没有 busybox，Magisk 的 busybox ash standalone 模式只做了语法与写法规避；
  本轮真机是手动跑 `service.sh` 起的服务，`late_start` 开机自启与 SELinux 上下文还要在重启后走一遍。
- 解析记录的早期形态（写 `/tmp`、带判定与应答字段）曾在真机（RMX5200 / a16）验证过写入与
  放行/拦截/AAAA/上游全挂四种分支。本版改成「一行一个域名 + 模块根目录」后，M2007J22C 上
  确认 Magisk 模块根目录可写、查询确实逐行落到 `<模块根>/dnsfw_queries.log`；打不开会退到
  `/data/local/tmp` 并在服务日志写明，不会因为记不上而不解析。

## 代码复核（2026-10-31，加解析记录时一并过了一遍）

已修：

- `strset_insert()` 首次 `calloc` 失败会留下 `cap=64 / keys=NULL` 的半初始化集合，之后任何
  `strset_find()` 都解引用空指针直接段错误（看门狗会把崩溃进程反复拉起来，表现为服务起不来）。
  改成先分配成功再改 `cap`。

看过但没改、值得知道的：

- 应答合法性只校验「QR=1 + 事务 ID 一致 + 源地址等于本槽正在等的上游」。上游源端口是
  `1054+槽位号` 这种可预测值，从链路上伪造应答只需要猜 16 位 ID。要更硬就加一条：应答里的
  question 段必须与查询逐字节一致。当前认为局域网/运营商链路的威胁不在本模块能解决的范围内，
  所以没动。
- `slot_send()` 发送失败（绑不上源端口、上游路由不通）不记上游 `strikes`，只有超时才计入冷却。
  属于「已知不一致」，影响到的是熔断的灵敏度，不影响正确性。
- `dlist_load()` 若对同一个 `dlist_t` 调两次会漏掉旧表；当前只在启动时各调一次，不是问题。
- 事件循环里的槽位生命周期是自洽的：`slot_close()` 幂等，failover 换 socket 不会跨槽复用 fd，
  `select` 前后的 `active` 复查也到位。

## 已知限制

- 只管本机 `OUTPUT` 的 UDP 53。TCP 53、DoT、DoH、以及浏览器自带 DoH / 应用内嵌解析器都绕过。
- 内核没有 `ip6table_nat` 时（本轮这台 4.14 perf 内核就是），IPv6 侧靠「回落」而不是「重定向」：
  只把同网络那台 v6 解析器打成不可用、让查询改走 v4，v6 报文本身并没有被过滤；只有 v6 解析器的
  网络完全不生效（门控故意如此，撤了就是断 DNS）。
- 上游是明文 UDP:53，链路可被监听或劫持；dnsfw 不做 DNSSEC 校验。
- 1053 只绑 loopback，但本机任何应用都能直接把它当上游用（无鉴权）。直接向 1053 发查询
  仍然会经过过滤，所以这不是放行旁路，只是少数的本地暴露面。
- Sink 地址的暴露面：被拦的域名会解析成 `127.0.0.1`，所以**本机在 80/443 上监听的服务会收到
  这些连接**（表现为应用拿到一个本地页面的内容，或证书对不上）。本轮在 M2007J22C 实测过：
  `127.0.0.1` 上只有 8765 / 42465 / 8788 三个监听，80/443/21/8080 全无服务，所以 Sink 就是纯死路，
  Via 得到 `ERR_CONNECTION_REFUSED`。换机器或本机起了本地 HTTP 服务时要重新看这一条。
- dnsfw 以 root 在 Magisk 上下文出网，**不受按应用绑定的 VPN/代理路由约束**：如果你靠某个
  VPN 走 DNS，被放行的查询会从物理接口直接出去。
- 设计上是 fail-open：规则装不上、看门狗连续失败、进程起不来，都会退回「DNS 不被过滤但可用」。
- 名单/上游改动由 inotify 热加载（约 150–200 ms）；只监听 `files/conf` 下那三个文件名，
  换文件名或改 `DNSFW_CONF` 需要重启服务。没有缓存、没有按应用统计。
- 解析记录只有域名本身：不记是哪个应用查的（要看归属得靠 `ss`/`netstat` 抓源端口）、
  不记判定与应答地址（判定用 `dnsfw test`，过程看服务日志）。同一域名被解析多次就有多行。
- 解析记录在模块根目录，升级/重装会替换模块目录，不保证留存；`/data/adb/modules` 在 /data 上，
  不是内存盘，所以 2 MiB 上限是防它无限长大，超限整份截断重建。长期留档把 `DNSFW_QLOG` 指到别处。
- 名单管理只有 KernelSU WebUI；在线名单订阅、远程 API 尚未实现。
- 绕过 Magisk 直接 `rm -rf` 模块目录时 `uninstall.sh` 不会执行，nat 规则会留在内核里直到重启；
  补救是先手动跑 `stop.sh`。

## 其它

- 全部脚本是 POSIX sh，兼顾 Android `/system/bin/sh`(mksh) 与 Magisk 的 busybox ash standalone 模式；
  `customize.sh` 是被 source 的，结尾不能有 `exit`。
- C 代码只用 POSIX/bionic 接口，NDK 按 API 21 编译；`module.prop` 里没有 `minApi` 这种
  Magisk 不认的键，真正的门槛是 Magisk 本身。
- `upstream.txt` 里 `#` 是「地址#端口」的分隔符，不是行内注释（行首 `#` 才是注释）。
