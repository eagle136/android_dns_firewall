/* =========================================================================
 * dnsfw.c — Android DNS 防火墙核心程序（Magisk 模块）
 *
 * 架构: select 事件循环处理 DNS；另起一个线程用 inotify 监听配置目录，
 *       名单/上游文件一改就重载（格式错误的行跳过，不影响其它条目）
 *   - 拦截: 一律回 NXDOMAIN（含 A），不给 sinkhole 地址，完全不碰上游
 *   - 透传: 每查询一个在途槽位，最多 MAX_INFLIGHT 路并发等上游，
 *           单上游 UPSTREAM_TIMEOUT_MS 超时后换下一个未试过的上游；
 *           连续失败的上游进入冷却，不再拖慢后续查询；全失败回 SERVFAIL；
 *           上游应答原样转发回客户端
 *   - 上游出口 socket 绑定固定源端口区间，配合 iptables 的 --sport 豁免规则，
 *     既避免重定向死循环，又不需要按上游 IP 放行（那样 app 把 DNS 指到上游 IP 就绕过了）
 *
 * 过滤流水线:
 *   阶段1  黑名单 conf/blocklist.txt  命中 -> 拦截候选
 *   阶段2  白名单 conf/whitelist.txt  命中 -> 放行
 *
 * 名单语法（黑白相同）:
 *   普通域名(不含*)   匹配自身及全部子域名
 *   *.test.com        等价于 test.com
 *   ad*.com / *tracker*   '*' 在任意位置，匹配任意字符串(含空)
 *   行内 '#' 之后为注释；条目尾部的 '.' 会被忽略
 *
 * 用法:
 *   dnsfw serve                     启动本地 DNS 服务（127.0.0.1:1053 与 [::1]:1053）
 *   dnsfw test <域名> [域名...]     测试流水线判定并打印命中的条目
 *   dnsfw lists                     显示已加载列表统计
 *
 * 记录: 两份去重域名日志 + 一份实时流水
 *   dnsfw_queries.log  放行（含未命中黑名单）的域名，去重；名单一变就按新名单重扫
 *   dnsfw_blocked.log  命中黑名单且未被白名单豁免的域名，去重；与上面互相搬移
 *   dnsfw_recent.log   每条查询一行（不去重），给网页滚动看最近若干条
 *
 * 环境变量:
 *   DNSFW_CONF  覆盖配置目录
 *   DNSFW_QLOG  覆盖解析记录文件（默认模块根目录的 dnsfw_queries.log；设为 off 关闭记录）
 *   DNSFW_BLOG  覆盖拦截记录文件（默认模块根目录的 dnsfw_blocked.log；设为 off 关闭它）
 *   DNSFW_RLOG  覆盖实时日志文件（默认模块根目录的 dnsfw_recent.log；设为 off 关闭它）
 * ========================================================================= */

#include <stdint.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifndef CONFDIR
#define CONFDIR "/data/adb/modules/dnsfirewall/files/conf"
#endif

/* 解析/拦截记录文件: 默认放模块根目录（装/刷机时随模块一起被替换），
   可用 DNSFW_QLOG / DNSFW_BLOG 覆盖。模块根目录由脚本层用 $MODDIR 导出，
   这里的默认值只给手工跑 serve 时兜底。 */
#ifndef QLOG_PATH
#define QLOG_PATH             "/data/adb/modules/dnsfirewall/dnsfw_queries.log"
#endif
#ifndef BLOG_PATH
#define BLOG_PATH             "/data/adb/modules/dnsfirewall/dnsfw_blocked.log"
#endif
#ifndef RLOG_PATH
#define RLOG_PATH             "/data/adb/modules/dnsfirewall/dnsfw_recent.log"
#endif
#define QLOG_FALLBACK         "/data/local/tmp/dnsfw_queries.log"
#define BLOG_FALLBACK         "/data/local/tmp/dnsfw_blocked.log"
#define RLOG_FALLBACK         "/data/local/tmp/dnsfw_recent.log"
#define QLOG_MAX_BYTES        (2 * 1024 * 1024)   /* 宁丢历史也不能吃磁盘 */

#define DNS_PORT              1053
#define MAX_INFLIGHT          100    /* 并发等待上游上限 */
#define UP_SPORT_BASE         1054   /* 上游出口源端口: 1054..1054+MAX_INFLIGHT-1 */
#define UP_SPORT_END          (UP_SPORT_BASE + MAX_INFLIGHT - 1)
# ifndef UPSTREAM_TIMEOUT_MS
#define UPSTREAM_TIMEOUT_MS   8000   /* 单上游等待超时（可用 -D 覆盖做快速回归） */
# endif
#define MAX_UPSTREAMS         16
#define UP_DOWN_STRIKES       3      /* 连续超时几次后进入冷却 */
#define UP_DOWN_COOLDOWN_MS   60000
#define MAX_QUERY_STORE       2048   /* 单条查询存槽上限 */
#define MAX_RECV              65536  /* UDP 数据报上限 */
#define DRAIN_BUDGET          256    /* 每轮事件循环最多处理的新查询数 */

#define RCODE_SERVFAIL 2
#define RCODE_NXDOMAIN 3

static const char *verdict_str(int blocked)
{
    return blocked ? "BLOCK" : "ALLOW";
}

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;   /* armv7 上 long 会溢出 */
}

/* 主线程和配置监听线程都会打日志；整行加锁输出，避免时间戳和正文交错 */
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

/* 名单/上游: 监听线程解析出新表后整表替换，查询线程持锁查表 */
static pthread_mutex_t g_conf_lock = PTHREAD_MUTEX_INITIALIZER;

static void plog(const char *fmt, ...)
{
    struct timespec ts;
    struct tm tm;
    va_list ap;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    pthread_mutex_lock(&g_log_lock);
    printf("[%02d:%02d:%02d] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
    pthread_mutex_unlock(&g_log_lock);
}

static void conf_dir(char *out, size_t outsz)
{
    const char *env = getenv("DNSFW_CONF");
    snprintf(out, outsz, "%s", (env && *env) ? env : CONFDIR);
}

/* ---------------- 字符串哈希集合（开放地址 + 线性探测） ---------------- */

typedef struct {
    char  **keys;
    size_t  cap;      /* 2 的幂 */
    size_t  used;
} strset_t;

static void strset_init(strset_t *S)
{
    S->keys = NULL;
    S->cap = 0;
    S->used = 0;
}

/* 大小写不敏感: 集合的相等判定用的是 strcasecmp，哈希也必须按同一口径，
   否则大小写不同的同一域名会落进不同桶，永远撞不上。 */
static size_t fnv1a(const char *s)
{
    unsigned int h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)tolower((unsigned char)*s++);
        h *= 16777619u;
    }
    return (size_t)h;
}

/* 返回 1 新插入，0 已存在，-1 失败 */
static int strset_insert(strset_t *S, const char *k)
{
    if (S->cap == 0) {
        /* 先分配成功再改 cap: 反过来写的话，分配失败会留下 cap=64/keys=NULL 的
           半初始化状态，下一次 strset_find 直接解引用空指针 */
        char **nk = (char **)calloc(64, sizeof(char *));
        if (!nk) return -1;
        S->keys = nk;
        S->cap = 64;
    }
    size_t j = fnv1a(k) & (S->cap - 1);
    while (S->keys[j]) {
        if (strcasecmp(S->keys[j], k) == 0) return 0;
        j = (j + 1) & (S->cap - 1);
    }
    if (S->used * 10 >= S->cap * 7) {              /* 负载 >=0.7 扩容 */
        size_t nc = S->cap * 2;
        char **nk = (char **)calloc(nc, sizeof(char *));
        if (!nk) return -1;
        for (size_t i = 0; i < S->cap; i++) {
            if (!S->keys[i]) continue;
            size_t t = fnv1a(S->keys[i]) & (nc - 1);
            while (nk[t]) t = (t + 1) & (nc - 1);
            nk[t] = S->keys[i];
        }
        free(S->keys);
        S->keys = nk;
        S->cap = nc;
        j = fnv1a(k) & (S->cap - 1);
        while (S->keys[j]) j = (j + 1) & (S->cap - 1);
    }
    char *cp = strdup(k);
    if (!cp) return -1;
    S->keys[j] = cp;
    S->used++;
    return 1;
}

/* 命中返回表内条目指针，未命中返回 NULL */
static const char *strset_find(const strset_t *S, const char *k)
{
    if (S->cap == 0) return NULL;
    size_t j = fnv1a(k) & (S->cap - 1);
    while (S->keys[j]) {
        if (strcasecmp(S->keys[j], k) == 0) return S->keys[j];
        j = (j + 1) & (S->cap - 1);
    }
    return NULL;
}

static void strset_free(strset_t *S)
{
    for (size_t i = 0; i < S->cap; i++)
        if (S->keys[i]) free(S->keys[i]);
    free(S->keys);
    S->keys = NULL;
    S->cap = S->used = 0;
}

/* ---------------- 解析/拦截记录（默认写在模块根目录） ----------------
 * 两份日志、互不重复:
 *   解析日志  放行（含未命中黑名单）的域名
 *   拦截日志  命中黑名单且未被白名单豁免的域名
 * 同一文件内重复域名只留一份（大小写不敏感）。名单一变就由 qlog_reconcile()
 * 按新名单重扫两份文件，命中关系变了的域名在两者之间搬移，两份日志始终与
 * 当前名单一致（见下面的「日志重匹配」一节）。
 * 只追加写; 打不开文件就降级到 /data/local/tmp，再不行就只告警一次、完全不记录。
 * 记录功能绝不许影响解析本身，所以这里任何失败都不改变主流程。 */

#define QLOG_MAX_DOMAINS 100000   /* 去重集合上限: 再大就只追加查重，免得吃内存 */

typedef struct {
    FILE       *fp;          /* NULL = 这一份没开起来（env 设了 off，或打不开） */
    char        path[256];
    long        bytes;
    strset_t    seen;        /* 已写过的域名，重复查询不再追加 */
    const char *hdr;         /* 文件为空时写的表头 */
} qlog_t;

static qlog_t g_qlog;        /* 解析（放行） */
static qlog_t g_blog;        /* 拦截 */
static qlog_t g_rlog;        /* 实时（不去重，逐条） */
/* WebUI 的开关: conf 目录里存在 qlog.off 就三份一起停写（文件保留，删除即恢复） */
static volatile int g_qlog_enabled = 1;

static const char QLOG_HEADER[] =
    "# dnsfw 解析域名记录: 一行一个被放行的域名（拦截的另记 dnsfw_blocked.log，重复只留一份）\n";
static const char BLOG_HEADER[] =
    "# dnsfw 拦截记录: 一行一个被拦截的域名（重复只留一份；解除拦截后移回 dnsfw_queries.log）\n";
static const char RLOG_HEADER[] =
    "# dnsfw 实时日志: 每条查询一行（HH:MM:SS 判定 域名），不去重，网页上滚动看最近若干条\n";

/* WebUI 的开关: conf 目录里存在 qlog.off 就停止记录（文件保留，删除即恢复）。
 * 配置监听线程在目录变化时调用这里，主线程 qlog_write 只读标志。 */
static void qlog_sync_enabled(void)
{
    char dir[256], p[288];
    conf_dir(dir, sizeof dir);
    int n = snprintf(p, sizeof p, "%s/qlog.off", dir);
    g_qlog_enabled = (n > 0 && (size_t)n < sizeof p && access(p, F_OK) == 0) ? 0 : 1;
}

/* 超限就整份截断重建: 记录文件只做追加写，宁丢历史也不能把盘吃到没边 */
static void qlog_reset_one(qlog_t *Q)
{
    if (!Q->fp) return;
    fclose(Q->fp);
    Q->fp = NULL;
    strset_free(&Q->seen);        /* 文件已重建，去重集合跟着清空 */
    strset_init(&Q->seen);
    Q->fp = fopen(Q->path, "w");
    Q->bytes = 0;
    if (!Q->fp) {
        plog("警告: %s 重建失败，本次运行不再记录\n", Q->path);
        return;
    }
    fprintf(Q->fp, "# %s 超过 %d 字节已截断重建\n", Q->path, QLOG_MAX_BYTES);
    fflush(Q->fp);
    long p = ftell(Q->fp);
    if (p > 0) Q->bytes = p;
}

/* 以追加方式挂上句柄；文件是空的就补表头 */
static void qlog_open_append(qlog_t *Q)
{
    Q->fp = fopen(Q->path, "a");
    if (!Q->fp) {
        plog("警告: %s 打不开，本次运行不记录\n", Q->path);
        return;
    }
    fseek(Q->fp, 0, SEEK_END);
    long sz = ftell(Q->fp);
    Q->bytes = sz > 0 ? sz : 0;
    if (Q->bytes == 0) {
        fputs(Q->hdr, Q->fp);
        fflush(Q->fp);
        long p = ftell(Q->fp);
        if (p > 0) Q->bytes = p;
    }
}

/* 开一份记录。env 设成 off/0 就整份不记；打不开先建目录再试，仍不行退到 fallback。
 * 任何失败都只影响记录，不影响解析。 */
static void qlog_open_one(qlog_t *Q, const char *envname, const char *defpath,
                          const char *fallback, const char *hdr, const char *label)
{
    memset(Q, 0, sizeof *Q);
    strset_init(&Q->seen);
    Q->hdr = hdr;

    const char *env = getenv(envname);
    if (env && (!*env || strcasecmp(env, "off") == 0 || strcmp(env, "0") == 0)) {
        plog("%s: 已关闭（%s 设成 off）\n", label, envname);
        return;
    }
    const char *want = (env && *env) ? env : defpath;
    snprintf(Q->path, sizeof Q->path, "%s", want);
    FILE *f = fopen(Q->path, "a");
    if (!f) {
        /* 目录可能还不存在（首次 serve 早于脚本创建）或只读；按需建一次目录再试 */
        char dir[256];
        snprintf(dir, sizeof dir, "%s", Q->path);
        char *slash = strrchr(dir, '/');
        if (slash && slash != dir) { *slash = 0; mkdir(dir, 0777); }
        f = fopen(Q->path, "a");
    }
    if (!f) {
        snprintf(Q->path, sizeof Q->path, "%s", fallback);
        f = fopen(Q->path, "a");
        if (f) plog("警告: %s 改写到 %s（%s 打不开）\n", label, Q->path, want);
    }
    if (!f) {
        plog("警告: %s 文件 %s 打不开，本次运行不记录\n", label, want);
        Q->path[0] = 0;
        return;
    }
    fclose(f);

    qlog_open_append(Q);
    if (!Q->fp) Q->path[0] = 0;
    else plog("%s: %s\n", label, Q->path);
}

static void qlog_open(void)
{
    qlog_sync_enabled();
    qlog_open_one(&g_qlog, "DNSFW_QLOG", QLOG_PATH, QLOG_FALLBACK, QLOG_HEADER, "解析记录");
    qlog_open_one(&g_blog, "DNSFW_BLOG", BLOG_PATH, BLOG_FALLBACK, BLOG_HEADER, "拦截记录");
    qlog_open_one(&g_rlog, "DNSFW_RLOG", RLOG_PATH, RLOG_FALLBACK, RLOG_HEADER, "实时日志");
}

/* 实时日志: 每条查询一行、不去重，网页上滚动看最近若干条。
 * 它不参与重匹配（没有去重集合），超限同样整份截断。 */
static void rlog_write(const char *name, int blocked)
{
    if (!g_rlog.fp || !g_qlog_enabled || !name || !*name) return;
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    fprintf(g_rlog.fp, "%02d:%02d:%02d %s %s\n",
            tm.tm_hour, tm.tm_min, tm.tm_sec, verdict_str(blocked), name);
    fflush(g_rlog.fp);
    long pos = ftell(g_rlog.fp);
    if (pos >= 0) g_rlog.bytes = pos;
    if (g_rlog.bytes > QLOG_MAX_BYTES) qlog_reset_one(&g_rlog);
}

static void qlog_write(const char *name, int blocked)
{
    if (!g_qlog_enabled || !name || !*name) return;
    rlog_write(name, blocked);

    qlog_t *Q = blocked ? &g_blog : &g_qlog;
    if (!Q->fp) return;
    /* 同一域名只写一份；集合满或内存不足时退回逐条追加，宁多写不丢记录 */
    if (Q->seen.used < QLOG_MAX_DOMAINS && strset_insert(&Q->seen, name) == 0) return;
    fprintf(Q->fp, "%s\n", name);
    fflush(Q->fp);
    long pos = ftell(Q->fp);
    if (pos >= 0) Q->bytes = pos;
    if (Q->bytes > QLOG_MAX_BYTES) qlog_reset_one(Q);
}

/* ---------------- 域名归一化与通配符 ---------------- */

/* 原地小写、去前导与尾随点 */
static char *normalize_domain(char *s)
{
    while (*s == '.') s++;
    for (char *p = s; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    size_t len = strlen(s);
    while (len && s[len-1] == '.') s[--len] = 0;
    return s;
}

/* 只接受 [a-z0-9._*-]：标签 1..63 字节、整串 <=253。格式不对的行整条跳过，
 * 免得它变成一条永远匹配不上的“幽灵条目”悄悄占着名单。 */
static int has_alnum(const char *s)
{
    for (; *s; s++)
        if (isalnum((unsigned char)*s)) return 1;
    return 0;
}

static int domain_pattern_ok(const char *s)
{
    size_t total = 0, label = 0;
    if (!*s) return 0;
    for (const char *p = s; ; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == 0 || c == '.') {
            if (label == 0 || label > 63) return 0;
            if (c == 0) break;
            label = 0;
            continue;
        }
        if (!(isalnum(c) || c == '-' || c == '_' || c == '*')) return 0;
        if (++total > 253) return 0;
        if (++label > 63) return 0;
    }
    return total > 0;
}

/* glob 匹配: '*' 匹配任意字符串(含空)，其余大小写不敏感 */
static int glob_match(const char *pat, const char *name)
{
    const char *p = pat, *n = name;
    const char *sp = NULL, *sn = NULL;      /* 最近一个 '*' 的位置 */
    while (*n) {
        if (*p == '*') {
            sp = p;
            sn = n;
            p++;
        } else if (*p && tolower((unsigned char)*p) == tolower((unsigned char)*n)) {
            p++;
            n++;
        } else if (sp) {
            n = ++sn;                       /* '*' 多匹配一个字符后重试 */
            p = sp + 1;
        } else {
            return 0;
        }
    }
    while (*p == '*') p++;
    return *p == '\0';
}

/* ---------------- 域名列表 ---------------- */

typedef struct {
    strset_t exact;    /* 无'*' 及 '*.x' 形式: 自身 + 逐点后缀都走哈希 */
    char   **wild;     /* 含'*' 的其它形式: glob 匹配 */
    size_t   wild_used, wild_cap;
} dlist_t;

static void dlist_init(dlist_t *L)
{
    memset(L, 0, sizeof(*L));
    strset_init(&L->exact);
}

static void dlist_free(dlist_t *L)
{
    strset_free(&L->exact);
    for (size_t i = 0; i < L->wild_used; i++) free(L->wild[i]);
    free(L->wild);
    L->wild = NULL;
    L->wild_used = L->wild_cap = 0;
}

/* 当前生效的名单: 监听线程解析后整表替换，查询线程持 g_conf_lock 读 */
static dlist_t g_black, g_white;

/* 成功 1，内存不足 0 */
static int dlist_push(dlist_t *L, const char *s)
{
    if (L->wild_used == L->wild_cap) {
        size_t nc = L->wild_cap ? L->wild_cap * 2 : 16;
        char **na = (char **)realloc(L->wild, nc * sizeof(char *));
        if (!na) return 0;
        L->wild = na;
        L->wild_cap = nc;
    }
    char *cp = strdup(s);
    if (!cp) return 0;
    L->wild[L->wild_used++] = cp;
    return 1;
}

/* 去首尾空白、剥 '#' 注释；空行/注释行返回 NULL。就地修改缓冲区 */
static char *strip_line(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    size_t len = strlen(s);
    while (len && isspace((unsigned char)s[len-1])) s[--len] = 0;
    char *h = strchr(s, '#');
    if (h) {
        *h = 0;
        len = strlen(s);                            /* 必须重算: 截断后旧 len 已失效 */
        while (len && isspace((unsigned char)s[len-1])) s[--len] = 0;
    }
    return *s ? s : NULL;
}

/* 加载列表。strict=1（黑名单）时拒收无点的单标签条目——那会拦掉整个 TLD。
 * 成功返回条目数(可能为 0)，打不开文件返回 -1 */
static int dlist_load(dlist_t *L, const char *path, int strict)
{
    dlist_t nl;
    dlist_init(&nl);
    FILE *f = fopen(path, "r");
    if (!f) {
        plog("无法打开 %s: %s\n", path, strerror(errno));
        dlist_free(&nl);
        return -1;
    }
    char line[512];
    size_t skipped = 0, bad = 0, oom = 0;
    while (fgets(line, sizeof(line), f)) {
        char *s = strip_line(line);
        if (!s) continue;
        char *norm = normalize_domain(s);
        if (!*norm) continue;
        if (!domain_pattern_ok(norm)) {
            plog("警告: %s 跳过格式不正确的条目 '%s'\n", path, norm);
            bad++;
            continue;
        }
        if (norm[0] == '*' && norm[1] == '.' && !strchr(norm + 2, '*')) {
            /* *.x 与 x 语义相同，归一到哈希表，不进 glob 慢路径；
               x 本身仍要是带点的域名，*.com 等于拦掉整个 TLD */
            if (strict && !strchr(norm + 2, '.')) {
                plog("警告: %s 跳过过宽条目 '%s'（无点会拦掉整个 TLD）\n", path, norm);
                skipped++;
                continue;
            }
            if (strset_insert(&nl.exact, norm + 2) < 0) oom++;
        } else if (strchr(norm, '*')) {
            /* 纯 '*'/'**' 一条就匹配所有域名，黑名单里拒收；
               *tracker* 这类含字母的模式照常支持 */
            if (strict && !has_alnum(norm)) {
                plog("警告: %s 跳过过宽条目 '%s'（会匹配所有域名）\n", path, norm);
                skipped++;
                continue;
            }
            if (!dlist_push(&nl, norm)) oom++;
        } else {
            if (strict && !strchr(norm, '.')) {
                plog("警告: %s 跳过过宽条目 '%s'（无点会拦掉整个 TLD）\n", path, norm);
                skipped++;
                continue;
            }
            if (strset_insert(&nl.exact, norm) < 0) oom++;
        }
    }
    fclose(f);
    if (oom) plog("警告: %s 有 %zu 条因内存不足未加载\n", path, oom);
    if (bad) plog("警告: %s 跳过 %zu 条格式不正确的条目\n", path, bad);
    if (skipped) plog("警告: %s 跳过 %zu 条过宽条目\n", path, skipped);
    *L = nl;
    return (int)(nl.exact.used + nl.wild_used);
}

/* 命中: 全名 -> 逐点后缀（都是哈希 O(1)） -> 通配符线性扫。
 * 命中返回条目文本，why 可为 NULL */
static const char *dlist_hit(const dlist_t *L, const char *name, const char **why)
{
    const char *k = strset_find(&L->exact, name);
    if (k) { if (why) *why = k; return k; }
    for (const char *dot = strchr(name, '.'); dot; dot = strchr(dot + 1, '.')) {
        k = strset_find(&L->exact, dot + 1);
        if (k) { if (why) *why = k; return k; }
    }
    for (size_t i = 0; i < L->wild_used; i++) {
        if (glob_match(L->wild[i], name)) {
            if (why) *why = L->wild[i];
            return L->wild[i];
        }
    }
    return NULL;
}

/* ---------------- 过滤流水线 ----------------
 * 阶段1 黑名单(命中=拦截候选) -> 阶段2 白名单(命中=放行) */
static int filter_pipeline(const dlist_t *black, const dlist_t *white, const char *name,
                           const char **black_hit, const char **white_hit)
{
    const char *b = dlist_hit(black, name, black_hit);
    if (!b) return 0;
    if (dlist_hit(white, name, white_hit)) return 0;    /* 白名单豁免 */
    return 1;
}

/* ---------------- 日志重匹配（名单一变就把域名搬对地方） ----------------
 * 目的: 两份去重日志始终符合当前名单。新命中黑名单的从解析日志搬进拦截日志；
 * 解除拦截（删黑名单条目、把域名加进白名单）的从拦截日志搬回解析日志。
 * 触发点: 配置重载之后、启动时各一次。
 * 名单只由配置监听线程改（reload_conf 里整表替换），这里故意不持 g_conf_lock，
 * 免得重扫期间把 DNS 查询挡住；主线程对这两张表只读。 */

/* 以追加方式打开目标文件，空文件补表头；失败返回 NULL */
static FILE *qlog_open_dst(const char *path, const char *hdr)
{
    FILE *f = fopen(path, "a");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    if (ftell(f) == 0) fputs(hdr, f);
    return f;
}

/* 把 src 里的域名分成两拨: 该留在本文件的写进 tmp，该搬到另一份的追加进 dst。
 *   is_block_src=1 表示 src 是拦截日志: 命中黑名单的留下，其余搬走
 *   keep_seen  顺便完成文件内去重，并记下最终留在本文件的域名
 *   dst_seen   对方文件已有的域名，已经在里面的不再重复追加
 * 返回 1 成功（tmp 可以 rename 覆盖原文件），0 失败（调用方不许动原文件）。 */
static int qlog_partition(const char *src, const char *tmp, const char *hdr,
                          int is_block_src, FILE *dst, strset_t *dst_seen,
                          strset_t *keep_seen, size_t *moved)
{
    FILE *in = fopen(src, "r");
    if (!in) return 0;
    FILE *out = fopen(tmp, "w");
    if (!out) { fclose(in); return 0; }
    fputs(hdr, out);

    char line[512];
    int bad = 0;
    while (fgets(line, sizeof line, in)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        size_t n = strlen(p);
        while (n && (p[n-1] == '\n' || p[n-1] == '\r')) p[--n] = 0;
        if (!*p || *p == '#') continue;
        char name[256];
        snprintf(name, sizeof name, "%s", p);
        if (!*normalize_domain(name)) continue;       /* 历史文件里的大小写/尾点在这里归一 */

        if (filter_pipeline(&g_black, &g_white, name, NULL, NULL) == is_block_src) {
            if (keep_seen->used < QLOG_MAX_DOMAINS && strset_insert(keep_seen, name) == 0)
                continue;                             /* 同一文件里的重复行 */
            fprintf(out, "%s\n", name);
        } else if (dst_seen->used >= QLOG_MAX_DOMAINS || strset_insert(dst_seen, name) != 0) {
            fprintf(dst, "%s\n", name);
            if (moved) (*moved)++;
        }
    }
    if (ferror(in) || ferror(out)) bad = 1;
    fclose(in);
    if (fclose(out) != 0) bad = 1;
    if (bad) { unlink(tmp); return 0; }
    return 1;
}

static void qlog_reconcile(void)
{
    if (!g_qlog_enabled) return;                       /* 记录关着就不折腾 */
    if (!g_qlog.fp || !g_blog.fp) return;              /* 有一份没开起来就不同步，免得搬出半套状态 */

    size_t moved_out = 0, moved_back = 0;
    char tmp[300];

    /* 重写前先放开句柄: 下面要 rename 覆盖同一个路径 */
    fclose(g_qlog.fp); g_qlog.fp = NULL;
    fclose(g_blog.fp); g_blog.fp = NULL;

    /* 1) 拦截日志 -> 不再命中的搬回解析日志 */
    FILE *q = qlog_open_dst(g_qlog.path, QLOG_HEADER);
    if (q) {
        strset_free(&g_blog.seen);
        strset_init(&g_blog.seen);
        snprintf(tmp, sizeof tmp, "%s.tmp", g_blog.path);
        if (qlog_partition(g_blog.path, tmp, BLOG_HEADER, 1, q, &g_qlog.seen,
                           &g_blog.seen, &moved_back)) {
            if (rename(tmp, g_blog.path) != 0) unlink(tmp);
        }
        fclose(q);
    }

    /* 2) 解析日志 -> 新命中的搬进拦截日志。
       上一步追加到解析日志的行此时已经落盘，这里读到的是最终内容 */
    FILE *b = qlog_open_dst(g_blog.path, BLOG_HEADER);
    if (b) {
        strset_free(&g_qlog.seen);
        strset_init(&g_qlog.seen);
        snprintf(tmp, sizeof tmp, "%s.tmp", g_qlog.path);
        if (qlog_partition(g_qlog.path, tmp, QLOG_HEADER, 0, b, &g_blog.seen,
                           &g_qlog.seen, &moved_out)) {
            if (rename(tmp, g_qlog.path) != 0) unlink(tmp);
        }
        fclose(b);
    }

    qlog_open_append(&g_qlog);                         /* 重新挂上句柄，顺带刷新字节数 */
    qlog_open_append(&g_blog);
    if (moved_out || moved_back)
        plog("日志重匹配: %zu 条移入拦截记录, %zu 条移回解析记录\n", moved_out, moved_back);
}

/* ---------------- 上游管理 ---------------- */

typedef struct {
    struct sockaddr_storage sa;   /* 载入时端口已是网络序 */
    socklen_t               salen;
    int                     strikes;
    int64_t                 down_until_ms;
} upstream_t;

static upstream_t g_up[MAX_UPSTREAMS];
static int        g_nu;

static const char *up_text(const upstream_t *arr, int i, char *buf, size_t bufsz)
{
    const struct sockaddr *sa = (const struct sockaddr *)&arr[i].sa;
    char host[INET6_ADDRSTRLEN] = {0};
    uint16_t port = 0;
    if (sa->sa_family == AF_INET) {
        inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, host, sizeof host);
        port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
    } else {
        inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr, host, sizeof host);
        port = ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    }
    snprintf(buf, bufsz, "%s#%u", host, port);
    return buf;
}

/* 每行 IPv4/IPv6[ #端口]；'#' 在这里只作端口分隔符，行首 '#' 才是注释。
 * 解析到 dst 而不是直接改全局表，这样重载失败时旧表保持原样。
 * 返回采纳条数；文件打不开返回 -1 */
static int load_upstreams_into(upstream_t *dst, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        plog("无法打开 %s: %s\n", path, strerror(errno));
        return -1;
    }
    int n = 0, bad = 0;
    char line[256];
    while (n < MAX_UPSTREAMS && fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == '\r' || !*s) continue;
        size_t len = strlen(s);
        while (len && isspace((unsigned char)s[len-1])) s[--len] = 0;
        uint16_t port = 53;
        char *h = strchr(s, '#');
        if (h) {
            *h++ = 0;
            char *end = NULL;
            long p = strtol(h, &end, 10);
            if (p <= 0 || p >= 65536 || (end && *end != '\0')) {
                plog("警告: %s 跳过端口写法错误的行 '%s'\n", path, line);
                bad++;
                continue;
            }
            port = (uint16_t)p;
            len = strlen(s);
            while (len && isspace((unsigned char)s[len-1])) s[--len] = 0;
        }
        struct sockaddr_in a4;
        struct sockaddr_in6 a6;
        memset(&a4, 0, sizeof a4);
        memset(&a6, 0, sizeof a6);
        if (inet_pton(AF_INET, s, &a4.sin_addr) == 1) {
            a4.sin_family = AF_INET;
            a4.sin_port = htons(port);                    /* 端口在载入时就转成网络序 */
            memcpy(&dst[n].sa, &a4, sizeof a4);
            dst[n].salen = sizeof a4;
        } else if (inet_pton(AF_INET6, s, &a6.sin6_addr) == 1) {
            a6.sin6_family = AF_INET6;
            a6.sin6_port = htons(port);
            memcpy(&dst[n].sa, &a6, sizeof a6);
            dst[n].salen = sizeof a6;
        } else {
            plog("警告: %s 跳过无法解析的上游 '%s'（需 IP，可带 #端口）\n", path, s);
            bad++;
            continue;
        }
        dst[n].strikes = 0;
        dst[n].down_until_ms = 0;
        n++;
    }
    fclose(f);
    if (bad) plog("警告: %s 有 %d 行格式不正确、已忽略\n", path, bad);
    return n;
}

/* ---------------- 配置热加载（inotify 线程） ----------------
 * 解析到临时表，成功才在锁内整表替换：任何一份文件读失败/全是坏行，
 * 都保留旧表，不会因为一次半截保存就把过滤或上游清空。 */

static void reload_conf(const char *dir)
{
    char path[512];
    dlist_t nb, nw;

    int qlog_was = g_qlog_enabled;
    qlog_sync_enabled();
    if (qlog_was != g_qlog_enabled) plog("记录功能已%s\n", g_qlog_enabled ? "开启" : "关闭");
    dlist_init(&nb);
    dlist_init(&nw);

    snprintf(path, sizeof path, "%s/blocklist.txt", dir);
    int b = dlist_load(&nb, path, 1);
    snprintf(path, sizeof path, "%s/whitelist.txt", dir);
    int w = dlist_load(&nw, path, 0);
    snprintf(path, sizeof path, "%s/upstream.txt", dir);
    upstream_t nup[MAX_UPSTREAMS];
    int u = load_upstreams_into(nup, path);

    int beff, weff, ueff, oldu;
    pthread_mutex_lock(&g_conf_lock);
    oldu = g_nu;
    if (b >= 0) { dlist_free(&g_black); g_black = nb; }
    if (w >= 0) { dlist_free(&g_white); g_white = nw; }
    if (u > 0) { memcpy(g_up, nup, (size_t)u * sizeof nup[0]); g_nu = u; }
    beff = (int)(g_black.exact.used + g_black.wild_used);
    weff = (int)(g_white.exact.used + g_white.wild_used);
    ueff = g_nu;
    pthread_mutex_unlock(&g_conf_lock);

    if (b < 0) dlist_free(&nb);
    if (w < 0) dlist_free(&nw);
    if (u <= 0) plog("警告: 上游配置没有可用条目，保留原来的 %d 个\n", oldu);
    plog("配置已重载: 黑名单 %d 条, 白名单 %d 条, 上游 %d 个\n", beff, weff, ueff);

    /* 名单变了就把两份去重日志按新名单重新分拣（放在表替换之后，不持锁） */
    qlog_reconcile();
}

static int ev_interesting(const char *name)
{
    return name && (!strcmp(name, "blocklist.txt") ||
                    !strcmp(name, "whitelist.txt") ||
                    !strcmp(name, "upstream.txt") ||
                    !strcmp(name, "qlog.off"));
}

static void *conf_watcher(void *arg)
{
    char *dir = (char *)arg;
    int fd = inotify_init1(IN_CLOEXEC);
    if (fd < 0) {
        plog("警告: inotify 初始化失败，配置改动不会实时生效: %s\n", strerror(errno));
        free(dir);
        return NULL;
    }
    if (inotify_add_watch(fd, dir, IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE |
                                     IN_DELETE | IN_ATTRIB) < 0) {
        plog("警告: 监听配置目录 %s 失败: %s，配置改动不会实时生效\n", dir, strerror(errno));
        close(fd);
        free(dir);
        return NULL;
    }
    plog("配置监听已启动: %s（改动实时生效）\n", dir);

    for (;;) {
        char evbuf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t n = read(fd, evbuf, sizeof evbuf);
        if (n < 0) {
            if (errno == EINTR) continue;
            plog("警告: 配置监听读取失败: %s，实时生效停止\n", strerror(errno));
            break;
        }
        if (n == 0) continue;
        int hit = 0;
        for (char *p = evbuf; p < evbuf + n; ) {
            struct inotify_event *ev = (struct inotify_event *)p;
            if (ev->len && ev_interesting(ev->name)) hit = 1;
            p += sizeof(struct inotify_event) + ev->len;
        }
        if (!hit) continue;

        /* 去抖: 编辑器多是「写临时文件 + rename」或连续写几次，
           等安静 150 ms 再重载，避免读到半截文件 */
        struct pollfd pf;
        pf.fd = fd;
        pf.events = POLLIN;
        for (;;) {
            pf.revents = 0;
            if (poll(&pf, 1, 150) <= 0) break;
            if (read(fd, evbuf, sizeof evbuf) <= 0) break;
        }
        reload_conf(dir);
    }
    close(fd);
    free(dir);
    return NULL;
}

/* 在 used 掩码之外挑一个上游: 先避开冷却中的，全在冷却则仍选一个（否则彻底断流） */
static int up_pick_free(uint16_t used)
{
    int64_t now = now_ms();
    for (int i = 0; i < g_nu; i++)
        if (!(used & (uint16_t)(1u << i)) && g_up[i].down_until_ms <= now) return i;
    for (int i = 0; i < g_nu; i++)
        if (!(used & (uint16_t)(1u << i))) return i;
    return -1;
}

static void up_mark_fail(int i)
{
    if (++g_up[i].strikes < UP_DOWN_STRIKES) return;
    g_up[i].strikes = 0;
    g_up[i].down_until_ms = now_ms() + UP_DOWN_COOLDOWN_MS;
    char buf[128];
    plog("上游 %s 连续 %d 次无响应, 冷却 %d s\n",
         up_text(g_up, i, buf, sizeof buf), UP_DOWN_STRIKES, UP_DOWN_COOLDOWN_MS / 1000);
}

static void up_mark_ok(int i)
{
    g_up[i].strikes = 0;
    g_up[i].down_until_ms = 0;
}

/* ---------------- DNS 报文 ---------------- */

/* 域名里的不可打印字节换成 '?'，避免污染日志终端，也不会造出假的分界点 */
static char dns_byte(unsigned char c)
{
    return (c >= 0x21 && c <= 0x7e) ? (char)c : '?';
}

/* 提取查询包第一个问题的域名（可选带回 QTYPE）; 成功返回其长度, 失败 -1。
 * *qtype_out 可为 NULL。QTYPE/QCLASS 页脚用于判「问题段是否完整」 */
static int parse_qname(const uint8_t *pkt, size_t len, char *out, size_t outsz, int *qtype_out)
{
    if (len < 13) return -1;
    if (pkt[2] & 0x80) return -1;             /* QR=1 是应答 */
    if (pkt[4] != 0 || pkt[5] != 1) return -1;/* 只处理单问题查询 */
    size_t off = 12, n = 0;
    for (int depth = 0; depth < 128; depth++) {
        if (off >= len) return -1;
        uint8_t l = pkt[off];
        if (l == 0) { off++; goto terminated; }
        if (l & 0xC0) return -1;              /* 查询里的名字指针非法，不支持 */
        if (off + 1 + l > len) return -1;
        if (n + l + 1 >= outsz) return -1;
        if (n > 0) out[n++] = '.';
        for (uint8_t i = 0; i < l; i++)
            out[n++] = dns_byte(pkt[off + 1 + i]);
        off += 1 + l;
    }
    return -1;                                /* 层数用尽仍无根 label: 畸形 */
terminated:
    if (off + 4 > len) return -1;             /* QTYPE/QCLASS 缺失: 畸形 */
    if (qtype_out) *qtype_out = (pkt[off] << 8) | pkt[off + 1];
    out[n] = 0;
    return n ? (int)n : -1;                   /* 根查询不参与判定 */
}

/* 构造本地应答: 原样复制查询头+问题段, QR=1, RA=1, an/ns/ar 归零, rcode=rc。
 * 成功返回总长, 失败 -1 */
static int build_response(const uint8_t *pkt, size_t plen,
                          uint8_t *resp, size_t respsz, int rcode)
{
    if (plen < 13) return -1;
    if (pkt[4] != 0 || pkt[5] != 1) return -1;
    size_t off = 12;
    for (int depth = 0; depth < 128; depth++) {
        if (off >= plen) return -1;
        uint8_t l = pkt[off];
        if (l & 0xC0) return -1;
        if (l == 0) { off++; goto terminated; }
        if (off + 1 + l > plen) return -1;
        off += 1 + l;
    }
    return -1;
terminated:
    if (off + 4 > plen) return -1;            /* 问题段不完整，绝不能越过 plen 复制 */
    size_t base = off + 4;
    if (base > respsz) return -1;
    memcpy(resp, pkt, base);
    resp[2] = (uint8_t)(0x80 | (pkt[2] & 0x01));   /* QR=1, opcode 归零, RD 回显 */
    resp[3] = (uint8_t)(0x80 | (rcode & 0x0F));    /* RA=1, AD/CD=0 */
    resp[4] = 0; resp[5] = 1;
    resp[6] = 0; resp[7] = 0;
    resp[8] = 0; resp[9] = 0;
    resp[10] = 0; resp[11] = 0;
    return (int)base;
}

/* 地址+端口是否同一个：上游 socket 不 connect，应答来源只能自己比 */
static int same_addr(const struct sockaddr *a, const struct sockaddr *b)
{
    if (a->sa_family != b->sa_family) return 0;
    if (a->sa_family == AF_INET) {
        const struct sockaddr_in *x = (const struct sockaddr_in *)a, *y = (const struct sockaddr_in *)b;
        return x->sin_addr.s_addr == y->sin_addr.s_addr && x->sin_port == y->sin_port;
    }
    const struct sockaddr_in6 *x6 = (const struct sockaddr_in6 *)a, *y6 = (const struct sockaddr_in6 *)b;
    return memcmp(&x6->sin6_addr, &y6->sin6_addr, sizeof x6->sin6_addr) == 0
        && x6->sin6_port == y6->sin6_port;
}

/* ---------------- 在途槽位表 ---------------- */

typedef struct {
    int                     fd;          /* 上游 socket（非阻塞, 已 bind 固定源端口） */
    int                     lfd_idx;     /* 从哪个监听 fd 收到的，回包必须用同一家族 */
    struct sockaddr_storage cli;
    socklen_t               cli_len;
    int64_t                 deadline_ms;
    int                     up_idx;
    struct sockaddr_storage up_sa;       /* 发出时该上游的地址: 重载后仍按它校验应答 */
    socklen_t               up_salen;
    uint16_t                tried;       /* 已试过的上游位图 */
    char                    name[256];   /* 归一化后的查询名（解析记录用） */
    uint8_t                 pkt[MAX_QUERY_STORE];
    size_t                  plen;
    int                     active;
} inflight_t;

static inflight_t g_inflight[MAX_INFLIGHT];
static int        g_lfd[2];
static int        g_nlisten;

static uint8_t qbuf[MAX_RECV];
static uint8_t rbuf[MAX_RECV];
static uint8_t abuf[MAX_RECV];

/* 从收到查询的那个监听套接字回包（家族必须与客户端一致，否则 IPv6 查询收不到应答） */
static void send_reply(int lfd_idx, const void *buf, int len,
                       const struct sockaddr *to, socklen_t tolen, const char *tag)
{
    if (len <= 0) return;
    if (sendto(g_lfd[lfd_idx], buf, (size_t)len, 0, to, tolen) < 0)
        plog("%s 发送失败: %s\n", tag, strerror(errno));
}

static int bind_source(int fd, sa_family_t fam, uint16_t port)
{
    if (fam == AF_INET) {
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        a.sin_addr.s_addr = htonl(INADDR_ANY);
        return bind(fd, (struct sockaddr *)&a, sizeof a);
    }
    struct sockaddr_in6 a6;
    memset(&a6, 0, sizeof a6);
    a6.sin6_family = AF_INET6;
    a6.sin6_port = htons(port);
    return bind(fd, (struct sockaddr *)&a6, sizeof a6);
}

/* 用该槽位的固定源端口把查询发给第 up_idx 个上游; 成功 1 失败 0 */
static int slot_send(int slot, int up_idx)
{
    inflight_t *S = &g_inflight[slot];
    sa_family_t fam = ((const struct sockaddr *)&g_up[up_idx].sa)->sa_family;

    if (S->fd >= 0) { close(S->fd); S->fd = -1; }
    int fd = socket(fam, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) { plog("socket 失败: %s\n", strerror(errno)); return 0; }
    uint16_t sport = (uint16_t)(UP_SPORT_BASE + slot);
    if (bind_source(fd, fam, sport) < 0) {
        plog("绑定源端口 %u 失败: %s（被占用时拒绝透传，否则 iptables 豁免失效会重定向死循环）\n",
             sport, strerror(errno));
        close(fd);
        return 0;
    }
    const struct sockaddr *dst = (const struct sockaddr *)&g_up[up_idx].sa;
    if (sendto(fd, S->pkt, S->plen, 0, dst, g_up[up_idx].salen) < 0) {
        char ub[128];
        plog("发往上游 %s 失败: %s\n", up_text(g_up, up_idx, ub, sizeof ub), strerror(errno));
        close(fd);
        return 0;
    }
    S->fd = fd;
    S->up_sa = g_up[up_idx].sa;             /* 重载后按发出时的地址校验应答 */
    S->up_salen = g_up[up_idx].salen;
    return 1;
}

static void slot_close(int i)
{
    inflight_t *S = &g_inflight[i];
    if (!S->active) return;
    if (S->fd >= 0) close(S->fd);
    S->fd = -1;
    S->active = 0;
}

/* 为透传查询开槽; 无槽/无上游/发送失败返回 -1 */
static int slot_open(const uint8_t *pkt, size_t plen, const char *name,
                     const struct sockaddr_storage *cli,
                     socklen_t cli_len, int lfd_idx)
{
    int slot = -1, up = -1, ok = 0;
    inflight_t *S = NULL;

    pthread_mutex_lock(&g_conf_lock);
    if (g_nu == 0) { pthread_mutex_unlock(&g_conf_lock); return -1; }
    for (int i = 0; i < MAX_INFLIGHT; i++)
        if (!g_inflight[i].active) { slot = i; break; }
    if (slot < 0) { pthread_mutex_unlock(&g_conf_lock); return -1; }

    S = &g_inflight[slot];
    S->fd = -1;
    S->active = 1;
    S->lfd_idx = lfd_idx;
    S->cli = *cli;
    S->cli_len = cli_len;
    memcpy(S->pkt, pkt, plen);
    S->plen = plen;
    S->tried = 0;
    snprintf(S->name, sizeof S->name, "%s", name);

    up = up_pick_free(0);
    ok = (up >= 0) && slot_send(slot, up);
    if (ok) {
        S->up_idx = up;
        S->tried = (uint16_t)(1u << up);
        S->deadline_ms = now_ms() + UPSTREAM_TIMEOUT_MS;
    }
    pthread_mutex_unlock(&g_conf_lock);

    if (!ok) { slot_close(slot); return -1; }
    return slot;
}

/* 当前上游失败: 换未试过的下一个重发，全部试过则回 SERVFAIL 并释放槽位 */
static void slot_failover(int i)
{
    inflight_t *S = &g_inflight[i];
    pthread_mutex_lock(&g_conf_lock);
    /* 配置可能刚被重载成更短的列表；旧索引只在数组范围内才记失败 */
    if (S->up_idx < g_nu) up_mark_fail(S->up_idx);
    for (int guard = 0; guard < g_nu; guard++) {
        int nxt = up_pick_free(S->tried);
        if (nxt < 0) break;
        S->tried = (uint16_t)(S->tried | (uint16_t)(1u << nxt));
        if (slot_send(i, nxt)) {
            S->up_idx = nxt;
            S->deadline_ms = now_ms() + UPSTREAM_TIMEOUT_MS;
            pthread_mutex_unlock(&g_conf_lock);
            return;
        }
    }
    pthread_mutex_unlock(&g_conf_lock);
    int rl = build_response(S->pkt, S->plen, rbuf, sizeof rbuf, RCODE_SERVFAIL);
    send_reply(S->lfd_idx, rbuf, rl, (const struct sockaddr *)&S->cli, S->cli_len, "SERVFAIL");
    qlog_write(S->name, 0);
    slot_close(i);
}

/* 应答合法性: 是应答、事务 ID 与查询一致、确实来自本槽正在等的上游。
 * 槽位 socket 不 connect（部分 OEM 会改写 connected UDP socket 的出口），所以必须自己查源 */
static int resp_ok(const uint8_t *resp, size_t rn, const struct sockaddr *from,
                   const inflight_t *S)
{
    if (rn < 12) return 0;
    if (!(resp[2] & 0x80)) return 0;
    if (memcmp(resp, S->pkt, 2) != 0) return 0;
    return same_addr(from, (const struct sockaddr *)&S->up_sa);
}

/* ---------------- 监听 ---------------- */

static int make_listener(sa_family_t fam)
{
    int fd = socket(fam, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) { plog("socket(%d) 失败: %s\n", fam, strerror(errno)); return -1; }
    int one = 1;
    /* 故意不设 SO_REUSEADDR: UDP 上它会让第二个实例绑到同一个 1053 并静默并存，
       而 stop 只按 PID 文件杀进程，剩下的那个会带着旧名单继续应答。
       不设它，端口被占时 bind 直接失败，由调用方退出，单实例由内核保证 */
    if (fam == AF_INET6)
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    if (fam == AF_INET) {
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons(DNS_PORT);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) {
            plog("绑定 127.0.0.1:%d 失败: %s\n", DNS_PORT, strerror(errno));
            close(fd);
            return -1;
        }
    } else {
        struct sockaddr_in6 a6;
        memset(&a6, 0, sizeof a6);
        a6.sin6_family = AF_INET6;
        a6.sin6_port = htons(DNS_PORT);
        a6.sin6_addr = in6addr_loopback;
        if (bind(fd, (struct sockaddr *)&a6, sizeof a6) < 0) {
            plog("绑定 [::1]:%d 失败: %s\n", DNS_PORT, strerror(errno));
            close(fd);
            return -1;
        }
    }
    return fd;
}

/* ---------------- 主循环: 单线程事件循环 ---------------- */

static int run_server(void)
{
    char confdir[256], path[512];
    setvbuf(stdout, NULL, _IOLBF, 0);
    conf_dir(confdir, sizeof confdir);

    dlist_init(&g_black);
    dlist_init(&g_white);
    snprintf(path, sizeof(path), "%s/blocklist.txt", confdir);
    int nb = dlist_load(&g_black, path, 1);
    snprintf(path, sizeof(path), "%s/whitelist.txt", confdir);
    int nw = dlist_load(&g_white, path, 0);
    if (nb < 0 || nw < 0)
        plog("警告: 名单缺失，服务照常启动但可能不拦截（fail-open，避免整机断 DNS）\n");
    snprintf(path, sizeof(path), "%s/upstream.txt", confdir);
    int nu = load_upstreams_into(g_up, path);
    g_nu = nu > 0 ? nu : 0;
    plog("黑名单 %d 条, 白名单 %d 条, 上游 %d 个%s\n", nb, nw, g_nu,
         g_nu ? "" : "（无，透传将全部 SERVFAIL）");
    qlog_open();
    qlog_reconcile();     /* 上次退出时的名单与现在可能不同，先按当前名单分拣一遍 */

    /* 配置监听线程: 文件保存后自动重载，不需要重启服务 */
    char *wdir = strdup(confdir);
    pthread_t wth;
    if (wdir && pthread_create(&wth, NULL, conf_watcher, wdir) == 0) {
        pthread_detach(wth);
    } else {
        plog("警告: 配置监听线程启动失败，改动不会实时生效\n");
        free(wdir);
    }

    g_nlisten = 0;
    int fd4 = make_listener(AF_INET);
    if (fd4 < 0) {
        plog("127.0.0.1:%d 监听失败（端口已被占用说明已有实例在跑），退出\n", DNS_PORT);
        return 1;
    }
    g_lfd[g_nlisten++] = fd4;
    int fd6 = make_listener(AF_INET6);
    if (fd6 >= 0) g_lfd[g_nlisten++] = fd6;
    if (fd6 < 0) plog("警告: IPv6 监听未就绪，IPv6 侧 DNS 不会被过滤\n");
    plog("监听 127.0.0.1:%d%s, 上游源端口 %u:%u, 并发上限 %d, 单上游超时 %d s\n",
         DNS_PORT, fd6 >= 0 ? " 与 [::1]:1053" : "",
         (unsigned)UP_SPORT_BASE, (unsigned)UP_SPORT_END, MAX_INFLIGHT,
         UPSTREAM_TIMEOUT_MS / 1000);

    for (;;) {
        /* ---- 1) 收新查询（非阻塞排空，每轮限量保证上游应答不被饿死） ---- */
        for (int li = 0; li < g_nlisten; li++) {
            int budget = DRAIN_BUDGET;
            while (budget-- > 0) {
                struct sockaddr_storage cli;
                socklen_t clen = sizeof cli;
                ssize_t n = recvfrom(g_lfd[li], qbuf, sizeof qbuf, 0,
                                     (struct sockaddr *)&cli, &clen);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                    plog("recvfrom 错误: %s\n", strerror(errno));
                    break;
                }
                if ((size_t)n < 12) continue;                    /* 太短，丢弃 */

                char name[256];
                if (parse_qname(qbuf, (size_t)n, name, sizeof name, NULL) < 0) {
                    int rl = build_response(qbuf, (size_t)n, rbuf, sizeof rbuf, RCODE_SERVFAIL);
                    if (rl > 0) {
                        send_reply(li, rbuf, rl, (struct sockaddr *)&cli, clen, "SERVFAIL");
                        plog("畸形查询，已回 SERVFAIL\n");
                    } else {
                        plog("畸形查询（问题段不完整），丢弃\n");   /* 无法回显问题段就不应答 */
                    }
                    continue;                    /* 没解析出域名，解析记录里不留条目 */
                }
                normalize_domain(name);
                if (!*name) continue;                            /* 根查询 */

                pthread_mutex_lock(&g_conf_lock);
                int blocked = filter_pipeline(&g_black, &g_white, name, NULL, NULL);
                pthread_mutex_unlock(&g_conf_lock);
                if (blocked) {
                    /* 拦截: 一律回 NXDOMAIN（含 A），不给 sinkhole 地址，完全不碰上游。
                       回"域名不存在"让客户端直接放弃，避免连 127.0.0.1 被拒后高频重试 */
                    plog("query %-40s -> %s\n", name, verdict_str(1));
                    qlog_write(name, 1);
                    int rl = build_response(qbuf, (size_t)n, rbuf, sizeof rbuf, RCODE_NXDOMAIN);
                    send_reply(li, rbuf, rl, (struct sockaddr *)&cli, clen, "NXDOMAIN");
                    continue;
                }
                plog("query %-40s -> %s\n", name, verdict_str(0));

                if ((size_t)n > MAX_QUERY_STORE) {
                    int rl = build_response(qbuf, (size_t)n, rbuf, sizeof rbuf, RCODE_SERVFAIL);
                    send_reply(li, rbuf, rl, (struct sockaddr *)&cli, clen, "SERVFAIL");
                    plog("查询超过 %d 字节，不转发\n", MAX_QUERY_STORE);
                    qlog_write(name, 0);
                    continue;
                }
                /* 透传: 开一个在途槽等上游 */
                if (slot_open(qbuf, (size_t)n, name, &cli, clen, li) < 0) {
                    int rl = build_response(qbuf, (size_t)n, rbuf, sizeof rbuf, RCODE_SERVFAIL);
                    send_reply(li, rbuf, rl, (struct sockaddr *)&cli, clen, "SERVFAIL");
                    plog("无可用上游或并发已满, SERVFAIL\n");
                    qlog_write(name, 0);
                }
            }
        }

        /* ---- 2) select: 等上游响应/槽位到期/新包 ---- */
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = 0;
        for (int li = 0; li < g_nlisten; li++) {
            FD_SET(g_lfd[li], &rfds);
            if (g_lfd[li] > maxfd) maxfd = g_lfd[li];
        }
        int64_t left = -1, now = now_ms();
        for (int i = 0; i < MAX_INFLIGHT; i++) {
            if (!g_inflight[i].active) continue;
            FD_SET(g_inflight[i].fd, &rfds);
            if (g_inflight[i].fd > maxfd) maxfd = g_inflight[i].fd;
            int64_t w = g_inflight[i].deadline_ms - now;
            if (w < 0) w = 0;
            if (left < 0 || w < left) left = w;
        }
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        if (left >= 0) { tv.tv_sec = (long)(left / 1000); tv.tv_usec = (long)(left % 1000) * 1000; }
        int rc = select(maxfd + 1, &rfds, NULL, NULL, left >= 0 ? &tv : NULL);
        if (rc < 0) {
            if (errno == EINTR) continue;
            plog("select 错误: %s\n", strerror(errno));
            break;
        }

        /* ---- 3) 上游响应到达: 校验后原样回客户端 ---- */
        if (rc > 0) {
            for (int i = 0; i < MAX_INFLIGHT; i++) {
                inflight_t *S = &g_inflight[i];
                if (!S->active || !FD_ISSET(S->fd, &rfds)) continue;
                struct sockaddr_storage from;
                socklen_t fl = sizeof from;
                ssize_t rn = recvfrom(S->fd, abuf, sizeof abuf, 0,
                                      (struct sockaddr *)&from, &fl);
                if (rn < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
                    slot_failover(i);          /* 如 ECONNREFUSED: 这个上游不通，换下一个 */
                    continue;
                }
                if (rn < 12 || !resp_ok(abuf, (size_t)rn, (struct sockaddr *)&from, S)) {
                    /* 空包/短包/ID 或来源不符只表示"这不是本次查询的应答"：
                       槽位必须留着继续等真应答，不能据此判上游故障；
                       日志只打印查询侧 ID，不读接收缓冲区（可能一个字节都没收到） */
                    plog("丢弃非法应答: 槽 %d 收到 %zd 字节，查询 id=%02x%02x\n",
                         i, rn, S->pkt[0], S->pkt[1]);
                    continue;                                       /* 忽略，继续等真正应答 */
                }
                pthread_mutex_lock(&g_conf_lock);
                if (S->up_idx < g_nu) up_mark_ok(S->up_idx);
                pthread_mutex_unlock(&g_conf_lock);
                send_reply(S->lfd_idx, abuf, (int)rn,
                           (const struct sockaddr *)&S->cli, S->cli_len, "透传应答");
                qlog_write(S->name, 0);
                slot_close(i);
            }
        }

        /* ---- 4) 槽位到期: 换未试过的上游重试, 全失败回 SERVFAIL ---- */
        now = now_ms();
        for (int i = 0; i < MAX_INFLIGHT; i++)
            if (g_inflight[i].active && now >= g_inflight[i].deadline_ms)
                slot_failover(i);
    }

    for (int li = 0; li < g_nlisten; li++) close(g_lfd[li]);
    for (int i = 0; i < MAX_INFLIGHT; i++) slot_close(i);
    if (g_qlog.fp) { fclose(g_qlog.fp); g_qlog.fp = NULL; }
    if (g_blog.fp) { fclose(g_blog.fp); g_blog.fp = NULL; }
    if (g_rlog.fp) { fclose(g_rlog.fp); g_rlog.fp = NULL; }
    pthread_mutex_lock(&g_conf_lock);
    dlist_free(&g_black);
    dlist_free(&g_white);
    pthread_mutex_unlock(&g_conf_lock);
    return 0;
}

/* ---------------- test / lists / main ---------------- */

static int run_test(int argc, char **argv)
{
    char confdir[256], path[512];
    conf_dir(confdir, sizeof confdir);
    dlist_t black, white;
    dlist_init(&black);
    dlist_init(&white);
    snprintf(path, sizeof(path), "%s/blocklist.txt", confdir);
    if (dlist_load(&black, path, 1) < 0) return 1;
    snprintf(path, sizeof(path), "%s/whitelist.txt", confdir);
    if (dlist_load(&white, path, 0) < 0) return 1;
    for (int i = 2; i < argc; i++) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s", argv[i]);
        char *e = normalize_domain(buf);
        const char *bh = NULL, *wh = NULL;
        int blocked = filter_pipeline(&black, &white, e, &bh, &wh);
        if (!bh) printf("%-34s %s  黑名单未命中\n", e, verdict_str(blocked));
        else if (!wh) printf("%-34s %s  黑名单命中 '%s'\n", e, verdict_str(blocked), bh);
        else printf("%-34s %s  黑名单 '%s' 被白名单 '%s' 豁免\n", e, verdict_str(blocked), bh, wh);
    }
    dlist_free(&black);
    dlist_free(&white);
    return 0;
}

static int run_lists(void)
{
    char confdir[256], path[512];
    conf_dir(confdir, sizeof confdir);
    dlist_t black, white;
    dlist_init(&black);
    dlist_init(&white);
    snprintf(path, sizeof(path), "%s/blocklist.txt", confdir);
    int nb = dlist_load(&black, path, 1);
    snprintf(path, sizeof(path), "%s/whitelist.txt", confdir);
    int nw = dlist_load(&white, path, 0);
    snprintf(path, sizeof(path), "%s/upstream.txt", confdir);
    upstream_t ups[MAX_UPSTREAMS];
    int nu = load_upstreams_into(ups, path);
    if (nu < 0) nu = 0;
    printf("confdir      : %s\n", confdir);
    printf("blacklist    : %d 条（精确 %zu, 通配符 %zu）\n",
           nb, black.exact.used, black.wild_used);
    printf("whitelist    : %d 条（精确 %zu, 通配符 %zu）\n",
           nw, white.exact.used, white.wild_used);
    printf("upstream     : %d 个\n", nu);
    char ub[128];
    for (int i = 0; i < nu; i++)
        printf("  [%d] %s%s\n", i, up_text(ups, i, ub, sizeof ub),
               ups[i].down_until_ms > now_ms() ? " (冷却中)" : "");
    dlist_free(&black);
    dlist_free(&white);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "用法: %s {serve | test <域名>... | lists}\n"
                "  名单支持通配符: *.test.com / ad*.com / *tracker*\n"
                "  环境变量 DNSFW_CONF 可覆盖配置目录（默认 %s）\n", argv[0], CONFDIR);
        return 1;
    }
    if (strcmp(argv[1], "serve") == 0) return run_server();
    if (strcmp(argv[1], "test") == 0)  return run_test(argc, argv);
    if (strcmp(argv[1], "lists") == 0) return run_lists();
    fprintf(stderr, "未知命令: %s\n", argv[1]);
    return 1;
}
