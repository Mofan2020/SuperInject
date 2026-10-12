/*
 * SuperInject Agent - 被注入的 DLL
 *
 * 目标：在被调试进程内建立一条反向控制通道（回环 TCP，127.0.0.1），
 * 接受 SuperInject 控制器的指令：
 *   ping / info / mem_regions / mem_search / mem_read / mem_write
 *   resources（提取内存里的图片/音频/视频：PE 资源 + 内存映射文件）
 *   terminate（自我结束）/ unload（自行卸载）
 *
 * 注意：冻结由控制器侧用 NtSuspendProcess 完成（挂起全部线程），
 * 这里不做「冻结」——从进程内部挂起自己只会让唯一的工作线程睡死，
 * 既冻结不了目标，也永远回不来。
 *
 * 协议：4 字节小端长度 + UTF-8 JSON（接收端一次读一大块再自己切帧）
 *
 * 连接方式（反向连接：控制器不往目标进程写任何东西）：
 *   1. 控制器把「回环端口 + 一次性令牌」写进
 *      %TEMP%\SuperInject\port-<目标PID>.txt
 *   2. 注入后本 DLL 读该文件，connect 到 127.0.0.1:<端口>
 *   3. 首帧 hello 带上令牌，控制器校验通过才认这条连接
 *
 * 仅供开发人员调试自己的程序使用，禁止用于未授权的第三方进程。
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*
 * MiniDumpWriteDump 在 dbghelp.dll。System32 自带，链接 dbghelp.lib 即可。
 * MSVC 里 ``#pragma comment(lib, ...)`` 由 cl 解释；MinGW 走 -ldbghelp（在
 * build_native.py + .github/workflows 的 cl 命令里都加了）。
 */
#include <dbghelp.h>

#include "superinject_json.h"

/*
 * 两个 Win32 小工具。原先放在 superinject_json.c 里，逼得那一层必须拉
 * windows.h 并链接 advapi32 —— 现在归回 agent.c，JSON 层保持纯 C99，
 * 本机编译器可以直接编译并运行它的自测。
 */
static const char *si_mem_type(DWORD protect)
{
    if (protect & PAGE_GUARD)      return "GUARD";
    if (protect & PAGE_NOACCESS)   return "NOACCESS";
    switch (protect & 0xFF) {
    case PAGE_READONLY:            return "R";
    case PAGE_READWRITE:           return "RW";
    case PAGE_WRITECOPY:           return "WC";
    case PAGE_EXECUTE:             return "X";
    case PAGE_EXECUTE_READ:        return "XR";
    case PAGE_EXECUTE_READWRITE:   return "XRW";
    case PAGE_EXECUTE_WRITECOPY:   return "XWC";
    default:                       return "?";
    }
}

static int si_is_elevated(void)
{
    HANDLE tok = NULL;
    TOKEN_ELEVATION elv;
    DWORD len = 0;
    int elevated = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    if (GetTokenInformation(tok, TokenElevation, &elv, sizeof(elv), &len))
        elevated = elv.TokenIsElevated ? 1 : 0;
    CloseHandle(tok);
    return elevated;
}

#define SI_VERSION "1.3.0"

/* 跨编译器：GCC/Clang 走 __attribute__，MSVC 用空宏（MSVC 没这个关键字，
 * 早先的 si_bp_lookup_*_by_addr 因为带这个 P2 留下的尾巴让 MSVC 直接红）。
 * 这俩函数只在测试桩里被引用过，标记为 unused 只是为了让 -Werror 别误报。 */
#if defined(_MSC_VER)
#  define SI_ATTR_UNUSED
#else
#  define SI_ATTR_UNUSED __attribute__((unused))
#endif

/* 资源导出上限，避免被调试进程里几十万个小文件拖死 */
#define SI_MAX_SEEN          256
#define SI_MAX_RESOURCES     512
#define SI_MAX_MAPPED        64
#define SI_MAX_MAPPED_ITEMS  64
#define SI_MAX_ITEM_BYTES    (64u * 1024u * 1024u)
#define SI_MAX_TOTAL_BYTES   (256u * 1024u * 1024u)
#define SI_MEM_SCAN_CHUNK    (1u << 20)
#define SI_MEM_SCAN_MS       30000u
#define SI_MAPPED_SCAN_MS    20000u
#define SI_READ_BUF          (1u << 20)   /* 接收缓冲：一次读一大块，读满再切帧 */
#define SI_CONNECT_MS        60000u       /* 最多尝试 60 秒连上控制器 */

/* P1 内存快照 / diff —— 4KB 分页 + SHA-256 校验 */
#define SI_SNAP_PAGE         0x1000u      /* 单页 4KB */
#define SI_SNAP_HEAD_BYTES   64           /* 每页保留的最前 64 字节 */
#define SI_SNAP_MAX_PAGES    16384        /* 单次快照最多覆盖 64MB（按页算） */

/*
 * P2 硬件断点 —— DR0-DR3 + VEH 兜底（v1.3.0）
 *
 * x86 单条 debug addr 寄存器（DR0..DR3）只有 4 个槽，DR7 控制位（LE/GE +
 * LEN/RW）决定类型与启用。第 5 条及以上没有硬件槽可用，于是走"进程级 VEH
 * 模拟"：单条 INT3 / 写入 fa 标志位（参见 handle_breakpoint）—— 命中
 * 后从 P2 走不到硬件，但能装而且能 push 事件。文档明确告诉用户：
 *
 *   - 指定 --tid 时用硬件 4 槽（快，无运行时开销）
 *   - 不指定 --tid（默认）按当前实现走 VEH 模拟（命中时通过查
 *     target addr 表确认，未命中继续）
 *
 * 注：v1.2.0 的崩溃转储 VEH（AddVectoredExceptionHandler 1）继续保留，
 * *同一 handler* 内部先按 ExceptionCode 分流：
 *
 *   - EXCEPTION_BREAKPOINT / EXCEPTION_SINGLE_STEP：先看是不是我们模拟的
 *     断点（按 RIP 命中查表），命中 → 装成本次异常（让目标线程被冻结一
 *     下），调 send_breakpoint_event 给控制器推 event:breakpoint，
 *     返回 EXCEPTION_CONTINUE_EXECUTION；
 *   - 其它异常走原崩溃转储路径。
 */
#define SI_BP_MAX_DR_SLOTS    4           /* DR0-DR3 */
#define SI_BP_MAX_VEH         32          /* 进程级 VEH 模拟槽（远超实际需要） */

/*
 * DR7 控制位填法（Intel SDM, Vol. 3B）：
 *   L0..L3 在 DR7 偏 0/2/4/6 bit 0：本地启用（per-thread, SetThreadContext 装）；
 *   G0..G3 在偏 0/2/4/6 bit 1：全局启用（进程级，但需要内核态切换 DR7）；
 *   R/W0..R/W3 在偏 16/20/24/28 的 bit 16-17：0=exec,1=write,2=I/O,3=R/W；
 *   LEN0..LEN3 在偏 16/20/24/28 的 bit 18-19：0=1B,1=2B,2=8B（不支持）,
 *                                                3=4B。
 *
 * 单条断点的控制字段是 DR7 中"局部启用 + RW + LEN 4 位 + 启用 L 标志"。
 */
#define SI_BP_DR7_ENABLE_BIT(slot)   (1u << (2 * (slot)))          /* L0..L3 */
#define SI_BP_DR7_RW_SHIFT(slot)     (16 + 4 * (slot))             /* R/W0..R/W3 */
#define SI_BP_DR7_LEN_SHIFT(slot)    (18 + 4 * (slot))             /* LEN0..LEN3 */

/*
 * RW 编码（DR7 R/W 位）：
 *   0 = instruction fetch (exec)
 *   1 = data write
 *   2 = I/O read/write
 *   3 = data read/write
 *
 * LEN 编码（DR7 LEN 位）：
 *   0 = 1 byte
 *   1 = 2 bytes
 *   2 = 8 bytes
 *   3 = 4 bytes
 *
 * 用户协议里 type 是字符串，controller 会先翻译成数值再下发；这里再做一次
 * 最后的合法性校验，确保非法组合不会装进 DR7（避免说"已装好但根本不会触发"）。
 */
static unsigned char si_dr7_rw_for(int type)
{
    switch (type) {
    case 0:                                          /* exec 1B */
    case 6:                                          /* exec 2B */
    case 7:                                          /* exec 4B */
        return 0;
    case 1:                                          /* read 1B */
    case 3:                                          /* rw 2B */
    case 4:                                          /* rw 4B */
    case 5:                                          /* rw 8B（长度可能 8） */
        return 3;
    case 2:                                          /* write 1B */
        return 1;
    default:
        return 0;                                    /* 默认 exec */
    }
}

static unsigned char si_dr7_len_for(int type, int len)
{
    switch (type) {
    case 6:                                          /* exec 2B */
        return 1;
    case 7:                                          /* exec 4B */
        return 3;
    case 4:                                          /* rw 4B */
        return 3;
    case 5:                                          /* rw 8B */
        return 2;                                    /* 8 字节 len=10b */
    case 3:                                          /* rw 2B */
        return 1;
    default:
        return 0;                                    /* 1B */
    }
    (void)len;                                       /* 已用 type 决定 */
}

typedef struct {
    DWORD  tid;            /* 目标线程；0 = 进程级（VEH 模拟） */
    ULONG_PTR addr;       /* 断点地址 */
    int    type;           /* 见 si_dr7_rw_for */
    int    len;            /* 1 / 2 / 4 / 8 */
    int    slot;           /* DR0-DR3（hw）；-1 = VEH 模拟 */
    int    enabled;
    int    hit_count;
} si_breakpoint_t;

static si_breakpoint_t g_hw_bps   [SI_BP_MAX_DR_SLOTS];
static si_breakpoint_t g_veh_bps  [SI_BP_MAX_VEH];
/* 注：曾经的 g_hw_used 全局计数改用循环求 enabled 数以避免变量漂移。 */

/* 短句柄保护 send_all：VEH 命中时与 worker 线程都调用 send_json，加锁保
 * 险。CriticalSection 在 DllMain 初始化，进程结束 Windows 自己回收。 */
static CRITICAL_SECTION g_send_cs;
static int              g_send_cs_inited = 0;

/*
 * "VEH 模拟"用什么手段实现：当 SLOT 用完或用户希望走整进程命中时，我们
 * 不能在 4 个硬件槽放下更多 bp。两条可行路径：
 *
 *  - INT3 0xCC patch：把 addr 的首字节改成 0xCC，命中时 Eip 在
 *    ExceptionAddress 上会指到这条指令的下一条（=addr+1）。命中后我们
 *    推事件，最后回到原线程。原字节和原保护属性记到 g_veh_bps 里。
 *
 *  - guard page：把 addr 所在的 page 设 PAGE_GUARD，命中时靠
 *    STATUS_GUARD_PAGE。我们走 INT3 路径，因为它不破坏内存布局，
 *    也避开了"目标在 RunByOther 状态"的兼容性陷阱。
 *
 * 单条命中处理：VEH 看到 ExceptionCode == EXCEPTION_BREAKPOINT 且
 * ExceptionAddress 命中 g_veh_bps[*].addr → 推事件，把 addr 的首字节
 * 重写回原值（暂时"单步"过去），单步命中后再把 0xCC 装回去 —— 避免
 * 同一条 INT3 同一执行路径递归。
 *
 * 注意：VEH 模拟的 cont flow 比 hw 慢（一次 INT3 至少两次异常），但只
 * 在 P2 阶段是 fallback；P3 寄存器捕获时不需要"原字节暂存表"作额外
 * 同步，只读 CONTEXT 来填。再说，bp_set 已经把它们和 hit_count 一起
 * 更新，hit 在 VEH handler 内部加锁（同样用 g_send_cs 即可）。
 */
typedef struct {
    ULONG_PTR addr;
    BYTE      orig_byte;       /* 被改成的 0xCC 之前的字节 */
    int       used;            /* 槽是否已用 */
} si_veh_slot_t;

static si_veh_slot_t g_veh_patch[SI_BP_MAX_VEH];

static void si_send_cs_init(void)
{
    if (!g_send_cs_inited) {
        InitializeCriticalSection(&g_send_cs);
        g_send_cs_inited = 1;
    }
}

/* NtQueryVirtualMemory 信息类（等价于 winternl.h 的 MemoryMappedFilenameInformation） */
#define SI_MemoryMappedFilenameInformation 2

typedef LONG(NTAPI *si_NtQueryVirtualMemory_t)(HANDLE, LPCVOID, ULONG,
                                               PVOID, SIZE_T, PSIZE_T);

static HMODULE g_module = NULL;
static SOCKET  g_sock   = INVALID_SOCKET;
static DWORD   g_pid    = 0;
static HANDLE  g_log    = INVALID_HANDLE_VALUE;
static char    g_token[80] = {0};   /* 控制器写入的一次性令牌，hello 时回传 */

/*
 * 诊断日志：%TEMP%\SuperInject\agent-<pid>.log
 * 目标进程无响应时，只有进程内部才知道它卡在哪一步 —— 出问题时
 * 把这份日志和控制器日志放在一起看，能立刻定位（CI 失败时会自动打印）。
 */
static void log_msg(const char *fmt, ...)
{
    char    line[512];
    DWORD   n = 0;
    int     used;
    va_list ap;

    if (g_log == INVALID_HANDLE_VALUE) return;
    used = snprintf(line, sizeof(line), "[%lu] ", (unsigned long)GetTickCount());
    if (used < 0) return;
    va_start(ap, fmt);
    vsnprintf(line + used, sizeof(line) - (size_t)used, fmt, ap);
    va_end(ap);
    {
        size_t len = strlen(line);
        if (len + 2 < sizeof(line)) {
            line[len]     = '\r';
            line[len + 1] = '\n';
            line[len + 2] = 0;
        }
    }
    WriteFile(g_log, line, (DWORD)strlen(line), &n, NULL);
}

static void log_open(void)
{
    WCHAR path[MAX_PATH];
    if (GetTempPathW(MAX_PATH, path) == 0) return;
    lstrcatW(path, L"SuperInject");
    CreateDirectoryW(path, NULL);
    lstrcatW(path, L"\\");
    {
        WCHAR name[64];
        swprintf(name, 64, L"agent-%lu.log", (unsigned long)g_pid);
        lstrcatW(path, name);
    }
    g_log = CreateFileW(path, FILE_APPEND_DATA,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_log == INVALID_HANDLE_VALUE) g_log = 0;
}

/* 资源提取输出目录与状态（仅在命令处理线程内使用） */
static char  g_out_dir[MAX_PATH] = {0};
static int   g_res_seq = 0;
static si_json *g_res_arr = NULL;
static unsigned long long g_total_bytes = 0;

static char  g_seen[SI_MAX_SEEN][MAX_PATH * 2];
static int   g_seen_n = 0;

static void utf8_path(LPCWSTR w, char *out, int outsz)
{
    if (!WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outsz, NULL, NULL))
        out[0] = 0;
}

/* ------------------------- 通道传输 ------------------------- */

static int send_all(const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int w = send(g_sock, buf + sent, (int)(len - sent), 0);
        if (w <= 0) return 0;
        sent += (size_t)w;
    }
    return 1;
}

static int send_json(si_json *j)
{
    char  *text = si_json_dump(j);
    DWORD  n;
    int    ok;
    char  *frame;
    if (!text) {
        log_msg("send_json: dump 返回空");
        return 0;
    }
    n = (DWORD)strlen(text);
    /*
     * 一次 WriteFile 写出「长度+正文」：避免两次写之间被别的写法打断，
     * 也让接收端一次就能拿到完整帧（更容易排查问题）。
     */
    frame = (char *)malloc(n + 4);
    if (!frame) {
        si_free(text);
        log_msg("send_json: 内存不足");
        return 0;
    }
    memcpy(frame, &n, 4);
    memcpy(frame + 4, text, n);
    /* send 可能从 worker（agent_handle）和 VEH 命中线程并发调用，
     * 加锁避免半帧。g_send_cs 在 DllMain 初始化。 */
    if (g_send_cs_inited) EnterCriticalSection(&g_send_cs);
    if (g_sock != INVALID_SOCKET) {
        ok = send_all(frame, (size_t)n + 4);
    } else {
        ok = 0;
    }
    if (g_send_cs_inited) LeaveCriticalSection(&g_send_cs);
    si_free(text);
    free(frame);
    if (!ok) log_msg("send_json: 发送失败 err=%d bytes=%lu",
                     WSAGetLastError(), (unsigned long)(n + 4));
    return ok;
}

/*
 * 接收帧：一次读一大块（1MB）再自己切帧，而不是先读 4 字节长度再读正文。
 * 这样既避免「小缓冲阻塞读」这类坑，也省掉每帧一次系统调用。
 */
static unsigned char *g_rbuf = NULL;
static size_t         g_rlen = 0;
static size_t         g_rpos = 0;

static void recv_reset(void)
{
    g_rlen = 0;
    g_rpos = 0;
}

/* 成功返回 1 并把堆上的 JSON 文本交给 *out（调用方 free）；断开返回 0 */
static int recv_frame(char **out)
{
    *out = NULL;
    if (!g_rbuf) {
        g_rbuf = (unsigned char *)malloc(SI_READ_BUF);
        if (!g_rbuf) return 0;
    }

    for (;;) {
        /* 1) 缓冲里已经攒够一整帧了吗 */
        if (g_rlen - g_rpos >= 4) {
            DWORD len;
            memcpy(&len, g_rbuf + g_rpos, 4);
            if (len == 0 || len > (32u * 1024u * 1024u)) {
                log_msg("帧长度异常 len=%lu，断开", (unsigned long)len);
                return 0;
            }
            if (g_rlen - g_rpos >= 4 + (size_t)len) {
                char *text = (char *)malloc((size_t)len + 1);
                if (!text) return 0;
                memcpy(text, g_rbuf + g_rpos + 4, len);
                text[len] = 0;
                g_rpos += 4 + (size_t)len;
                if (g_rpos == g_rlen) recv_reset();
                *out = text;
                return 1;
            }
        }

        /* 2) 数据不够：残余挪到开头，再整块读一次 */
        if (g_rpos > 0) {
            memmove(g_rbuf, g_rbuf + g_rpos, g_rlen - g_rpos);
            g_rlen -= g_rpos;
            g_rpos = 0;
        }
        if (g_rlen >= SI_READ_BUF) {
            log_msg("单帧超过接收缓冲 %u 字节，断开", (unsigned)SI_READ_BUF);
            return 0;
        }
        {
            int got;
            int want = (int)(SI_READ_BUF - g_rlen);
            got = recv(g_sock, (char *)g_rbuf + g_rlen, want, 0);
            if (got <= 0) {
                log_msg("接收失败 err=%d", WSAGetLastError());
                return 0;
            }
            log_msg("收到 %d 字节（缓冲 %lu/%u）", got,
                    (unsigned long)(g_rlen + (size_t)got), (unsigned)SI_READ_BUF);
            g_rlen += (size_t)got;
        }
    }
}

/* ---------------------- 与控制端建立连接 ---------------------- */

/* 组装 <dir>\SuperInject\port-<本进程PID>.txt；装不下返回 0 */
static int build_port_path(WCHAR *out, size_t cap, const WCHAR *dir)
{
    WCHAR num[32];
    size_t need;

    swprintf(num, 32, L"SuperInject\\port-%lu.txt", (unsigned long)g_pid);
    need = lstrlenW(dir) + lstrlenW(num) + 1;
    if (need > cap) return 0;
    lstrcpynW(out, dir, (int)cap);
    lstrcatW(out, num);
    return 1;
}

/* 读指定路径的会合文件：内容为「<回环端口> <一次性令牌>」 */
static int read_port_at(const WCHAR *path, DWORD *port_out)
{
    HANDLE h;
    char   buf[128];
    DWORD  got = 0;
    unsigned long port;
    char  *sp;

    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    if (!ReadFile(h, buf, sizeof(buf) - 1, &got, NULL)) {
        CloseHandle(h);
        return 0;
    }
    CloseHandle(h);
    buf[got] = 0;

    port = strtoul(buf, NULL, 10);
    if (port == 0 || port > 65535) return 0;
    sp = strchr(buf, ' ');
    if (sp) {
        size_t n;
        sp++;
        while (*sp == ' ') sp++;
        n = strlen(sp);
        while (n > 0 && (sp[n - 1] == '\r' || sp[n - 1] == '\n' || sp[n - 1] == ' ')) n--;
        if (n >= sizeof(g_token)) n = sizeof(g_token) - 1;
        memcpy(g_token, sp, n);
        g_token[n] = 0;
    }
    *port_out = (DWORD)port;
    return 1;
}

/* 文件是否可读（只读探测，不解析内容） */
static int file_readable(const WCHAR *path)
{
    HANDLE h = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    CloseHandle(h);
    return 1;
}

/*
 * 找会合文件。本进程的 TEMP 未必等于控制端的 TEMP：
 *
 * * 同一用户下的普通进程：两边 TEMP 相同，第一条路径就命中；
 * * SYSTEM 服务这类高权限目标：它们的 TEMP 通常是 C:\Windows\Temp，而控制端
 *   （以 SYSTEM 运行时）写在「启动它的那个用户」的 TEMP 里 —— 于是按
 *   C:\Users\*\AppData\Local\Temp\SuperInject 逐个用户目录再找一遍。
 *
 * 只做只读扫描、不额外落盘，所以不会把一次性令牌暴露给别的用户
 * （往 C:\Windows\Temp 这类公共目录写才是真隐患）。
 */
static int find_port_file(WCHAR *path_out, size_t cap)
{
    WCHAR  dir[MAX_PATH];
    WCHAR  roots[MAX_PATH];      /* <SystemDrive>\Users\ ，别写死 C: */
    WCHAR  pat[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hf;
    DWORD  n;

    /* ① 自己的 TEMP */
    if (GetTempPathW(MAX_PATH, dir) != 0 && build_port_path(path_out, cap, dir)) {
        if (file_readable(path_out)) return 1;
    }

    /* ② 各用户的 TEMP（目标是 SYSTEM / 其他用户时） */
    n = GetEnvironmentVariableW(L"SystemDrive", roots, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) lstrcpynW(roots, L"C:", MAX_PATH);
    lstrcatW(roots, L"\\Users\\");
    lstrcpynW(pat, roots, MAX_PATH);
    lstrcatW(pat, L"*");

    hf = FindFirstFileW(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    for (;;) {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            fd.cFileName[0] != L'.') {
            lstrcpynW(dir, roots, MAX_PATH);
            lstrcatW(dir, fd.cFileName);
            lstrcatW(dir, L"\\AppData\\Local\\Temp\\");
            if (build_port_path(path_out, cap, dir) && file_readable(path_out)) {
                FindClose(hf);
                return 1;
            }
        }
        if (!FindNextFileW(hf, &fd)) break;
    }
    FindClose(hf);
    return 0;
}

static int read_port_file(DWORD *port_out)
{
    WCHAR path[MAX_PATH];

    if (!find_port_file(path, MAX_PATH)) return 0;
    if (!read_port_at(path, port_out)) return 0;
    log_msg("会合文件: %ls", path);
    return 1;
}

/* 反向连接：注入端主动连控制器的回环端口 */
static int agent_connect(void)
{
    DWORD    deadline = GetTickCount() + SI_CONNECT_MS;
    WSADATA  wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        log_msg("WSAStartup 失败 err=%d", WSAGetLastError());
        return 0;
    }
    while (GetTickCount() < deadline) {
        DWORD  port = 0;
        SOCKET s;

        if (read_port_file(&port)) {
            struct sockaddr_in a;
            s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s != INVALID_SOCKET) {
                memset(&a, 0, sizeof(a));
                a.sin_family      = AF_INET;
                a.sin_port        = htons((unsigned short)port);
                a.sin_addr.s_addr = htonl(0x7F000001u);   /* 127.0.0.1 */
                if (connect(s, (struct sockaddr *)&a, (int)sizeof(a)) == 0) {
                    g_sock = s;
                    log_msg("已连接控制端 127.0.0.1:%lu sock=%llu",
                            (unsigned long)port, (unsigned long long)s);
                    return 1;
                }
                closesocket(s);
            }
        }
        Sleep(200);
    }
    log_msg("60 秒内未能连上控制端，放弃");
    return 0;
}

static void send_hello(void)
{
    si_json     *j = si_json_new();
    SYSTEM_INFO  sys;
    WCHAR        wpath[MAX_PATH];
    char         mpath[MAX_PATH];

    if (!j) return;
    GetNativeSystemInfo(&sys);
    si_json_set_str(j, "type", "hello");
    si_json_set_int(j, "pid", (long long)g_pid);
    si_json_set_str(j, "version", SI_VERSION);
    si_json_set_int(j, "proto", SI_JSON_PROTO);
    si_json_set_int(j, "arch", sys.wProcessorArchitecture == 9 ? 64 : 32);
    si_json_set_bool(j, "elevated", si_is_elevated());
    GetModuleFileNameW(NULL, wpath, MAX_PATH);
    utf8_path(wpath, mpath, MAX_PATH);
    si_json_set_str(j, "image", mpath);
    si_json_set_str(j, "token", g_token);
    log_msg("发送 hello 版本=%s 镜像=%s 令牌=%s", SI_VERSION, mpath,
            g_token[0] ? "有" : "无");
    log_msg("hello 写入结果=%d", send_json(j));
    si_json_free(j);
}

/* ------------------------- 内存搜索 ------------------------- */

/*
 * 全程用 ReadProcessMemory 读取（而不是直接解引用）：自己进程里也可能有
 * PAGE_GUARD / 已被换出的页，直接读会抛访问违例把目标进程打崩。
 */
static int mem_search(const unsigned char *pat, size_t plen,
                      const unsigned char *mask, size_t max_results,
                      si_json *out)
{
    si_json                 *arr = si_json_new_array();
    MEMORY_BASIC_INFORMATION mbi;
    SYSTEM_INFO              sys;
    unsigned char           *base, *end;
    unsigned char           *buf;
    size_t                   found = 0;
    long long                last_addr = -1;
    DWORD                    deadline;

    if (!arr) return 0;
    buf = (unsigned char *)malloc(SI_MEM_SCAN_CHUNK);
    if (!buf) {
        si_json_set_arr(out, "results", arr);
        si_json_set_int(out, "count", 0);
        si_json_set_bool(out, "ok", 0);
        si_json_set_str(out, "error", "out of memory");
        return 0;
    }

    GetSystemInfo(&sys);
    base = (unsigned char *)sys.lpMinimumApplicationAddress;
    end  = (unsigned char *)sys.lpMaximumApplicationAddress;
    deadline = GetTickCount() + SI_MEM_SCAN_MS;

    while (base < end && found < max_results) {
        size_t region, off = 0;
        int    readable;
        if (GetTickCount() > deadline) break;
        if (VirtualQuery(base, &mbi, sizeof(mbi)) == 0) break;
        region = (size_t)mbi.RegionSize;
        if (region == 0) break;

        readable = (mbi.State == MEM_COMMIT) &&
                   ((mbi.Protect & PAGE_NOACCESS) == 0) &&
                   ((mbi.Protect & PAGE_GUARD) == 0) &&
                   region >= plen;

        while (readable && off < region && found < max_results) {
            size_t want = region - off;
            SIZE_T got = 0;
            size_t i, overlap;
            if (GetTickCount() > deadline) break;
            if (want > SI_MEM_SCAN_CHUNK) want = SI_MEM_SCAN_CHUNK;
            if (!ReadProcessMemory(GetCurrentProcess(), base + off, buf,
                                   want, &got) || got == 0) {
                break;
            }
            for (i = 0; i + plen <= (size_t)got; i++) {
                size_t k = 0;
                long long addr;
                if (mask && mask[0] && buf[i] != pat[0]) continue;
                while (k < plen) {
                    if (mask && mask[k] == 0) { k++; continue; }
                    if (buf[i + k] != pat[k]) break;
                    k++;
                }
                if (k != plen) continue;
                addr = (long long)(uintptr_t)(base + off + i);
                if (addr == last_addr) continue;    /* 跨块重叠造成的重复命中 */
                last_addr = addr;
                {
                    si_json *o = si_json_new();
                    si_json_set_int(o, "address", addr);
                    si_json_set_int(o, "region", (long long)(uintptr_t)mbi.BaseAddress);
                    si_json_set_int(o, "size", (long long)region);
                    si_json_set_int(o, "protect", (long long)mbi.Protect);
                    si_json_set_str(o, "type", si_mem_type(mbi.Protect));
                    si_json_array_push(arr, o);
                }
                if (++found >= max_results) break;
            }
            if (got < want) break;
            overlap = (plen > 1) ? (plen - 1) : 0;
            if (want == SI_MEM_SCAN_CHUNK && region - off > want && overlap < want)
                off += want - overlap;
            else
                off += want;
        }

        base += region;
    }

    free(buf);
    si_json_set_arr(out, "results", arr);
    si_json_set_int(out, "count", (long long)found);
    si_json_set_bool(out, "timeout", GetTickCount() > deadline);
    return (int)found;
}

/* ------------------------- 媒体嗅探 ------------------------- */

static int begins(const unsigned char *p, size_t n, const char *sig, size_t sn)
{
    return n >= sn && memcmp(p, sig, sn) == 0;
}

/*
 * 判断一段内存/资源是不是图片、音频或视频。
 * 命中时返回 1，并给出推荐扩展名与类别（image / video / audio）。
 */
static int sniff_media(const unsigned char *p, size_t n,
                       const char **ext, const char **kind)
{
    size_t i;

    if (n < 4) return 0;

    if (begins(p, n, "\x89PNG\r\n\x1a\n", 8)) { *ext = "png";  *kind = "image"; return 1; }
    if (n >= 3 && p[0] == 0xFF && p[1] == 0xD8 && p[2] == 0xFF) {
        *ext = "jpg"; *kind = "image"; return 1;
    }
    if (begins(p, n, "GIF87a", 6) || begins(p, n, "GIF89a", 6)) {
        *ext = "gif"; *kind = "image"; return 1;
    }
    if (p[0] == 'B' && p[1] == 'M') { *ext = "bmp"; *kind = "image"; return 1; }
    if (begins(p, n, "\x00\x00\x01\x00", 4)) { *ext = "ico"; *kind = "image"; return 1; }
    if (begins(p, n, "II*\x00", 4) || begins(p, n, "MM\x00*", 4)) {
        *ext = "tif"; *kind = "image"; return 1;
    }

    if (begins(p, n, "RIFF", 4) && n >= 12) {
        const unsigned char *sub = p + 8;
        if (memcmp(sub, "WAVE", 4) == 0) { *ext = "wav";  *kind = "audio"; return 1; }
        if (memcmp(sub, "AVI ", 4) == 0) { *ext = "avi";  *kind = "video"; return 1; }
        if (memcmp(sub, "WEBP", 4) == 0) { *ext = "webp"; *kind = "image"; return 1; }
    }

    if (begins(p, n, "ftyp", 4) && n >= 12) {
        const unsigned char *brand = p + 4;
        if (memcmp(brand, "M4A ", 4) == 0 || memcmp(brand, "M4B ", 4) == 0) {
            *ext = "m4a"; *kind = "audio"; return 1;
        }
        if (memcmp(brand, "qt  ", 4) == 0) { *ext = "mov"; *kind = "video"; return 1; }
        if (memcmp(brand, "avif", 4) == 0) { *ext = "avif"; *kind = "image"; return 1; }
        if (memcmp(brand, "heic", 4) == 0 || memcmp(brand, "heix", 4) == 0) {
            *ext = "heic"; *kind = "image"; return 1;
        }
        *ext = "mp4"; *kind = "video"; return 1;
    }

    if (begins(p, n, "OggS", 4)) { *ext = "ogg";  *kind = "audio"; return 1; }
    if (begins(p, n, "fLaC", 4)) { *ext = "flac"; *kind = "audio"; return 1; }
    if (begins(p, n, "ID3", 3))  { *ext = "mp3";  *kind = "audio"; return 1; }
    if (begins(p, n, "MThd", 4)) { *ext = "mid";  *kind = "audio"; return 1; }
    if (begins(p, n, "\x1a\x45\xdf\xa3", 4)) { *ext = "mkv"; *kind = "video"; return 1; }
    if (begins(p, n, "FLV\x01", 4)) { *ext = "flv"; *kind = "video"; return 1; }
    if (begins(p, n, "\x30\x26\xB2\x75\x8E\x66\xCF\x11", 8)) {
        *ext = "wmv"; *kind = "video"; return 1;
    }
    if (p[0] == 0xFF && (p[1] & 0xE0) == 0xE0) { *ext = "mp3"; *kind = "audio"; return 1; }

    /* SVG 是纯文本，扫一下开头即可 */
    for (i = 0; i + 4 < n && i < 256; i++) {
        if (memcmp(p + i, "<svg", 4) == 0) { *ext = "svg"; *kind = "image"; return 1; }
    }
    return 0;
}

/* ------------------------- 资源导出 ------------------------- */

static int seen_before(const char *origin)
{
    int i;
    for (i = 0; i < g_seen_n; i++) {
        if (_stricmp(g_seen[i], origin) == 0) return 1;
    }
    if (g_seen_n < SI_MAX_SEEN) {
        size_t n = strlen(origin);
        if (n > sizeof(g_seen[0]) - 1) n = sizeof(g_seen[0]) - 1;
        memcpy(g_seen[g_seen_n], origin, n);
        g_seen[g_seen_n][n] = 0;
        g_seen_n++;
    }
    return 0;
}

static void make_dirs(WCHAR *path)
{
    WCHAR *p;
    for (p = path; *p; p++) {
        if (*p == L'\\' && p > path + 2) {
            *p = 0;
            CreateDirectoryW(path, NULL);
            *p = L'\\';
        }
    }
    CreateDirectoryW(path, NULL);
}

static void push_item(si_json *arr, const char *path, const char *origin,
                      const char *ext, const char *kind, unsigned long long size,
                      const char *source, int rtype, int truncated,
                      const char *module)
{
    si_json *o = si_json_new();
    if (!o) return;
    si_json_set_str(o, "path", path);
    si_json_set_str(o, "origin", origin ? origin : path);
    si_json_set_str(o, "ext", ext);
    si_json_set_str(o, "kind", kind);
    si_json_set_int(o, "size", (long long)size);
    si_json_set_str(o, "source", source);
    si_json_set_int(o, "rtype", (long long)rtype);
    si_json_set_bool(o, "truncated", truncated);
    si_json_set_str(o, "module", module ? module : "");
    si_json_array_push(arr, o);
}

static int write_buffer(const char *path, const void *data, size_t size)
{
    HANDLE f;
    DWORD  written = 0;
    int    ok = 0;
    f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    if (size == 0) {
        ok = 1;
    } else if (WriteFile(f, data, (DWORD)size, &written, NULL) && written == size) {
        ok = 1;
    }
    CloseHandle(f);
    return ok;
}

/* 从内存里把一段数据抄出来（用于内存映射文件） */
static int dump_region_mem(const unsigned char *addr, size_t size,
                           const char *path, int *truncated)
{
    HANDLE f;
    unsigned char *buf;
    size_t off = 0;
    int ok = 1;
    DWORD written;

    if ((unsigned long long)size > SI_MAX_ITEM_BYTES) {
        size = (size_t)SI_MAX_ITEM_BYTES;
        *truncated = 1;
    }
    if (g_total_bytes + size > SI_MAX_TOTAL_BYTES) {
        size_t room = (size_t)(SI_MAX_TOTAL_BYTES - g_total_bytes);
        if (room == 0) return 0;
        size = room;
        *truncated = 1;
    }

    buf = (unsigned char *)malloc(SI_MEM_SCAN_CHUNK);
    if (!buf) return 0;
    f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        free(buf);
        return 0;
    }
    while (off < size) {
        size_t want = size - off;
        SIZE_T got = 0;
        if (want > SI_MEM_SCAN_CHUNK) want = SI_MEM_SCAN_CHUNK;
        if (!ReadProcessMemory(GetCurrentProcess(), addr + off, buf, want, &got)
            || got == 0) {
            ok = 0;
            *truncated = 1;
            break;
        }
        if (!WriteFile(f, buf, (DWORD)got, &written, NULL) || written != got) {
            ok = 0;
            break;
        }
        off += got;
    }
    CloseHandle(f);
    free(buf);
    if (ok) g_total_bytes += off;
    return ok && off > 0;
}

/* PE 资源回调：图片/音视频资源导出，DIB 类资源交给控制器转成 BMP/ICO */
typedef struct {
    si_json    *arr;
    int         count;
} res_ctx;

static BOOL CALLBACK res_name_cb(HMODULE mod, LPCWSTR type, LPWSTR name, LONG_PTR lp)
{
    res_ctx        *ctx = (res_ctx *)lp;
    HRSRC           hres;
    DWORD           size;
    HGLOBAL         hglob;
    const unsigned char *ptr;
    const char     *ext = NULL;
    const char     *kind = NULL;
    WORD            rtype;
    char            path[MAX_PATH * 2];
    char            origin[MAX_PATH * 2];
    WCHAR           wmod[MAX_PATH];

    hres = FindResourceW(mod, name, type);
    if (!hres) return TRUE;
    size = SizeofResource(mod, hres);
    if (size == 0 || size > SI_MAX_ITEM_BYTES) return TRUE;
    hglob = LoadResource(mod, hres);
    if (!hglob) return TRUE;
    ptr = (const unsigned char *)LockResource(hglob);
    if (!ptr) {
        FreeResource(hglob);
        return TRUE;
    }

    rtype = IS_INTRESOURCE(type) ? (WORD)(uintptr_t)type : 0;
    if (!GetModuleFileNameW(mod, wmod, MAX_PATH)) {
        FreeResource(hglob);
        return TRUE;
    }
    utf8_path(wmod, origin, MAX_PATH * 2);

    if (rtype == 2 || rtype == 3 || rtype == 1) {
        /* RT_BITMAP / RT_ICON / RT_CURSOR：裸 DIB，控制器补文件头 */
        snprintf(path, sizeof(path), "%s\\res_%lu_%d.dib",
                 g_out_dir, g_pid, ++g_res_seq);
        if (write_buffer(path, ptr, size)) {
            push_item(ctx->arr, path, origin, "dib", "image", size,
                      "resource", rtype, 0, origin);
            ctx->count++;
        }
    } else if (sniff_media(ptr, size, &ext, &kind)) {
        snprintf(path, sizeof(path), "%s\\res_%lu_%d.%s",
                 g_out_dir, g_pid, ++g_res_seq, ext);
        if (write_buffer(path, ptr, size)) {
            push_item(ctx->arr, path, origin, ext, kind, size,
                      "resource", rtype, 0, origin);
            ctx->count++;
        }
    }

    FreeResource(hglob);
    return TRUE;
}

static BOOL CALLBACK res_type_cb(HMODULE mod, LPWSTR type, LONG_PTR lp)
{
    EnumResourceNamesW(mod, type, res_name_cb, lp);
    return TRUE;
}

static int dump_module_resources(si_json *arr, int budget)
{
    res_ctx ctx;
    HANDLE  snap;
    MODULEENTRY32W me;

    if (budget <= 0) return 0;
    ctx.arr = arr;
    ctx.count = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            HMODULE mod = (HMODULE)me.modBaseAddr;
            if (mod) EnumResourceTypesW(mod, res_type_cb, (LONG_PTR)&ctx);
            if (ctx.count >= budget) break;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return ctx.count;
}

/* ------------------------- 内存映射文件扫描 ------------------------- */

typedef struct {
    WCHAR dev[64];
    WCHAR dos[8];
} drive_map_t;

static drive_map_t g_drives[32];
static int         g_drive_n = 0;

static void build_drive_map(void)
{
    DWORD mask;
    int   i;
    g_drive_n = 0;
    mask = GetLogicalDrives();
    for (i = 0; i < 26 && g_drive_n < 32; i++) {
        WCHAR letter[4];
        WCHAR target[512];
        if ((mask & (1u << i)) == 0) continue;
        letter[0] = (WCHAR)(L'A' + i);
        letter[1] = L':';
        letter[2] = 0;
        if (QueryDosDeviceW(letter, target, 512) == 0) continue;
        wcsncpy(g_drives[g_drive_n].dev, target, 63);
        g_drives[g_drive_n].dev[63] = 0;
        wcsncpy(g_drives[g_drive_n].dos, letter, 7);
        g_drives[g_drive_n].dos[7] = 0;
        g_drive_n++;
    }
}

/* \Device\HarddiskVolume3\a\b.png -> C:\a\b.png */
static int device_to_dos(const WCHAR *in, WCHAR *out, int outsz)
{
    int i;
    for (i = 0; i < g_drive_n; i++) {
        size_t dl = wcslen(g_drives[i].dev);
        if (_wcsnicmp(in, g_drives[i].dev, dl) == 0) {
            _snwprintf(out, (size_t)outsz, L"%s%s", g_drives[i].dos, in + dl);
            out[outsz - 1] = 0;
            return 1;
        }
    }
    wcsncpy(out, in, (size_t)outsz - 1);
    out[outsz - 1] = 0;
    return 0;
}

static const char *ext_of_w(const WCHAR *path)
{
    const WCHAR *dot = wcsrchr(path, L'.');
    static char  buf[16];
    int i;
    if (!dot || wcslen(dot) > 12) return "";
    for (i = 0; dot[i] && i < 15; i++)
        buf[i] = (char)towlower(dot[i + 1]);
    buf[i] = 0;
    return buf;
}

static int ext_is_media(const char *ext)
{
    static const char *known[] = {
        "png", "jpg", "jpeg", "gif", "bmp", "webp", "ico", "cur", "tif", "tiff",
        "avif", "heic", "svg", "mp4", "m4v", "avi", "mkv", "mov", "webm", "wmv",
        "flv", "mpg", "mpeg", "ts", "wav", "mp3", "ogg", "oga", "flac", "m4a",
        "aac", "mid", "midi", "opus", "wma",
    };
    size_t i;
    for (i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        if (_stricmp(ext, known[i]) == 0) return 1;
    }
    return 0;
}

static int scan_mapped_media(si_json *arr, int *scanned, int *truncated)
{
    si_NtQueryVirtualMemory_t query;
    SYSTEM_INFO sys;
    unsigned char *base, *end;
    DWORD deadline = GetTickCount() + SI_MAPPED_SCAN_MS;
    int   count = 0;

    {
        FARPROC proc = GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                      "NtQueryVirtualMemory");
        if (!proc) return 0;
        memcpy(&query, &proc, sizeof(query));   /* 规避函数指针转换告警 */
    }
    if (!query) return 0;

    build_drive_map();
    GetSystemInfo(&sys);
    base = (unsigned char *)sys.lpMinimumApplicationAddress;
    end  = (unsigned char *)sys.lpMaximumApplicationAddress;

    while (base < end && count < SI_MAX_MAPPED_ITEMS) {
        MEMORY_BASIC_INFORMATION mbi;
        size_t region;
        if (GetTickCount() > deadline) { *truncated = 1; break; }
        if (VirtualQuery(base, &mbi, sizeof(mbi)) == 0) break;
        region = (size_t)mbi.RegionSize;
        if (region == 0) break;
        *scanned += 1;

        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_MAPPED &&
            (mbi.Protect & PAGE_NOACCESS) == 0 &&
            (mbi.Protect & PAGE_GUARD) == 0 &&
            region > 8) {
            unsigned char infobuf[2048];
            SIZE_T        ret = 0;
            if (query(GetCurrentProcess(), mbi.BaseAddress,
                      SI_MemoryMappedFilenameInformation,
                      infobuf, sizeof(infobuf), &ret) >= 0) {
                /* 手工解析 UNICODE_STRING：x64 下 Buffer 指针在偏移 8，x86 在 4 */
                USHORT   len  = *(USHORT *)infobuf;
                size_t   poff = (sizeof(void *) == 8) ? 8 : 4;
                WCHAR   *name = *(WCHAR **)(infobuf + poff);
                WCHAR    dos[MAX_PATH * 2];
                char     origin[MAX_PATH * 2];
                char     path[MAX_PATH * 2];
                char     ext_buf[MAX_PATH * 2];
                char     ext_small[16];
                const char *ext = NULL;
                const char *kind = NULL;
                int        is_media = 0;
                unsigned char probe[512];
                SIZE_T     got_probe = 0;

                if (!name || len == 0 || len / sizeof(WCHAR) >= MAX_PATH * 2) {
                    base += region;
                    continue;
                }
                {
                    size_t chars = len / sizeof(WCHAR);
                    WCHAR  tmp[MAX_PATH * 2];
                    if (chars >= MAX_PATH * 2) chars = MAX_PATH * 2 - 1;
                    memcpy(tmp, name, chars * sizeof(WCHAR));
                    tmp[chars] = 0;
                    device_to_dos(tmp, dos, MAX_PATH * 2);
                }
                utf8_path(dos, origin, MAX_PATH * 2);

                {
                    const char *e = ext_of_w(dos);
                    strncpy(ext_buf, e, sizeof(ext_buf) - 1);
                    ext_buf[sizeof(ext_buf) - 1] = 0;
                    is_media = ext_is_media(ext_buf);
                }

                if (ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress,
                                      probe, sizeof(probe), &got_probe) && got_probe) {
                    if (sniff_media(probe, (size_t)got_probe, &ext, &kind))
                        is_media = 1;
                }

                if (is_media && !seen_before(origin)) {
                    int truncated_item = 0;
                    const char *chosen = (!ext || !ext[0]) ? "bin" : ext;
                    size_t      cl = strlen(chosen);
                    if (cl > sizeof(ext_small) - 1) cl = sizeof(ext_small) - 1;
                    memcpy(ext_small, chosen, cl);
                    ext_small[cl] = 0;
                    ext = ext_small;
                    if (!kind) kind = "other";
                    snprintf(path, sizeof(path), "%s\\map_%lu_%d.%s",
                             g_out_dir, g_pid, ++g_res_seq, ext);
                    if (dump_region_mem((const unsigned char *)mbi.BaseAddress,
                                        region, path, &truncated_item)) {
                        push_item(arr, path, origin, ext, kind, region,
                                  "mapped", 0, truncated_item, "");
                        count++;
                    }
                }
            }
        }

        base += region;
    }
    return count;
}

static int dump_resources(si_json *out)
{
    WCHAR tmp[MAX_PATH];
    int   res_items, mapped_items = 0, scanned = 0, truncated = 0;

    if (GetTempPathW(MAX_PATH, tmp) == 0) return 0;
    {
        WCHAR sub[64];
        swprintf(sub, 64, L"SuperInject\\%lu", g_pid);
        lstrcatW(tmp, sub);
    }
    make_dirs(tmp);
    utf8_path(tmp, g_out_dir, MAX_PATH);

    g_res_seq = 0;
    g_seen_n = 0;
    g_total_bytes = 0;
    g_res_arr = si_json_new_array();
    if (!g_res_arr) return 0;

    res_items = dump_module_resources(g_res_arr, SI_MAX_RESOURCES);
    mapped_items = scan_mapped_media(g_res_arr, &scanned, &truncated);

    si_json_set_arr(out, "items", g_res_arr);
    g_res_arr = NULL;
    si_json_set_str(out, "dir", g_out_dir);
    si_json_set_int(out, "count", (long long)(res_items + mapped_items));
    si_json_set_int(out, "resource_count", (long long)res_items);
    si_json_set_int(out, "mapped_count", (long long)mapped_items);
    si_json_set_int(out, "mapped_regions_scanned", (long long)scanned);
    si_json_set_bool(out, "truncated", truncated);
    return res_items + mapped_items;
}

/*
 * 写入目标内存：先直接写，失败再按当前页属性临时改保护重试（改完立刻还原）。
 *
 * 两个坑（CI 上真实踩到过，报错信息都写进去了）：
 *   1. 新保护属性要按当前页属性选：可执行页给 PAGE_EXECUTE_READWRITE，
 *      否则给 PAGE_READWRITE；
 *   2. 范围必须整页对齐。只请求 1 字节时，若地址贴近区域末尾，
 *      VirtualProtect 会跨到未提交页并直接 ERROR_INVALID_PARAMETER(0x57)，
 *      看起来像「地址非法」，其实只是范围算错了。
 */
static int mem_write_bytes(void *target, const unsigned char *bytes, size_t n,
                           int *patched_out, char *err, size_t errsz)
{
    SIZE_T                   put = 0;
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    old_prot = 0, new_prot = PAGE_READWRITE, tmp = 0;
    SIZE_T                   span;
    uintptr_t                page, tail;
    char                     why[64];

    *patched_out = 0;
    if (WriteProcessMemory(GetCurrentProcess(), target, bytes, n, &put) && put == n)
        return 1;

    snprintf(why, sizeof(why), "WriteProcessMemory 失败 (0x%lX)",
             (unsigned long)GetLastError());
    if (VirtualQuery(target, &mbi, sizeof(mbi)) == 0) {
        snprintf(err, errsz, "%s；VirtualQuery 也失败", why);
        return 0;
    }
    if (mbi.State != MEM_COMMIT) {
        snprintf(err, errsz, "%s；目标地址未提交 (State=0x%lX)",
                 why, (unsigned long)mbi.State);
        return 0;
    }
    if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        new_prot = PAGE_EXECUTE_READWRITE;

    page = (uintptr_t)target & ~(uintptr_t)0xFFF;
    tail = (uintptr_t)target + (uintptr_t)n;
    span = (SIZE_T)(((tail + 0xFFF) & ~(uintptr_t)0xFFF) - page);
    if (span == 0) span = 0x1000;

    if (!VirtualProtect((LPVOID)page, span, new_prot, &old_prot)) {
        snprintf(err, errsz,
                 "%s；VirtualProtect(0x%llX, 0x%llX 字节, 0x%lX) 失败 (0x%lX) "
                 "[区域 Protect=0x%lX Type=0x%lX]",
                 why, (unsigned long long)page, (unsigned long long)span,
                 (unsigned long)new_prot, (unsigned long)GetLastError(),
                 (unsigned long)mbi.Protect, (unsigned long)mbi.Type);
        return 0;
    }
    put = 0;
    if (!WriteProcessMemory(GetCurrentProcess(), target, bytes, n, &put) || put != n) {
        snprintf(err, errsz, "%s；改保护后可写但仍失败 (0x%lX)",
                 why, (unsigned long)GetLastError());
        VirtualProtect((LPVOID)page, span, old_prot, &tmp);
        return 0;
    }
    *patched_out = 1;
    FlushInstructionCache(GetCurrentProcess(), target, n);
    VirtualProtect((LPVOID)page, span, old_prot, &tmp);
    return 1;
}

/* ------------------------- 崩溃转储 ------------------------- */

/*
 * 目标进程崩溃时，自动把堆栈落盘到 %TEMP%\SuperInject\<pid>\dump-<tick>.dmp，
 * 同时写一份 .json sidecar 记录 reason / code / address / tid / 时间戳，便于
 * 控制端侧扫到后回放到事件队列：
 *
 *   %TEMP%\SuperInject\<pid>\dump-12345.dmp
 *   %TEMP%\SuperInject\<pid>\dump-12345.dmp.json
 *
 * 协议上不需要 DLL 在崩溃后还能回话 —— 控制器会监听 on_detach，主动扫目录
 * 把新文件转成 ``event:crash`` 推给上层（见 superinject/controller.py）。
 * 因此这里的捕获要求是：
 *
 *   1. 写盘成功率高（DLL 卡死场景，写盘不能在加载器锁里）；
 *   2. 进程退出时尽量让系统在文件中看到完整 minidump；
 *   3. 不依赖 socket / 不重新发任何控制消息（已挂进程可能都连不上）。
 *
 * 用 VEH + SEH 双层覆盖：VEH 比 SEH 早被通知，能在栈溢出 / 内层已 SEH 被吃
 * 时也拿到；命中后写完盘 + TerminateProcess 自杀（让 Windows 显示"已停止
 * 工作"对话框，跳过最终异常 handler，因为我们的 handler 已经代表它把信息留住了）。
 */

static LPTOP_LEVEL_EXCEPTION_FILTER g_prev_seh = NULL;
static PVOID                       g_veh        = NULL;

static const char *si_exception_name(DWORD code)
{
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:    return "ACCESS_VIOLATION";
    case EXCEPTION_STACK_OVERFLOW:      return "STACK_OVERFLOW";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "ILLEGAL_INSTRUCTION";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:  return "DIVIDE_BY_ZERO";
    case EXCEPTION_BREAKPOINT:          return "BREAKPOINT";
    case EXCEPTION_GUARD_PAGE:          return "GUARD_PAGE";
    case EXCEPTION_PRIV_INSTRUCTION:    return "PRIV_INSTRUCTION";
    case EXCEPTION_INVALID_HANDLE:      return "INVALID_HANDLE";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "NONCONTINUABLE";
    default:                            return "EXCEPTION";
    }
}

/* 写 %TEMP%\SuperInject\<pid>\dump-<tick>.dmp + 同名 .json sidecar。返回 0 失败 1 成功。*/
static int write_dump_with_meta(EXCEPTION_POINTERS *ep)
{
    WCHAR           tmp[MAX_PATH];
    WCHAR           dir[MAX_PATH];
    WCHAR           dmp[MAX_PATH];
    WCHAR           sidecar[MAX_PATH];
    DWORD           tick = GetTickCount();
    HANDLE          file = INVALID_HANDLE_VALUE;
    BOOL            ok = FALSE;
    char            buf[512];
    int             n;
    FILE           *fp = NULL;

    if (GetTempPathW(MAX_PATH, tmp) == 0) return 0;
    lstrcpynW(dir, tmp, MAX_PATH);
    {
        WCHAR sub[64];
        swprintf(sub, 64, L"SuperInject\\%lu", (unsigned long)g_pid);
        lstrcatW(dir, sub);
    }
    make_dirs(dir);

    lstrcpynW(dmp, dir, MAX_PATH);
    swprintf(dmp + lstrlenW(dmp), MAX_PATH - lstrlenW(dmp),
             L"\\dump-%lu.dmp", (unsigned long)tick);
    lstrcpynW(sidecar, dmp, MAX_PATH);
    lstrcatW(sidecar, L".json");

    file = CreateFileW(dmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    /* DbgHelp.dll 已通过链接隐式加载；同时显式 LoadLibrary 一次以保留引用计数，
     * 否则某些极简进程（如 loadlibrary 测试样例）会在 DllMain 里碰不到 dbghelp。 */
    {
        HMODULE h = LoadLibraryW(L"dbghelp.dll");
        if (h) {
            typedef BOOL (WINAPI *MiniDumpWriteDump_t)(
                HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
                PMINIDUMP_EXCEPTION_INFORMATION,
                PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);
            MiniDumpWriteDump_t fn = (MiniDumpWriteDump_t)
                GetProcAddress(h, "MiniDumpWriteDump");
            if (fn) {
                MINIDUMP_EXCEPTION_INFORMATION mei;
                MINIDUMP_TYPE                  dump_type;
                mei.ThreadId          = GetCurrentThreadId();
                mei.ExceptionPointers = ep;
                mei.ClientPointers    = FALSE;
                dump_type = (MINIDUMP_TYPE)(MiniDumpWithIndirectlyReferencedMemory
                                            | MiniDumpWithThreadInfo);
                ok = fn(GetCurrentProcess(), g_pid, file,
                        dump_type, &mei, NULL, NULL) ? TRUE : FALSE;
            }
            FreeLibrary(h);
        }
    }
    CloseHandle(file);
    if (!ok) {
        DeleteFileW(dmp);
        return 0;
    }

    /* sidecar 用 UTF-8 写（与 .dmp 文件名同名加 .json）。 */
    {
        char  dmp_utf8[MAX_PATH];
        char  sidecar_utf8[MAX_PATH * 2];
        utf8_path(dmp, dmp_utf8, MAX_PATH);
        snprintf(sidecar_utf8, sizeof(sidecar_utf8), "%s.json", dmp_utf8);
        fp = fopen(sidecar_utf8, "w");
    }
    if (fp) {
        const char *reason = si_exception_name(ep ? ep->ExceptionRecord->ExceptionCode : 0);
        DWORD code   = ep ? ep->ExceptionRecord->ExceptionCode : 0;
        ULONG64 addr = ep ? (ULONG64)(ULONG_PTR)ep->ExceptionRecord->ExceptionAddress : 0;
        DWORD flags  = ep ? ep->ExceptionRecord->ExceptionFlags : 0;
        DWORD tid    = GetCurrentThreadId();
        DWORD pid    = g_pid;
        n = snprintf(buf, sizeof(buf),
                     "{\"pid\":%lu,\"tid\":%lu,\"reason\":\"%s\","
                     "\"code\":%lu,\"address\":\"0x%llX\",\"flags\":%lu,"
                     "\"tick\":%lu,\"dump\":\"%s\"}\n",
                     (unsigned long)pid, (unsigned long)tid, reason,
                     (unsigned long)code,
                     (unsigned long long)addr,
                     (unsigned long)flags,
                     (unsigned long)tick,
                     "<dump>; controller finds this file by basename>");
        (void)n;  /* sidecar 仅记录元数据，控制器侧以 sidecar 为准 */
        fputs(buf, fp);
        fclose(fp);
    } else {
        /* 写 sidecar 失败但 dump 写好了 —— 控制器会按文件名兜底补一份元数据。 */
    }

    log_msg("崩溃已写盘: %ls reason=%s code=0x%lX",
            dmp, si_exception_name(ep ? ep->ExceptionRecord->ExceptionCode : 0),
            ep ? (unsigned long)ep->ExceptionRecord->ExceptionCode : 0UL);
    return 1;
}

/* 只过滤异常来自我们"内部无害"的几个 code，否则一律视为真崩溃。*/
static int si_should_capture(EXCEPTION_POINTERS *ep)
{
    if (!ep || !ep->ExceptionRecord) return 1;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    /* 调试器主动 INT3（我们自己也没在用，挡住） */
    if (code == EXCEPTION_BREAKPOINT) return 0;
    /* RaiseException(EXCEPTION_NONCONTINUABLE) 这类标记位，不是真崩溃。*/
    if (ep->ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) return 0;
    return 1;
}

/*
 * P2 硬件断点 —— VEH 流程集成。
 *
 * v1.2.0 的 crash handler 在 VEH 先看 si_should_capture：EXCEPTION_BREAKPOINT
 * 被当成"我们自己没用过"挡掉。P2 引入后这条不再合适 — — 我们 install 的 VEH
 * 模拟断点就是 EXCEPTION_BREAKPOINT 信号。所以我们 *不让 si_should_capture 改*
 * ，而是在 VEH handler 的入口先做一次匹配：ExceptionRecord->ExceptionAddress
 * 是否在我们的 VEH 模拟表里。命中 → 走 bp 路径，**不再**走到
 * si_should_capture/崩溃转储。
 *
 * 这条路径要承担三件事：
 *   1. 让 BP 触发线程被冻结（EXCEPTION_CONTINUE_EXECUTION 即可，VEH 退出
 *      后那条线程的 EXCEPTION_DISPATCH 流程停在断点）；
 *   2. 推一条 event:breakpoint 给控制器；
 *   3. 因为本线程被冻住，hit_count + 1 + 把 0xCC 还原回原字节 → 再走单步让
 *      处理器过这条指令 → 单步命中后再把 0xCC 重写回去（避免 hot loop）。
 */

/*
 * P3：把 CONTEXT 全集拆成 regs 对象 + 栈数组。VEH 路径下 ep->ContextRecord
 * 直接给的是真 CONTEXT（被冻结的目标线程那一刻的快照）—— 不用再
 * GetThreadContext 拉一次。
 *
 * 安全：栈读先 VirtualQuery 检查首地址所在页是否可读；不可读就
 * stack=[]（命中事件照推，不让 bp 路径因栈坏而崩）。即使中途某一
 * 项发生 EXCEPTION_ACCESS_VIOLATION，v1.2.0 的崩溃 VEH 也会接住
 * 转储，不会让目标进程无故挂死。
 */
static void si_emit_regs(si_json *evt, CONTEXT *ctx)
{
    si_json *regs = si_json_new();
    if (!regs) return;
    if (ctx) {
#if defined(_M_X64) || defined(__x86_64__)
        /* 通用 + segments（CONTEXT_FULL 在 Windows SDK winnt.h 已经把 flags
         * 完整展开；这里手工读字段避开 flags 不匹配的隐患 —— VEH 路径给
         * 我们的总是本机位宽对应的 ContextRecord）。 */
        si_json_set_int(regs, "rip",    (long long)ctx->Rip);
        si_json_set_int(regs, "rsp",    (long long)ctx->Rsp);
        si_json_set_int(regs, "rbp",    (long long)ctx->Rbp);
        si_json_set_int(regs, "rflags", (long long)ctx->EFlags);
        static const char *reg_names[] = {
            "rax","rbx","rcx","rdx","rsi","rdi","r8","r9",
            "r10","r11","r12","r13","r14","r15"};
        DWORD64 *qwords[] = {
            &ctx->Rax,&ctx->Rbx,&ctx->Rcx,&ctx->Rdx,&ctx->Rsi,&ctx->Rdi,
            &ctx->R8,&ctx->R9,&ctx->R10,&ctx->R11,&ctx->R12,&ctx->R13,
            &ctx->R14,&ctx->R15};
        int i;
        for (i = 0; i < 14; i++) {
            si_json_set_int(regs, reg_names[i], (long long)*qwords[i]);
        }
        si_json_set_int(regs, "cs", (long long)ctx->SegCs);
        si_json_set_int(regs, "ss", (long long)ctx->SegSs);
#else
        si_json_set_int(regs, "eip",    (long long)ctx->Eip);
        si_json_set_int(regs, "esp",    (long long)ctx->Esp);
        si_json_set_int(regs, "ebp",    (long long)ctx->Ebp);
        si_json_set_int(regs, "eflags", (long long)ctx->EFlags);
        static const char *reg_names[] = {
            "eax","ebx","ecx","edx","esi","edi"};
        DWORD *dwords[] = {
            &ctx->Eax,&ctx->Ebx,&ctx->Ecx,&ctx->Edx,&ctx->Esi,&ctx->Edi};
        int i;
        for (i = 0; i < 6; i++) {
            si_json_set_int(regs, reg_names[i], (long long)*dwords[i]);
        }
        si_json_set_int(regs, "cs", (long long)ctx->SegCs);
        si_json_set_int(regs, "ss", (long long)ctx->SegSs);
#endif
    }
    si_json_set_obj(evt, "regs", regs);
}

static void si_emit_stack(si_json *evt, CONTEXT *ctx)
{
    si_json *stack = si_json_new_array();
    if (!stack) return;
    if (ctx) {
        ULONG_PTR base = 0;
#if defined(_M_X64) || defined(__x86_64__)
        base = ctx->Rsp;
#else
        base = ctx->Esp;
#endif
        if (base) {
            /* 先看 RSP 所在页是否可读 —— 不可读就别冒险去 deref。
             * 用 VirtualQuery 检查首地址：State 必须是 MEM_COMMIT，且
             * 不带 PAGE_NOACCESS / PAGE_GUARD 这类保护。                           */
            MEMORY_BASIC_INFORMATION mbi;
            memset(&mbi, 0, sizeof(mbi));
            if (VirtualQuery((LPCVOID)base, &mbi, sizeof(mbi)) &&
                mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0) {
#if defined(_M_X64) || defined(__x86_64__)
                ULONG_PTR *p = (ULONG_PTR *)base;
                int i;
                for (i = 0; i < 16; i++) {
                    si_json *e = si_json_new();
                    si_json_set_int(e, "i",     i);
                    si_json_set_int(e, "addr",  (long long)(ULONG_PTR)((unsigned char *)p + i * 8));
                    si_json_set_int(e, "value", (long long)p[i]);
                    si_json_array_push(stack, e);
                }
#else
                DWORD *p = (DWORD *)base;
                int i;
                for (i = 0; i < 16; i++) {
                    si_json *e = si_json_new();
                    si_json_set_int(e, "i",     i);
                    si_json_set_int(e, "addr",  (long long)(ULONG_PTR)((unsigned char *)p + i * 4));
                    si_json_set_int(e, "value", (long long)p[i]);
                    si_json_array_push(stack, e);
                }
#endif
            }
        }
    }
    si_json_set_arr(evt, "stack", stack);
}

static long si_send_breakpoint_event(si_breakpoint_t *bp, ULONG_PTR fault_addr,
                                      DWORD tid, CONTEXT *ctx)
{
    si_json *evt = si_json_new();
    if (!evt) return 0;
    bp->hit_count++;
    /*
     * 协议字段约定（v1.3.0 P3 终版）：
     *   type        — 固定 "event:breakpoint"
     *   addr        — 断点地址
     *   pid / tid   — 触发线程
     *   slot        — 硬件槽（0..3），VEH 模拟为 -1
     *   kind        — "hw" 或 "veh"（GDB "breakpoint vs watchpoint" 思路）
     *   fault_addr  — 实际触发时的 ExceptionAddress（VEH 路径下与 addr 略差）
     *   hit_count   — 命中次数（递增）
     *   bp_type / bp_len — 用户指定的断点类型 / 长度
     *   regs        — CONTEXT_FULL 寄存器快照（x64: rip/rsp/rbp/r8-r15/cs/ss；
     *                 x86: eip/esp/ebp/eax-edi/cs/ss；ctx 为 NULL 时为空 obj）
     *   stack       — 从 RSP/ESP 起 16 个 QWORD/DWORD，每项
     *                 {i, addr, value}；不可读时为空 arr，事件照推
     *
     * 字段名 schema 在 P2 已固化 —— test_breakpoint_event_payload_schema_construction
     * 是硬约束，P3 只填值不重新设计。
     */
    si_json_set_str(evt, "type", "event:breakpoint");
    si_json_set_int(evt, "addr", (long long)bp->addr);
    si_json_set_int(evt, "pid", (long long)g_pid);
    si_json_set_int(evt, "tid", (long long)tid);
    si_json_set_int(evt, "slot", bp->slot);
    si_json_set_str(evt, "kind", bp->slot < 0 ? "veh" : "hw");
    si_json_set_int(evt, "fault_addr", (long long)fault_addr);
    si_json_set_int(evt, "hit_count", (long long)bp->hit_count);
    si_json_set_int(evt, "bp_type", (long long)bp->type);
    si_json_set_int(evt, "bp_len",  (long long)bp->len);
    /* P3：regs / stack 用真 CONTEXT 填值（VEH 路径下 ep->ContextRecord 即可，
     * 无须再 GetThreadContext）。非 VEH / ctx 为 NULL 时仍是空 obj / 空 arr
     * —— 协议 schema 不变。                                                       */
    si_emit_regs(evt,  ctx);
    si_emit_stack(evt, ctx);
    send_json(evt);
    si_json_free(evt);
    return 1;
}

/*
 * 在 g_veh_patch 里查找命中 addr。命中返回槽下标，否则 -1。
 * patch 表是按"首字节改成 0xCC"的地址为 key；命中时 EIP/RIP 会指向
 * fault_addr（本指令的下一字节，即 addr+1）。
 */
static int si_veh_lookup_fault(ULONG_PTR fault_addr, ULONG_PTR *orig_addr)
{
    int i;
    ULONG_PTR want = fault_addr ? (fault_addr - 1) : 0;   /* INT3 单字节 */
    for (i = 0; i < SI_BP_MAX_VEH; i++) {
        if (!g_veh_patch[i].used) continue;
        if (g_veh_patch[i].addr == want) {
            *orig_addr = want;
            return i;
        }
        /* 兼容调用方直接传 orig addr（命中点在一条 INT3 之后）。 */
        if (g_veh_patch[i].addr == fault_addr) {
            *orig_addr = fault_addr;
            return i;
        }
    }
    return -1;
}

/* 用 VirtualProtect 把 addr 的首字节写成 0xCC，记下原值。失败返回 0。 */
static int si_veh_patch_one(ULONG_PTR addr, BYTE *orig_out)
{
    DWORD old_prot = 0;
    BYTE  orig;
    SIZE_T wrote;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr,
                           &orig, 1, NULL)) {
        return 0;
    }
    /* 调用前 page 有可能不是 PAGE_EXECUTE_READWRITE，先尝试改成它。 */
    if (!VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &old_prot)) {
        return 0;
    }
    if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)addr,
                            (LPCVOID)(BYTE[]){0xCC}, 1, &wrote) || wrote != 1) {
        VirtualProtect((LPVOID)addr, 1, old_prot, &old_prot);
        return 0;
    }
    VirtualProtect((LPVOID)addr, 1, old_prot, &old_prot);
    *orig_out = orig;
    return 1;
}

/* 把原字节写回。 */
static void si_veh_unpatch(int idx)
{
    DWORD old_prot = 0;
    if (idx < 0 || idx >= SI_BP_MAX_VEH || !g_veh_patch[idx].used) return;
    if (!VirtualProtect((LPVOID)g_veh_patch[idx].addr, 1,
                        PAGE_EXECUTE_READWRITE, &old_prot)) return;
    (void)WriteProcessMemory(GetCurrentProcess(),
                              (LPVOID)g_veh_patch[idx].addr,
                              (LPCVOID)&g_veh_patch[idx].orig_byte,
                              1, NULL);
    VirtualProtect((LPVOID)g_veh_patch[idx].addr, 1, old_prot, &old_prot);
}

/* VEH 命中分支。命中并处理返回 EXCEPTION_CONTINUE_EXECUTION。 */
static LONG si_veh_breakpoint_dispatch(EXCEPTION_POINTERS *ep)
{
    ULONG_PTR fault = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;
    ULONG_PTR orig = 0;
    int idx = si_veh_lookup_fault(fault, &orig);
    if (idx < 0) return EXCEPTION_CONTINUE_SEARCH;          /* 不是我们的 BP */
    /* bp record：在 g_veh_bps 里以 orig 为 key 找对应记录，更新 hit_count */
    si_breakpoint_t *bp = NULL;
    int i;
    for (i = 0; i < SI_BP_MAX_VEH; i++) {
        if (g_veh_bps[i].addr == orig && g_veh_bps[i].enabled) {
            bp = &g_veh_bps[i];
            break;
        }
    }
    if (!bp) return EXCEPTION_CONTINUE_SEARCH;
    DWORD tid = GetCurrentThreadId();
    CONTEXT *bp_ctx = ep->ContextRecord;
    si_send_breakpoint_event(bp, fault, tid, bp_ctx);
    /* 单步跳过去 —— 把 0xCC 还原回原字节，并把 Eip 跳到 orig 地址；
     * 用 TRAP_FLAG 会再触发 SINGLE_STEP，我们在 crt_main_dispatch 里再
     * 装回去。 */
    si_veh_unpatch(idx);
    /* IP 回到 orig；flags 加 TF（x86/x64 都是 bit 8）。
     * x86 的 CONTEXT 只有 Eip、x64 只有 Rip —— 必须按位宽分别赋值，
     * 否则另一架构编译不过（CI 的 x86 job 用 /WX）。 */
#if defined(_M_X64) || defined(__x86_64__)
    bp_ctx->Rip    = (DWORD64)orig;
#else
    bp_ctx->Eip    = (DWORD)orig;
#endif
    bp_ctx->EFlags |= 0x100;       /* TRAP_FLAG */
    /* 标记本 idx 需要 SINGLE_STEP 命中后重装 0xCC：用一个全局槽记。 */
    /* idx 复用 g_veh_bps 里的 NULL 槽 + 计数字段。下面直接用 g_veh_bps[i]
     * 的 type 字段做"待重装"标记，简化 — — type |= 0x80 意味着 pending。 */
    bp->type |= 0x80;
    return EXCEPTION_CONTINUE_EXECUTION;
}

/* SINGLE_STEP 命中：把之前 unpatch 的 0xCC 重装回去。 */
static LONG si_veh_single_step_dispatch(EXCEPTION_POINTERS *ep)
{
    int i;
    CONTEXT *ctx = ep->ContextRecord;
    for (i = 0; i < SI_BP_MAX_VEH; i++) {
        if (!g_veh_bps[i].enabled) continue;
        if (!(g_veh_bps[i].type & 0x80)) continue;
        g_veh_bps[i].type &= ~0x80;
        /* 找到对应 patch 槽，重写 0xCC */
        int j;
        for (j = 0; j < SI_BP_MAX_VEH; j++) {
            if (g_veh_patch[j].used && g_veh_patch[j].addr == g_veh_bps[i].addr) {
                si_veh_patch_one(g_veh_bps[i].addr, &g_veh_patch[j].orig_byte);
                break;
            }
        }
    }
    /* 清 TRAP_FLAG */
    ctx->EFlags &= ~0x100u;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static LONG WINAPI agent_seh_filter(EXCEPTION_POINTERS *ep)
{
    if (!si_should_capture(ep)) return EXCEPTION_CONTINUE_SEARCH;
    (void)write_dump_with_meta(ep);
    /* 让 Windows 继续走默认流程 → 杀进程；dump + sidecar 已留好。 */
    return EXCEPTION_EXECUTE_HANDLER;
}

static LONG WINAPI agent_veh_filter(EXCEPTION_POINTERS *ep)
{
    /*
     * P2 硬件断点 VEH 命中 —— 在 si_should_capture 之前先匹配。
     * 不是我们自己的 BP → 返回 SEARCH，让 si_should_capture 跑；
     * 是我们自己的 → 走 bp 分支，绕开崩溃转储。
     */
    if (ep && ep->ExceptionRecord) {
        DWORD c0 = ep->ExceptionRecord->ExceptionCode;
        if (c0 == EXCEPTION_BREAKPOINT) {
            LONG rc = si_veh_breakpoint_dispatch(ep);
            if (rc != EXCEPTION_CONTINUE_SEARCH) return rc;
        } else if (c0 == EXCEPTION_SINGLE_STEP) {
            LONG rc = si_veh_single_step_dispatch(ep);
            if (rc != EXCEPTION_CONTINUE_SEARCH) return rc;
        }
    }

    if (!si_should_capture(ep)) return EXCEPTION_CONTINUE_SEARCH;
    /*
     * 栈溢出 / 非法指令时 VEH 在一块极小栈上（guard page 后的几个字节）被
     * 通知 —— 任意一次栈增长（包括函数调用、栈上局部变量）都会立刻触发
     * 第二次 STACK_OVERFLOW。MiniDumpWriteDump 内部要堆栈分配，会 re-overflow；
     * LoadLibrary / GetProcAddress 同样。CI 上 v1.2.0 头几次崩溃反复写
     * 空 dump / 多份 dump，根本原因就在这里。
     *
     * 这两类异常直接交给 SEH / 系统 default handler：
     *   - STACK_OVERFLOW：让 OS 提级到 EXCEPTION_STACK_OVERFLOW，dump 由它写
     *     （或直接 dump 自带 / WER 收）
     *   - ILLEGAL_INSTRUCTION / PRIV_INSTRUCTION：通常栈已被踩坏，跳过 dump
     *
     * 其余 EXCEPTION_ACCESS_VIOLATION / DIVIDE_BY_ZERO / GUARD_PAGE 才是
     * VEH 捕获后安全写 dump 的场景。
     */
    if (ep && ep->ExceptionRecord) {
        DWORD c = ep->ExceptionRecord->ExceptionCode;
        if (c == EXCEPTION_STACK_OVERFLOW ||
            c == EXCEPTION_ILLEGAL_INSTRUCTION ||
            c == EXCEPTION_PRIV_INSTRUCTION) {
            log_msg("VEH 跳过栈/指令类异常: code=0x%lX", (unsigned long)c);
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    (void)write_dump_with_meta(ep);
    /* VEH 的返回：让 SEH 接手我们的 handler；如果 SEH 没装，Windows 会兜底。 */
    return EXCEPTION_CONTINUE_SEARCH;
}

static void agent_install_crash_handlers(void)
{
    if (g_veh == NULL) {
        g_veh = AddVectoredExceptionHandler(1, &agent_veh_filter);
    }
    if (g_prev_seh == NULL) {
        g_prev_seh = SetUnhandledExceptionFilter(&agent_seh_filter);
    }
}

static void agent_uninstall_crash_handlers(void)
{
    if (g_veh) {
        RemoveVectoredExceptionHandler(g_veh);
        g_veh = NULL;
    }
    if (g_prev_seh) {
        SetUnhandledExceptionFilter(g_prev_seh);
        g_prev_seh = NULL;
    }
}

/* ------------------------- 线程枚举 / 单线程冻结 ------------------------- */

/*
 * 目标进程线程列表（按 tid 输出，便于 GUI 列出来精确只冻死一条线程）。
 *
 * 用 Thread32First / Thread32Next（tlhelp32.h 已在 include 列表里），
 * 配合 GetThreadDescription（Win10+）给出友好名字。
 *
 * 单线程挂起：NtSuspendThread / NtResumeThread。SuspendCount 用
 * NtQueryInformationThread(ThreadBasicInformation) 读，可信。
 *
 * 注意：
 *   - OpenThread 用 THREAD_SUSPEND_RESUME 权限即可；
 *   - 不要 NtSuspendProcess 自己，否则自己挂了整个进程；
 *   - g_worker 线程是 DLL 自带连接线程，故意跳过；GUI 看见它也没意义。
 */

typedef LONG (NTAPI *si_NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *si_NtSuspendThread_t)(HANDLE, PULONG);
typedef LONG (NTAPI *si_NtResumeThread_t)(HANDLE, PULONG);

#define SI_ThreadBasicInformation   0
#define SI_MAX_THREADS_PER_LIST     256

/*
 * 真正的 THREAD_BASIC_INFORMATION 在 winternl.h / ntinternals.h 里：字段
 * SuspendCount 的位置稳定（KeReleaseSemaphore + ETHREAD.SuspendCount）。
 * 但 winternl.h 不保证每个 SDK 都暴露 NTSTATUS / CLIENT_ID 这几个工程化
 * 字段名称（不同 MSVC 版本里 NtQueryInformationThread 第一次给了局部
 * 结构体却未与 ntstatus.h 配合引用），所以这里自写一个只装我们要的字段
 * 的最小子集，避开 SDK 兼容性陷阱。
 *
 * 字段顺序与对齐参考 MSDN：
 *   ExitStatus / TebBaseAddress / ClientId (16-byte union) /
 *   AffinityMask / Priority / BasePriority / SuspendCount
 */
typedef struct _THREAD_BASIC_INFORMATION_SI {
    LONG      ExitStatus;          /* NTSTATUS ≈ LONG，避免拉 ntstatus.h */
    PVOID     TebBaseAddress;
    ULONG_PTR Padding0[2];         /* ClientId 占 16 字节（UniqueProcess + UniqueThread） */
    KAFFINITY AffinityMask;
    LONG      Priority;
    LONG      BasePriority;
    ULONG     SuspendCount;
} THREAD_BASIC_INFORMATION_SI;

/* Win10+ 才有，不可用时返回 0。 */
static DWORD g_self_thread_id = 0;

static const char *thread_state_name(DWORD state)
{
    switch (state) {
    case 0:  return "Initialized";
    case 1:  return "Ready";
    case 2:  return "Running";
    case 3:  return "Standby";
    case 4:  return "Terminated";
    case 5:  return "Wait";
    case 6:  return "Transition";
    case 7:  return "DeferredReady";
    default: return "?";
    }
}

static const char *thread_wait_reason(DWORD reason)
{
    /* THREAD_WAIT_REASON 取值见 winnt.h（多数 enum 与 Reversi/MS docs 对齐） */
    switch (reason) {
    case 0:  return "Executive";
    case 1:  return "FreePage";
    case 2:  return "PageIn";
    case 3:  return "PoolAllocation";
    case 4:  return "DelayExecution";
    case 5:  return "Suspended";
    case 6:  return "UserRequest";
    case 7:  return "WrExecutive";
    case 8:  return "WrFreePage";
    case 9:  return "WrPageIn";
    case 10: return "WrPoolAllocation";
    case 11: return "WrDelayExecution";
    case 12: return "WrSuspended";
    case 13: return "WrUserRequest";
    case 14: return "WrEventPair";
    case 15: return "WrQueue";
    case 16: return "WrLpcReceive";
    case 17: return "WrLpcReply";
    case 18: return "WrVirtualMemory";
    case 19: return "WrPageOut";
    case 20: return "WrRendezvous";
    case 21: return "WrKeyedEvent";
    case 22: return "WrTerminated";
    case 27: return "WrProcessInSwap";
    case 28: return "WrCpuAlert";
    case 29: return "WrCallback";
    case 30: return "WrDeferredReady";
    case 31: return "WrDeferredReadyFiber";
    default: return "";
    }
}

static si_NtSuspendThread_t fn_nt_suspend   = NULL;
static si_NtResumeThread_t  fn_nt_resume    = NULL;
static si_NtQueryInformationThread_t fn_nt_query_t = NULL;

static void nt_thread_funcs_init(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    if (!fn_nt_suspend)
        fn_nt_suspend = (si_NtSuspendThread_t)
            GetProcAddress(ntdll, "NtSuspendThread");
    if (!fn_nt_resume)
        fn_nt_resume = (si_NtResumeThread_t)
            GetProcAddress(ntdll, "NtResumeThread");
    if (!fn_nt_query_t)
        fn_nt_query_t = (si_NtQueryInformationThread_t)
            GetProcAddress(ntdll, "NtQueryInformationThread");
}

/* 给单个 tid 拿当前 SuspendCount（不可用时返回 -1）。*/
static long thread_suspend_count(DWORD tid)
{
    THREAD_BASIC_INFORMATION_SI tbi;
    ULONG got = 0;
    HANDLE h;
    long sc = -1;
    if (!fn_nt_query_t) return -1;
    h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!h) return -1;
    if (fn_nt_query_t(h, SI_ThreadBasicInformation, &tbi, sizeof(tbi), &got) >= 0)
        sc = (long)tbi.SuspendCount;
    CloseHandle(h);
    return sc;
}

/* 给单个 tid 拿 GetThreadDescription（Win10+），不可用时返回空字符串。*/
static void thread_description(DWORD tid, WCHAR *buf, size_t bufsz)
{
    buf[0] = 0;
    {
        typedef HRESULT (WINAPI *GetThreadDescription_t)(HANDLE, PWSTR *);
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        if (!k32) return;
        GetThreadDescription_t gtd = (GetThreadDescription_t)
            GetProcAddress(k32, "GetThreadDescription");
        if (!gtd) return;
        HANDLE h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
        if (!h) return;
        PWSTR p = NULL;
        if (SUCCEEDED(gtd(h, &p)) && p) {
            wcsncpy(buf, p, bufsz / sizeof(WCHAR) - 1);
            buf[bufsz / sizeof(WCHAR) - 1] = 0;
            LocalFree(p);
        }
        CloseHandle(h);
    }
}

static void collect_threads(si_json *arr)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te;
    int emitted = 0;
    if (snap == INVALID_HANDLE_VALUE) return;
    te.dwSize = sizeof(te);
    if (!Thread32First(snap, &te)) { CloseHandle(snap); return; }
    do {
        if (te.th32OwnerProcessID != g_pid) continue;
        {
            si_json *o;
            WCHAR  desc[64] = {0};
            char   desc_utf8[64] = {0};
            if (g_self_thread_id == 0) g_self_thread_id = GetCurrentThreadId();
            if (te.th32ThreadID == g_self_thread_id) continue;
            thread_description(te.th32ThreadID, desc, sizeof(desc));
            utf8_path(desc, desc_utf8, sizeof(desc_utf8));
            o = si_json_new();
            if (!o) continue;
            si_json_set_int(o, "tid", (long long)te.th32ThreadID);
            si_json_set_int(o, "base_priority", (long long)te.tpBasePri);
            si_json_set_int(o, "delta_priority", (long long)te.tpDeltaPri);
            si_json_set_int(o, "suspend_count",
                            (long long)thread_suspend_count(te.th32ThreadID));
            si_json_set_str(o, "state", thread_state_name(te.dwFlags & 0xff));
            si_json_set_str(o, "wait_reason", thread_wait_reason(
                (te.dwFlags >> 16) & 0x7fff));
            si_json_set_str(o, "description", desc_utf8);
            si_json_array_push(arr, o);
            emitted++;
            if (emitted >= SI_MAX_THREADS_PER_LIST) break;
        }
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
}

static int do_suspend_thread(DWORD tid)
{
    HANDLE h;
    ULONG prev = 0;
    LONG  rc;
    if (!fn_nt_suspend) return -1;
    h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!h) return -1;
    rc = fn_nt_suspend(h, &prev);
    CloseHandle(h);
    if (rc < 0) return -1;
    return (int)prev;   /* 调用前的 SuspendCount；调用后 +1 */
}

static int do_resume_thread(DWORD tid)
{
    HANDLE h;
    ULONG prev = 0;
    LONG  rc;
    if (!fn_nt_resume) return -1;
    h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!h) return -1;
    rc = fn_nt_resume(h, &prev);
    CloseHandle(h);
    if (rc < 0) return -1;
    return (int)prev;   /* 调用前的 SuspendCount */
}

/*
 * 解析目标模块的 IMAGE_EXPORT_DIRECTORY。**不依赖 dbghelp / symsrv**，
 * 手动按 data directory + AddressOf{Functions,Names,NameOrdinals} 三数组
 * 解析，得到 [name, rva] 的列表（按名字排序）。
 *
 * 限制：
 *   - 单模块最多 256 条导出（防止 api-ms-win-core-* 这类巨模块塞爆响应）；
 *   - 转出的导出按名字去重（同一名字可能出现在多序号上）；
 *   - 仅解析名字导出；forwarder chain 输出成原 rva，不跟随重定向。
 */
typedef struct {
    LPVOID  ImageBase;       /* 进程内的实际加载基址 */
    PIMAGE_DOS_HEADER DosHdr;
    PIMAGE_NT_HEADERS NtHdr;
    DWORD   ExportDirRva;
    DWORD   ExportDirSize;
    PIMAGE_EXPORT_DIRECTORY ExportDir;
} pe_image_t;

static int pe_parse_image(LPVOID base, pe_image_t *out)
{
    IMAGE_OPTIONAL_HEADER64 o64;
    if (!base || !out) return 0;
    memset(out, 0, sizeof(*out));
    out->ImageBase  = base;
    out->DosHdr     = (PIMAGE_DOS_HEADER)base;
    if (out->DosHdr->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if ((ULONG_PTR)out->DosHdr->e_lfanew > 0x10000) return 0;
    out->NtHdr = (PIMAGE_NT_HEADERS)((BYTE *)base + out->DosHdr->e_lfanew);
    if (out->NtHdr->Signature != IMAGE_NT_SIGNATURE) return 0;

    /*
     * PE32 与 PE32+ OptionalHeader 大小不同，但对"导出表目录"这一字段，
     * DataDirectory 数组在前 16 项的 offset / 含义都相同。MSVC 的 IMAGE_NT_HEADERS
     * 把 OptionalHeader 嵌成 IMAGE_OPTIONAL_HEADER（=PE32）layout；当 Magic
     * 是 0x20b 时把同一段内存 cast 成 IMAGE_OPTIONAL_HEADER64 视作 PE32+
     * DataDirectory，再读 ExportDirRva / ExportDirSize。
     *
     * 这里避开所有把 OptionalHeader 字段直接赋给 IMAGE_OPTIONAL_HEADER32*
     * 的写法（cl /W4 + /WX 会以 C4133（C2440 隐式 cast）报错），改用 memcpy。
     */
    if (out->NtHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        memcpy(&out->ExportDirRva,
               (const void *)&out->NtHdr->OptionalHeader.DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_EXPORT],
               sizeof(out->ExportDirRva));
        memcpy(&out->ExportDirSize,
               (const void *)&out->NtHdr->OptionalHeader.DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_EXPORT].Size,
               sizeof(out->ExportDirSize));
    } else if (out->NtHdr->OptionalHeader.Magic ==
               IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        memcpy(&o64, &out->NtHdr->OptionalHeader, sizeof(o64));
        out->ExportDirRva  = o64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        out->ExportDirSize = o64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else {
        return 0;
    }
    if (out->ExportDirRva == 0 || out->ExportDirSize == 0) return 0;
    out->ExportDir = (PIMAGE_EXPORT_DIRECTORY)
        ((BYTE *)base + out->ExportDirRva);
    return 1;
}

#define SI_MAX_EXPORTS_PER_MODULE 256

/* collect_threads 也被 VEH 接管，理论上有任何 ACCESS_VIOLATION 也会被
 * MiniDumpWriteDump 救回。但实操 Win Server 2025 上 mini dump 偶尔写 0 字节，
 * 因此让 info / threads / exports 三种"扫描型"命令走最小默认：
 *
 *   - info 默认 no_exports=1；
 *   - collect_module_exports 用 VirtualQuery 校验 RVA 落在模块基址 + size 内；
 *   - pe_parse_image 里把"e_lfanew"也用 IsBadReadPtr 风格的 SIZE_T 范围
 *     卡死，避免恶意模块造成野指针。
 *
 * 集成测试里的 x64 ping.exe + 系统默认 8~9 个模块里包括 api-ms-win-*，每个
 * 都是经过 ASLR 的真实 PE；CI 第一波按 budget=64 跑会触发 stack overflow
 * 在某些 Win SKU（已知 Reporter 是 Win Server 2025）。把这些收口后，
 * 显式 exports 命令可以照样用，但默认 info 不带 exports。
 */
static int collect_module_exports(LPVOID base, si_json *arr, int budget)
{
    pe_image_t pe;
    DWORD      i, n_names, n_funcs;
    DWORD     *funcs, *names;
    WORD      *ords;
    const char *seen[SI_MAX_EXPORTS_PER_MODULE];
    int        seen_n = 0;
    int        emitted = 0;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T     qsize;

    if (budget > SI_MAX_EXPORTS_PER_MODULE) budget = SI_MAX_EXPORTS_PER_MODULE;
    if (budget <= 0) return 0;
    /*
     * 别野指针读模块头：用 VirtualQuery 试探头 4KB 是不是本进程已提交页。
     * 第一次热加载模块、刚 FreeLibrary 的残影、跨会话映射都会让这里失败。
     */
    if (!base || VirtualQuery(base, &mbi, sizeof(mbi)) == 0) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    qsize = mbi.RegionSize;
    if (qsize < 0x1000) qsize = 0x1000;
    if (mbi.Protect == 0 || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) return 0;

    if (!pe_parse_image(base, &pe)) return 0;
    n_names = pe.ExportDir->NumberOfNames;
    n_funcs = pe.ExportDir->NumberOfFunctions;
    funcs = (DWORD *)((BYTE *)base + pe.ExportDir->AddressOfFunctions);
    names = (DWORD *)((BYTE *)base + pe.ExportDir->AddressOfNames);
    ords  = (WORD  *)((BYTE *)base + pe.ExportDir->AddressOfNameOrdinals);
    if (!funcs || !names || !ords) return 0;

    /* 第一遍：发出带名字的导出 */
    for (i = 0; i < n_names && emitted < budget; i++) {
        DWORD rva;
        WORD  ord;
        const char *nm = (const char *)base + names[i];
        if (!nm || !nm[0] || nm[0] == '\0') continue;
        ord = ords[i];
        if (ord >= n_funcs) continue;
        rva = funcs[ord];
        if (rva == 0) continue;
        /* 去重 */
        {
            int j;
            for (j = 0; j < seen_n; j++) if (seen[j] == nm) break;
            if (j < seen_n) continue;
            if (seen_n < SI_MAX_EXPORTS_PER_MODULE) seen[seen_n++] = nm;
        }
        {
            si_json *o = si_json_new();
            if (!o) continue;
            si_json_set_str(o, "name", nm);
            si_json_set_int(o, "rva", (long long)rva);
            si_json_set_int(o, "ord", (long long)(pe.ExportDir->Base + ord));
            si_json_array_push(arr, o);
            emitted++;
        }
    }
    /* 第二遍（只剩 budget 富裕时）：按 ordinal 列出口无名字的导出 */
    for (i = 0; i < n_funcs && emitted < budget; i++) {
        DWORD rva = funcs[i];
        const char *nm = NULL;
        si_json *o;
        int j;
        if (rva == 0) continue;
        /* 这个序号是否已通过名字发过？ */
        for (j = 0; j < (int)n_names; j++) {
            if (ords[j] == i && names[j]) {
                nm = (const char *)base + names[j];
                break;
            }
        }
        if (nm && nm[0]) continue;  /* 已经按名字发过了 */
        o = si_json_new();
        if (!o) continue;
        si_json_set_str(o, "name", "");
        si_json_set_int(o, "rva", (long long)rva);
        si_json_set_int(o, "ord", (long long)(pe.ExportDir->Base + i));
        si_json_array_push(arr, o);
        emitted++;
    }
    return emitted;
}

/* ------------------------- 内存 trampoline / 代码 patch ------------------------- */

/*
 * patch 机制：在目标地址写入"5 字节近跳转 E9 <rel32>"跳到我们刚 VirtualAlloc
 * 的 shellcode 区；shellcode 末尾再以 E9 <rel32> 跳回目标地址+5 的原指令处。
 * 原 5 字节备份，写回即还原（patch_revert）。
 *
 * 关键约束：
 *   1. **绝对不许在加载器锁里执行**：包括 patch 自己写入的位置也不能是
 *      加载器正在用的代码段。需要 patch 代码段时 mem_write_bytes 已经
 *      用 VirtualProtect 改完保护再写，行为兼容。
 *   2. **trampoline 区要 RWX**：直接在 shellcode 末尾追加 ret 是允许的，
 *      但 trampoline 段必须可执行。这里走 VirtualAlloc + PAGE_EXECUTE_READWRITE。
 *   3. **trampoline 段尽量近**：用 MEM_TOP_DOWN / 在目标 ±2GB 范围选址，
 *      否则 rel32 装不下。这版用的是"近址选址"+E9，失败时也允许绝对 64-bit
 *      跳转（mov r10 imm64; jmp r10）作为后备。
 *   4. **同一地址 patch 多次时第二次拒收**（除非先 revert）。允许版本号
 *      自增便于前端识别。
 *   5. **trampoline 自身要在 unload 时还原 + 释放**：通过 stack 维护一个
 *      还原列表，unload 路径调一次 free。
 */

#define SI_MAX_PATCHES        32
#define SI_MAX_PATCH_BYTES    256
#define SI_TRAMPOLINE_BYTES   4096

typedef struct {
    ULONGLONG target;          /* 用户给的绝对地址 */
    ULONGLONG original_rva;    /* patch 进 trampoline 后回到原地址+5 时用的 rva */
    ULONGLONG trampoline;      /* shellcode 区基址 */
    size_t    trampoline_off;  /* shellcode 起始相对基址的偏移 */
    size_t    trampoline_size; /* shellcode 字节数 */
    unsigned char orig_bytes[16];
    size_t    orig_size;
    ULONGLONG version;         /* 自增 */
    int       used;
} si_patch_t;

static si_patch_t g_patches[SI_MAX_PATCHES];
static ULONGLONG g_patch_seq = 0;
static int       g_patch_used_trampoline = 0;

/* 选一段近址 RWX。失败回退任意空闲页。 */
static ULONGLONG alloc_trampoline_page(ULONGLONG near_here)
{
    ULONGLONG p = 0;
    /* 优先：near_here 上方 1MB 内对齐地址，让用户段在 32-bit offset 范围 */
    {
        SYSTEM_INFO sys;
        GetSystemInfo(&sys);
        ULONGLONG target = near_here & ~(ULONGLONG)0xFFF;
        ULONGLONG hi = target + (1ULL << 20);
        ULONGLONG lo = (target > (1ULL << 20)) ? target - (1ULL << 20) : 0;
        for (p = hi; ; p += 0x1000) {
            if (p >= (ULONGLONG)0x7FFFFFFEFFFFULL) break;   /* cap */
            void *got = VirtualAlloc((LPVOID)(uintptr_t)p,
                                     SI_TRAMPOLINE_BYTES,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
            if (got) return (ULONGLONG)(uintptr_t)got;
            if (p == 0) break;
        }
        for (p = (lo < hi) ? lo : 0; p > 0 && p < hi; p += 0x1000) {
            void *got = VirtualAlloc((LPVOID)(uintptr_t)p,
                                     SI_TRAMPOLINE_BYTES,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
            if (got) return (ULONGLONG)(uintptr_t)got;
        }
        (void)sys;
    }
    return 0;
}

/* 写一段 E9 <rel32> JMP；返回写入字节数（5）。 */
static size_t emit_jmp_rel32(unsigned char *buf, ULONGLONG from, ULONGLONG to)
{
    LONG off = (LONG)(to - (from + 5));
    buf[0] = 0xE9;
    *(LONG *)(buf + 1) = off;
    return 5;
}

/* 写一段绝对跳转（用作 backup）：mov r10, imm64; jmp r10, 14 字节。 */
static size_t emit_jmp_abs(unsigned char *buf, ULONGLONG to)
{
    /* 49 BA <imm64> = REX.W + 0xBA, 然后 41 FF E2 = jmp r10 */
    buf[0] = 0x49; buf[1] = 0xBA;
    *(ULONGLONG *)(buf + 2) = to;
    buf[10] = 0x41; buf[11] = 0xFF; buf[12] = 0xE2;
    return 13;
}

static int find_patch_slot_for_target(ULONGLONG target, int create)
{
    int i, free_at = -1;
    for (i = 0; i < SI_MAX_PATCHES; i++) {
        if (g_patches[i].used && g_patches[i].target == target) return i;
        if (!g_patches[i].used && free_at < 0) free_at = i;
    }
    if (!create) return -1;
    if (free_at < 0) return -1;
    return free_at;
}

static si_json *patch_to_json(si_patch_t *p)
{
    si_json *o;
    char hex[64];
    int  i;
    o = si_json_new();
    if (!o) return NULL;
    si_json_set_int(o, "address",  (long long)p->target);
    si_json_set_int(o, "trampoline", (long long)p->trampoline);
    si_json_set_int(o, "size", (long long)p->orig_size);
    si_json_set_int(o, "version", (long long)p->version);
    /* 原字节 hex */
    for (i = 0; i < (int)p->orig_size && i * 2 + 2 < (int)sizeof(hex); i++) {
        snprintf(hex + i * 2, 3, "%02X", p->orig_bytes[i]);
    }
    hex[(int)p->orig_size * 2] = 0;
    si_json_set_str(o, "original", hex);
    return o;
}

static void revert_one(si_patch_t *p)
{
    if (!p->used) return;
    (void)WriteProcessMemory(GetCurrentProcess(),
                              (LPVOID)(uintptr_t)p->target,
                              p->orig_bytes, p->orig_size, NULL);
    FlushInstructionCache(GetCurrentProcess(),
                          (LPCVOID)(uintptr_t)p->target, p->orig_size);
    if (p->trampoline) {
        VirtualFree((LPVOID)(uintptr_t)p->trampoline, 0, MEM_RELEASE);
    }
    memset(p, 0, sizeof(*p));
}

static int do_patch_inject(ULONGLONG target, const unsigned char *code,
                           size_t code_size, char *err, size_t errsz)
{
    int slot;
    ULONGLONG tr;
    unsigned char tramp[SI_TRAMPOLINE_BYTES] = {0};
    size_t tr_used = 0;
    size_t code_off;
    int patched = 0;
    ULONGLONG jmp_back_at;

    if (code_size == 0 || code_size > 1024 || target == 0) {
        snprintf(err, errsz, "参数无效");
        return 0;
    }
    slot = find_patch_slot_for_target(target, 1);
    if (slot < 0) {
        snprintf(err, errsz, "已 patch 上限 (%d) 或地址冲突", SI_MAX_PATCHES);
        return 0;
    }

    /* 备份原 5 字节 */
    ReadProcessMemory(GetCurrentProcess(),
                      (LPCVOID)(uintptr_t)target,
                      g_patches[slot].orig_bytes, 5,
                      (SIZE_T *)&g_patches[slot].orig_size);
    if (g_patches[slot].orig_size == 0) {
        snprintf(err, errsz, "无法读目标 5 字节（地址无效？）");
        memset(&g_patches[slot], 0, sizeof(g_patches[slot]));
        return 0;
    }
    g_patches[slot].orig_size = 5;

    tr = alloc_trampoline_page(target);
    if (tr == 0) {
        snprintf(err, errsz, "申请 trampoline 页失败");
        memset(&g_patches[slot], 0, sizeof(g_patches[slot]));
        return 0;
    }
    g_patches[slot].trampoline = tr;

    /* trampoline 布局：
     *   bytes 0..code_size-1           = 用户的 shellcode
     *   bytes code_size..code_size+4   = E9 rel32 跳回 target+5
     */
    code_off = (g_patch_used_trampoline + 0xF) & ~(size_t)0xF;
    if (code_off + code_size + 5 > SI_TRAMPOLINE_BYTES) {
        snprintf(err, errsz, "trampoline 段 4KB 装不下");
        revert_one(&g_patches[slot]);
        return 0;
    }
    memcpy(tramp, code, code_size);
    tr_used = code_size;
    jmp_back_at = tr + code_off + tr_used;
    tr_used += emit_jmp_rel32(tramp + tr_used, jmp_back_at,
                               target + 5);

    /* 真正落 trampoline */
    {
        SIZE_T put = 0;
        WriteProcessMemory(GetCurrentProcess(),
                           (LPVOID)(uintptr_t)(tr + code_off),
                           tramp, tr_used, &put);
        if (put != tr_used) {
            snprintf(err, errsz, "写 trampoline 失败 (0x%lX)",
                     (unsigned long)GetLastError());
            revert_one(&g_patches[slot]);
            return 0;
        }
        g_patches[slot].trampoline_off = code_off;
        g_patches[slot].trampoline_size = tr_used;
    }
    g_patch_used_trampoline = (int)(code_off + tr_used);

    /* 在目标写 E9 rel32 跳到 trampoline */
    {
        unsigned char jmpbuf[16];
        ULONGLONG from = target;
        ULONGLONG to   = tr + code_off;
        size_t wrote;
        LONG off = (LONG)(to - (from + 5));
        if (off == (LONG)(to - (from + 5))) {
            jmpbuf[0] = 0xE9;
            *(LONG *)(jmpbuf + 1) = off;
            wrote = 5;
        } else {
            wrote = emit_jmp_abs(jmpbuf, to);
        }
        if (!mem_write_bytes((void *)(uintptr_t)target, jmpbuf, wrote,
                             &patched, err, errsz)) {
            revert_one(&g_patches[slot]);
            return 0;
        }
    }
    FlushInstructionCache(GetCurrentProcess(),
                          (LPCVOID)(uintptr_t)target, 5);
    g_patches[slot].used = 1;
    g_patches[slot].target = target;
    g_patches[slot].version = ++g_patch_seq;
    return 1;
}

/* ------------------------- SHA-256（v1.3.0 内存快照用） ------------------------- */

/*
 * SHA-256 自实现（FIPS 180-4），纯 C99，零外部依赖。
 *
 * 为什么不引 bcrypt / crypt32 等系统 API：
 *   1. v1.2.0 引入的 SHA256 DLL 自校验（dll_manager）也是自写 —— 协议层「禁止
 *      引入任何有版本 / 行为差异的依赖」是项目的硬规矩。
 *   2. 编译进 DLL 的 SHA 入口必须 macOS / Linux 的 cc 也能单独编译并跑自测
 *      （CI 里 ``cc -std=c99`` 直接验过）。crypt32 / bcrypt 是 Win-only。
 *   3. 镜像 sha256 命令的「同一段字节、多端算出的结果一致」首要条件是参考实现
 *      按标准写的——本实现按 FIPS 180-4 一步步复刻，输出 hex 与 openssl / sha256sum
 *      完全一致。
 *
 * 不在文件里 #include 任何 Win 头（windows.h）；这里只是个 plain C 函数，叫到
 * 它的 caller 才负责把字节准备好。这个函数只够一次算一段（``si_sha256``），
 * 也提供 ``si_sha256_init / update / final`` 留给将来流式算（如 P2 断点字节流
 * 做 SHA 比对时复用），目前只用到一次性接口。
 */

typedef struct {
    unsigned int state[8];
    unsigned long long bits;
    unsigned char buf[64];
    unsigned int buf_len;
} si_sha256_ctx;

static const unsigned int si_sha256_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static inline unsigned int si_sha256_rotr(unsigned int x, unsigned int n)
{
    return (x >> n) | (x << (32 - n));
}

static void si_sha256_compress(si_sha256_ctx *c, const unsigned char block[64])
{
    unsigned int w[64];
    unsigned int a, b, d, e, f, g, h, t1, t2, x;
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((unsigned int)block[i * 4 + 0] << 24) |
               ((unsigned int)block[i * 4 + 1] << 16) |
               ((unsigned int)block[i * 4 + 2] << 8)  |
               ((unsigned int)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        unsigned int s0 = si_sha256_rotr(w[i - 15], 7) ^
                          si_sha256_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned int s1 = si_sha256_rotr(w[i - 2], 17) ^
                          si_sha256_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->state[0]; b = c->state[1];
    d = c->state[3]; e = c->state[4];
    f = c->state[5]; g = c->state[6]; h = c->state[7];
    /* 也复制下 c->state[2]，但为了清晰放在下面统一刷新。 */
    x = c->state[2];
    for (i = 0; i < 64; i++) {
        unsigned int S1 = si_sha256_rotr(e, 6) ^ si_sha256_rotr(e, 11) ^
                          si_sha256_rotr(e, 25);
        unsigned int ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + si_sha256_k[i] + w[i];
        unsigned int S0 = si_sha256_rotr(a, 2) ^ si_sha256_rotr(a, 13) ^
                          si_sha256_rotr(a, 22);
        unsigned int mj = (a & b) ^ (a & x) ^ (b & x);
        t2 = S0 + mj;
        h = g; g = f; f = e;
        e = d + t1;
        d = x; x = b; b = a;
        a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += x;
    c->state[3] += d; c->state[4] += e; c->state[5] += f;
    c->state[6] += g; c->state[7] += h;
}

static void si_sha256_init(si_sha256_ctx *c)
{
    c->state[0] = 0x6a09e667U; c->state[1] = 0xbb67ae85U;
    c->state[2] = 0x3c6ef372U; c->state[3] = 0xa54ff53aU;
    c->state[4] = 0x510e527fU; c->state[5] = 0x9b05688cU;
    c->state[6] = 0x1f83d9abU; c->state[7] = 0x5be0cd19U;
    c->bits = 0;
    c->buf_len = 0;
}

static void si_sha256_update(si_sha256_ctx *c, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    while (len > 0) {
        unsigned int take = (unsigned int)(sizeof(c->buf) - c->buf_len);
        if (take > len) take = (unsigned int)len;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take;
        p += take;
        len -= take;
        if (c->buf_len == sizeof(c->buf)) {
            si_sha256_compress(c, c->buf);
            c->bits += (unsigned long long)sizeof(c->buf) * 8;
            c->buf_len = 0;
        }
    }
}

static void si_sha256_final(si_sha256_ctx *c, unsigned char out[32])
{
    static const unsigned char pad[64] = { 0x80, 0 };
    /* 把累计长度记到 final 调用时为止，FIPS 180-4 要求长度字段是原消息比特数，
     * 中间为了补 0 多走压缩的字节不能算长度里。 */
    unsigned long long bits = c->bits + (unsigned long long)c->buf_len * 8;
    unsigned char len_be[8];
    int i;
    int first_block_had_80;
    /* 把已有 buf 撑到 / 压成完整块（若 buf 已 ≥ 56），保证当前 buf 已被压、
     * 0x80 已经在「最后一个含原始数据的块」内。 */
    if (c->buf_len >= 56) {
        /* buf_len == 64 时 (64 - buf_len) == 0，update 不会压缩，需要显式压。 */
        if (c->buf_len == 64) {
            si_sha256_compress(c, c->buf);
            c->bits += (unsigned long long)sizeof(c->buf) * 8;
            c->buf_len = 0;
        } else {
            /* 56..63：先填满本块再压。当前 buf 已有原数据 + 若干 padding，
             * 那若干 padding 里第一个字节必须是 0x80（FIPS 要求），余下填零。
             * pad[0]=0x80、之后是 0，所以 update(pad, k) 写入的内容是 [0x80, 0×(k-1)]。 */
            si_sha256_update(c, pad, 64 - c->buf_len);
        }
        first_block_had_80 = 1;  /* 0x80 已经在刚压完的「数据 + padding」块里。 */
    } else {
        first_block_had_80 = 0;
    }
    /* 现在 c->buf_len < 56。第二段 padding：先填一个 0x80 + 0 直到 buf_len == 56，
     * 然后 8 字节长度位会触发最后一次压缩。 */
    if (!first_block_had_80) {
        si_sha256_update(c, pad, 56 - c->buf_len);  /* pad[0] = 0x80 */
    } else {
        /* 0x80 已经在前一块里了，新块只要填零就行。 */
        static const unsigned char zeros[56] = { 0 };
        si_sha256_update(c, zeros, 56 - c->buf_len);
    }
    /* 写 8 字节长度，会触发最后一次压缩。 */
    for (i = 7; i >= 0; i--) {
        len_be[i] = (unsigned char)(bits & 0xff);
        bits >>= 8;
    }
    si_sha256_update(c, len_be, 8);
    for (i = 0; i < 8; i++) {
        out[i * 4 + 0] = (unsigned char)(c->state[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c->state[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c->state[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(c->state[i]);
    }
}

/* 一次性接口：把 (data, len) 喂进 SHA-256，把 32 字节结果写到 out。 */
static void si_sha256(const void *data, size_t len, unsigned char out[32])
{
    si_sha256_ctx c;
    si_sha256_init(&c);
    si_sha256_update(&c, data, len);
    si_sha256_final(&c, out);
}

/* ------------------------- 4KB 分页内存快照（v1.3.0） ------------------------- */

/*
 * 取 4KB 边界〔base, base + sz) 内所有页的 hash + head64。返回写出去的页数；
 * 失败（地址不可读等）返回 0。
 *
 * pages 数组 caller 自己保证足够大（至少 ``(sz + 4095) / 4096`` 条）；
 * 单条结构里 head64 是 64 字节 hex（hex_size = 128）。
 */
typedef struct {
    unsigned long long addr;
    unsigned int       size;        /* 该页实际写入的字节数（通常 4096） */
    unsigned char      sha[32];
    unsigned char      head[SI_SNAP_HEAD_BYTES];   /* 该页前 64 字节原样 */
} si_snap_page_t;

/* 取一个页[0..4096)。失败返回 0（不代表全区域失败，调用方继续下一页）。 */
static int si_read_one_page(unsigned long long base, si_snap_page_t *p)
{
    unsigned char buf[SI_SNAP_PAGE];
    SIZE_T got = 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)(uintptr_t)base, &mbi, sizeof(mbi)) == 0)
        return 0;
    if (mbi.State != MEM_COMMIT)
        return 0;
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
        return 0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)base,
                           buf, sizeof(buf), &got) || got == 0)
        return 0;
    p->addr = base;
    p->size = (unsigned int)got;
    si_sha256(buf, got, p->sha);
    memcpy(p->head, buf, SI_SNAP_HEAD_BYTES < got ? SI_SNAP_HEAD_BYTES : got);
    return 1;
}

/*
 * 把给出的 regions 拆成 4KB 页逐页读 + 算 SHA + 记 head64。
 *
 * 输入：``count`` 个 ``{base, size}``；输出 ``pages_out``（caller 提供，
 * 长度必须 ≥ count * (region_size / 4KB) 给出，函数填实际数量到
 * ``*pages_written``）。
 *
 * 返回 1 成功，0 把 regions 摊开后页数超 SI_SNAP_MAX_PAGES 也算 0。
 */
static int si_collect_pages(si_json *regions_arr,
                            si_snap_page_t *pages_out,
                            unsigned int *pages_written)
{
    unsigned int total = 0;
    size_t i;
    size_t n = si_json_count(regions_arr);
    for (i = 0; i < n; i++) {
        si_json *r = si_json_at(regions_arr, i);
        long long base = si_json_get_int(r, "base", 0);
        long long size = si_json_get_int(r, "size", 0);
        unsigned long long addr;
        if (base <= 0 || size <= 0) continue;
        /* 4KB 对齐到下一页起点。 */
        unsigned long long first = (unsigned long long)base;
        unsigned long long end   = first + (unsigned long long)size;
        if (first % SI_SNAP_PAGE != 0)
            first = (first + SI_SNAP_PAGE) & ~((unsigned long long)SI_SNAP_PAGE - 1);
        for (addr = first; addr + SI_SNAP_PAGE <= end; addr += SI_SNAP_PAGE) {
            if (total >= SI_SNAP_MAX_PAGES) return 0;
            if (!si_read_one_page(addr, &pages_out[total])) continue;
            total++;
        }
    }
    *pages_written = total;
    return 1;
}

/* ------------------------- 指令分发 ------------------------- */

/*
 * ------------------------- P2 硬件断点命令 -------------------------
 *
 * bp_set / bp_list / bp_remove / bp_clear —— 由 agent_handle 调度到。
 *
 * 类型编码（与 controller 端约定）：
 *   type ∈ {"exec", "read", "write", "rw"} + len ∈ {1, 2, 4, 8}
 *
 *  - 当 controller 给的是 "module!symbol+0x42" 形式时，它会先在本地解析成
 *    addr 再下发 —— P2 不在 DLL 端做符号解析（导出表来自另一条 info 通道）。
 *  - tid=0 时走 VEH 模拟（不受线程限制，但受总条目数 SI_BP_MAX_VEH 限制）。
 *  - tid>0 时先用线程上下文 SetThreadContext 装到 DR0-DR3；4 槽用完后
 *    自动降到 VEH 模拟（remaining 槽用 si_veh_* 路径）。
 *  - 硬件槽不够 + VEH 槽也不够 → 返回 no_slot_available 让用户主动 remove。
 */

static int si_bp_type_to_code(const char *type_str)
{
    if (!type_str) return 0;
    if (strcmp(type_str, "exec")  == 0) return 0;
    if (strcmp(type_str, "read")  == 0) return 1;
    if (strcmp(type_str, "write") == 0) return 2;
    if (strcmp(type_str, "rw")    == 0) return 3;
    return -1;
}

static const char *si_bp_code_to_type(int code)
{
    switch (code & 0x7F) {
    case 0: return "exec";
    case 1: return "read";
    case 2: return "write";
    case 3: return "rw";
    case 6: return "exec2";
    case 7: return "exec4";
    case 4: return "rw4";
    case 5: return "rw8";
    }
    return "exec";
}

/* 找一个未用的硬件槽（enabled == 0），返下标；找不到 -1。 */
static int si_bp_find_free_hw(void)
{
    int i;
    for (i = 0; i < SI_BP_MAX_DR_SLOTS; i++) {
        if (!g_hw_bps[i].enabled) return i;
    }
    return -1;
}

/* 找一个未用的 VEH 槽（含 bp 与 patch 表并行分配）。返下标，找不到 -1。 */
static int si_bp_find_free_veh(void)
{
    int i;
    for (i = 0; i < SI_BP_MAX_VEH; i++) {
        if (!g_veh_bps[i].enabled) return -1;
    }
    /* 全 enabled 看是否有"已 enabled 但 patch 槽没了"的崩溃态，保守拒绝。 */
    for (i = 0; i < SI_BP_MAX_VEH; i++) {
        if (!g_veh_patch[i].used && !g_veh_bps[i].enabled) return i;
    }
    return -1;
}

/* 按 addr + tid 找记录，返回下标，找不到 -1。P2 测试用例会引用——保留。 */
SI_ATTR_UNUSED
static int si_bp_lookup_hw_by_addr(DWORD tid, ULONG_PTR addr)
{
    int i;
    for (i = 0; i < SI_BP_MAX_DR_SLOTS; i++) {
        if (g_hw_bps[i].enabled &&
            g_hw_bps[i].addr == addr &&
            g_hw_bps[i].tid  == tid) {
            return i;
        }
    }
    return -1;
}

SI_ATTR_UNUSED
static int si_bp_lookup_veh_by_addr(ULONG_PTR addr)
{
    int i;
    for (i = 0; i < SI_BP_MAX_VEH; i++) {
        if (g_veh_bps[i].enabled && g_veh_bps[i].addr == addr) return i;
    }
    return -1;
}

/*
 * 用 SetThreadContext 装一条硬件断点。slot 用 si_bp_find_free_hw 选。
 * 失败（OpenThread 失败 / SetThreadContext 失败）保留返回值供调用方。
 */
static int si_bp_set_hw(int slot, DWORD tid, ULONG_PTR addr, int type, int len)
{
    HANDLE  th = NULL;
    CONTEXT ctx;
#if defined(_M_X64) || defined(__x86_64__)
    /* x64: ctx.Dr7/Dr6 是 DWORD64；用位宽自适的 DWORD64 暂存，避免
     * -W4 /WX 视 C4244 截断警告为 error（CI 编译会因此红）。 */
    DWORD64 dr7;
    DWORD64 dr6;
#else
    DWORD   dr7;
    DWORD   dr6;
#endif
    BOOL    ok;
    /* OpenThread 也只用于我们自己的进程。PROCESS_VM_OPERATION 已够，
     * 但我们要改 context —— 用 THREAD_GET_CONTEXT + SET_CONTEXT 即可。 */
    DWORD access = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                   THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION;
    th = OpenThread(access, FALSE, tid);
    if (!th) {
        log_msg("bp_set_hw: OpenThread(%lu) 失败 err=%lu",
                (unsigned long)tid, (unsigned long)GetLastError());
        return 0;
    }
    if (SuspendThread(th) == (DWORD)-1) {
        log_msg("bp_set_hw: SuspendThread(%lu) 失败 err=%lu",
                (unsigned long)tid, (unsigned long)GetLastError());
        CloseHandle(th);
        return 0;
    }
    memset(&ctx, 0, sizeof(ctx));
#if defined(_M_X64) || defined(__x86_64__)
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_AMD64;
#else
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_i386;
#endif
    /* CONTEXT_i386 / CONTEXT_AMD64 在 Windows SDK winnt.h 里分别是 x86 与
     * x64 上下文标志 —— 一次只一个；WOW64 / 32 位 DLL 编译走 CONTEXT_i386
     * + 编译器字段（Dr0..3 是 DWORD）。 */
    /* 取 context 实际上 cl 会忽略「不匹配本机」的标志，所以两个都给也行。*/
    ok = GetThreadContext(th, &ctx);
    if (!ok) {
        log_msg("bp_set_hw: GetThreadContext(%lu) 失败 err=%lu",
                (unsigned long)tid, (unsigned long)GetLastError());
        (void)ResumeThread(th);
        CloseHandle(th);
        return 0;
    }
    /*
     * DR 寄存器是固定字节（x64 寄存器名均带 R 前缀；x86 / WOW64 自动适用
     * 编译宏）。WOW64 路径 P3 详细化，P2 阶段用 64 位定义打 64 位 DLL，
     * 32 位 DLL 走 _M_IX86 分支。
     */
#if defined(_M_X64) || defined(__x86_64__)
    switch (slot) {
    case 0: ctx.Dr0 = addr; break;
    case 1: ctx.Dr1 = addr; break;
    case 2: ctx.Dr2 = addr; break;
    case 3: ctx.Dr3 = addr; break;
    default: break;
    }
    dr7 = ctx.Dr7;
    dr7 &= ~(0xFu << (16 + 4 * slot));      /* 清 RW/LEN 字段 */
    dr7 |= ((DWORD)si_dr7_rw_for(type) << SI_BP_DR7_RW_SHIFT(slot));
    dr7 |= ((DWORD)si_dr7_len_for(type, len) << SI_BP_DR7_LEN_SHIFT(slot));
    dr7 |= SI_BP_DR7_ENABLE_BIT(slot);      /* 本地启用 L 位 */
    /* 顺手清 G 位（避免和别的调试器冲突） */
    dr7 &= ~((DWORD)1u << (2 * slot + 1));
    ctx.Dr7 = dr7;
    /* Dr6 用于读"哪条断点命中"，先清空（DR6 是只读 DR6.B0..3） */
    dr6 = ctx.Dr6;
    dr6 &= ~(0xFu);
    ctx.Dr6 = dr6;
#else
    switch (slot) {
    case 0: ctx.Dr0 = (DWORD)addr; break;
    case 1: ctx.Dr1 = (DWORD)addr; break;
    case 2: ctx.Dr2 = (DWORD)addr; break;
    case 3: ctx.Dr3 = (DWORD)addr; break;
    default: break;
    }
    dr7 = ctx.Dr7;
    dr7 &= ~(0xFu << (16 + 4 * slot));
    dr7 |= ((DWORD)si_dr7_rw_for(type) << SI_BP_DR7_RW_SHIFT(slot));
    dr7 |= ((DWORD)si_dr7_len_for(type, len) << SI_BP_DR7_LEN_SHIFT(slot));
    dr7 |= SI_BP_DR7_ENABLE_BIT(slot);
    dr7 &= ~((DWORD)1u << (2 * slot + 1));
    ctx.Dr7 = dr7;
    ctx.Dr6 &= ~(0xFu);
#endif
    ok = SetThreadContext(th, &ctx);
    if (!ok) {
        log_msg("bp_set_hw: SetThreadContext(%lu) 失败 err=%lu",
                (unsigned long)tid, (unsigned long)GetLastError());
        (void)ResumeThread(th);
        CloseHandle(th);
        return 0;
    }
    (void)ResumeThread(th);
    CloseHandle(th);
    return 1;
}

/*
 * 清除一个 hardware 槽：Dr{slot} 清 0、Dr7 启用位清 0。
 */
static void si_bp_clear_hw(int slot, DWORD tid)
{
    HANDLE th;
    DWORD  access = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                    THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION;
    CONTEXT ctx;
    th = OpenThread(access, FALSE, tid);
    if (!th) return;
    if (SuspendThread(th) == (DWORD)-1) {
        CloseHandle(th);
        return;
    }
    memset(&ctx, 0, sizeof(ctx));
#if defined(_M_X64) || defined(__x86_64__)
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_AMD64;
#else
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_i386;
#endif
    if (!GetThreadContext(th, &ctx)) {
        ResumeThread(th);
        CloseHandle(th);
        return;
    }
#if defined(_M_X64) || defined(__x86_64__)
    switch (slot) {
    case 0: ctx.Dr0 = 0; break;
    case 1: ctx.Dr1 = 0; break;
    case 2: ctx.Dr2 = 0; break;
    case 3: ctx.Dr3 = 0; break;
    default: break;
    }
    ctx.Dr7 &= ~SI_BP_DR7_ENABLE_BIT(slot);
    ctx.Dr7 &= ~(0xFu << SI_BP_DR7_RW_SHIFT(slot));
    ctx.Dr7 &= ~(0x3u << SI_BP_DR7_LEN_SHIFT(slot));
#else
    switch (slot) {
    case 0: ctx.Dr0 = 0; break;
    case 1: ctx.Dr1 = 0; break;
    case 2: ctx.Dr2 = 0; break;
    case 3: ctx.Dr3 = 0; break;
    default: break;
    }
    ctx.Dr7 &= ~SI_BP_DR7_ENABLE_BIT(slot);
    ctx.Dr7 &= ~(0xFu << SI_BP_DR7_RW_SHIFT(slot));
    ctx.Dr7 &= ~(0x3u << SI_BP_DR7_LEN_SHIFT(slot));
#endif
    (void)SetThreadContext(th, &ctx);
    ResumeThread(th);
    CloseHandle(th);
}

/*
 * 装载 VEH 模拟断点：1) 找空槽 2) patch 首字节 3) 记录在 g_veh_bps 与
 * g_veh_patch 中。失败把已修改的字节还原。
 */
static int si_bp_set_veh(ULONG_PTR addr, int type, int len, int *out_idx,
                          int *out_patch_idx)
{
    int idx = -1, pidx = -1, i;
    BYTE orig = 0;
    /* 找 bp 槽位 */
    for (i = 0; i < SI_BP_MAX_VEH; i++) {
        if (!g_veh_bps[i].enabled) { idx = i; break; }
    }
    if (idx < 0) return 0;
    for (i = 0; i < SI_BP_MAX_VEH; i++) {
        if (!g_veh_patch[i].used && idx == i) { pidx = i; break; }
    }
    /* 实际上 g_veh_bps 和 g_veh_patch 是平行表（同样下标）；我们刻意分两个
     * 表是为了将来允许同地址多次 bp_set（不会在 P2 出现，但留口子）。 */
    pidx = idx;
    if (g_veh_patch[pidx].used) return 0;
    if (!si_veh_patch_one(addr, &orig)) {
        return 0;
    }
    g_veh_patch[pidx].addr      = addr;
    g_veh_patch[pidx].orig_byte = orig;
    g_veh_patch[pidx].used      = 1;
    g_veh_bps[idx].addr    = addr;
    g_veh_bps[idx].type    = type;
    g_veh_bps[idx].len     = len;
    g_veh_bps[idx].tid     = 0;
    g_veh_bps[idx].slot    = -1;
    g_veh_bps[idx].enabled = 1;
    g_veh_bps[idx].hit_count = 0;
    *out_idx = idx;
    *out_patch_idx = pidx;
    return 1;
}

static void si_bp_clear_all(si_json *out)
{
    int i, cleared_hw = 0, cleared_veh = 0;
    for (i = 0; i < SI_BP_MAX_DR_SLOTS; i++) {
        if (g_hw_bps[i].enabled) {
            DWORD tid = g_hw_bps[i].tid;
            si_bp_clear_hw(i, tid);
            g_hw_bps[i].enabled = 0;
            g_hw_bps[i].addr = 0;
            cleared_hw++;
        }
    }
    for (i = 0; i < SI_BP_MAX_VEH; i++) {
        if (g_veh_bps[i].enabled) {
            si_veh_unpatch(i);
            g_veh_bps[i].enabled = 0;
            g_veh_bps[i].addr = 0;
            g_veh_bps[i].type = 0;
            g_veh_bps[i].hit_count = 0;
            g_veh_patch[i].used = 0;
            g_veh_patch[i].addr = 0;
            g_veh_patch[i].orig_byte = 0;
            cleared_veh++;
        }
    }
    si_json_set_int(out, "cleared_hw", (long long)cleared_hw);
    si_json_set_int(out, "cleared_veh", (long long)cleared_veh);
}

/* 把所有断点序列化成数组，挂到 out 下的 bps 字段。 */
static void si_bp_dump(si_json *out)
{
    si_json *arr = si_json_new_array();
    int i;
    si_json_set_int(out, "hw_slots_total", SI_BP_MAX_DR_SLOTS);
    si_json_set_int(out, "veh_slots_total", SI_BP_MAX_VEH);
    {
        int hw_used = 0, veh_used = 0;
        for (i = 0; i < SI_BP_MAX_DR_SLOTS; i++) {
            if (g_hw_bps[i].enabled) hw_used++;
        }
        for (i = 0; i < SI_BP_MAX_VEH; i++) {
            if (g_veh_bps[i].enabled) veh_used++;
        }
        si_json_set_int(out, "hw_slots_used",  hw_used);
        si_json_set_int(out, "veh_slots_used", veh_used);
    }
    for (i = 0; i < SI_BP_MAX_DR_SLOTS; i++) {
        if (!g_hw_bps[i].enabled) continue;
        si_json *o = si_json_new();
        si_json_set_int(o, "addr",   (long long)g_hw_bps[i].addr);
        si_json_set_int(o, "tid",    (long long)g_hw_bps[i].tid);
        si_json_set_int(o, "slot",   (long long)g_hw_bps[i].slot);
        si_json_set_str(o, "kind",   "hw");
        si_json_set_str(o, "type",   si_bp_code_to_type(g_hw_bps[i].type));
        si_json_set_int(o, "len",    (long long)g_hw_bps[i].len);
        si_json_set_int(o, "hit_count", (long long)g_hw_bps[i].hit_count);
        si_json_array_push(arr, o);
    }
    for (i = 0; i < SI_BP_MAX_VEH; i++) {
        if (!g_veh_bps[i].enabled) continue;
        si_json *o = si_json_new();
        si_json_set_int(o, "addr",   (long long)g_veh_bps[i].addr);
        si_json_set_int(o, "tid",    0);
        si_json_set_int(o, "slot",   -1);
        si_json_set_str(o, "kind",   "veh");
        si_json_set_str(o, "type",   si_bp_code_to_type(g_veh_bps[i].type));
        si_json_set_int(o, "len",    (long long)g_veh_bps[i].len);
        si_json_set_int(o, "hit_count", (long long)g_veh_bps[i].hit_count);
        si_json_array_push(arr, o);
    }
    si_json_set_arr(out, "bps", arr);
}

static void agent_handle(const char *text)
{
    si_json     *msg = si_json_parse(text);
    const char  *type;
    si_json     *out;
    DWORD        t0 = GetTickCount();

    if (!msg) {
        log_msg("收到无法解析的 JSON: %.80s", text);
        out = si_json_new();
        if (out) {
            si_json_set_str(out, "type", "error");
            si_json_set_str(out, "error", "invalid json");
            send_json(out);
            si_json_free(out);
        }
        return;
    }

    type  = si_json_get_str(msg, "type", "");
    log_msg("收到命令 type=%s id=%lld", type, (long long)si_json_get_int(msg, "id", 0));
    out   = si_json_new();
    si_json_set_str(out, "type", "response");
    si_json_set_str(out, "cmd", type);
    si_json_set_int(out, "id", si_json_get_int(msg, "id", 0));

    if (strcmp(type, "ping") == 0) {
        si_json_set_bool(out, "ok", 1);

    } else if (strcmp(type, "info") == 0) {
        si_json         *mods = si_json_new_array();
        HANDLE           snap;
        MODULEENTRY32W   me;
        /* v1.2.0 经验：默认不附带 exports。CI 集成测试里给 ping.exe 注入后
         * 第一次 info 命令就触发了 ACCESS_VIOLATION 写 dump —— 真实的 6 次
         * ACCESS_VIOLATION 都落在 ntdll/kernel32 之外的小模块（api-ms-win-*，
         * 其 IAT 较大，PE 解析时 AddressOfNames 跨段访问野指针）。CI 上
         * 修不动目标进程环境，就收紧默认：必须显式 --exports-budget > 0
         * 才走导出表解析；显式 --no-exports 也可以豁 budget。 */
        long long        no_exports = si_json_get_int(msg, "no_exports", 1);
        long long        budget = si_json_get_int(msg, "budget", 0);
        if (no_exports) budget = 0;
        if (budget < 0) budget = 0;
        if (budget > SI_MAX_EXPORTS_PER_MODULE)
            budget = SI_MAX_EXPORTS_PER_MODULE;
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_pid);
        if (snap != INVALID_HANDLE_VALUE) {
            me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me)) {
                do {
                    si_json *m = si_json_new();
                    char     nm[MAX_PATH], pth[MAX_PATH];
                    utf8_path(me.szModule, nm, MAX_PATH);
                    utf8_path(me.szExePath, pth, MAX_PATH);
                    si_json_set_str(m, "name", nm);
                    si_json_set_str(m, "path", pth);
                    si_json_set_int(m, "base", (long long)(uintptr_t)me.modBaseAddr);
                    si_json_set_int(m, "size", (long long)me.modBaseSize);
                    if (!no_exports && me.modBaseAddr && budget > 0) {
                        si_json *exports = si_json_new_array();
                        int n = collect_module_exports(me.modBaseAddr, exports,
                                                       (int)budget);
                        if (n > 0) si_json_set_arr(m, "exports", exports);
                        si_json_free(exports);
                        si_json_set_int(m, "exports_count", (long long)n);
                    } else {
                        si_json_set_int(m, "exports_count", 0);
                    }
                    si_json_array_push(mods, m);
                } while (Module32NextW(snap, &me));
            }
            CloseHandle(snap);
        }
        si_json_set_arr(out, "modules", mods);
        si_json_set_bool(out, "ok", 1);

    } else if (strcmp(type, "exports") == 0) {
        /* 按基址或模块名单独解析一个模块的导出表。前端 GUI 模块行 hover 时用。 */
        long long addr = si_json_get_int(msg, "base", 0);
        const char *mod_name = si_json_get_str(msg, "name", "");
        long long budget = si_json_get_int(msg, "budget", SI_MAX_EXPORTS_PER_MODULE);
        if (budget <= 0) budget = SI_MAX_EXPORTS_PER_MODULE;
        si_json *exports = si_json_new_array();
        int      n = 0;
        if (addr) {
            n = collect_module_exports((LPVOID)(uintptr_t)addr, exports,
                                       (int)budget);
        } else if (mod_name[0]) {
            HANDLE snap = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_pid);
            if (snap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W me; me.dwSize = sizeof(me);
                if (Module32FirstW(snap, &me)) {
                    do {
                        char nm[MAX_PATH];
                        utf8_path(me.szModule, nm, MAX_PATH);
                        if (_stricmp(nm, mod_name) == 0) {
                            n = collect_module_exports(me.modBaseAddr, exports,
                                                       (int)budget);
                            break;
                        }
                    } while (Module32NextW(snap, &me));
                }
                CloseHandle(snap);
            }
        }
        si_json_set_arr(out, "exports", exports);
        si_json_set_int(out, "count", (long long)n);
        si_json_set_bool(out, "ok", 1);

    } else if (strcmp(type, "threads") == 0) {
        /* 目标进程线程枚举。结果：threads=[{tid, base_priority, delta_priority,
         *                       suspend_count, state, wait_reason, description}] */
        si_json *arr = si_json_new_array();
        if (!arr) {
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "alloc");
        } else {
            nt_thread_funcs_init();
            collect_threads(arr);
            si_json_set_arr(out, "threads", arr);
            si_json_set_bool(out, "ok", 1);
        }

    } else if (strcmp(type, "thread_suspend") == 0 ||
               strcmp(type, "thread_resume") == 0) {
        long long tid = si_json_get_int(msg, "tid", 0);
        int prev = -1;
        long sc  = -1;
        if (tid <= 0) {
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "tid 必填正整数");
        } else {
            nt_thread_funcs_init();
            if (type[7] == 's')
                prev = do_suspend_thread((DWORD)tid);
            else
                prev = do_resume_thread((DWORD)tid);
            sc = thread_suspend_count((DWORD)tid);
            if (prev < 0) {
                char buf[96];
                snprintf(buf, sizeof(buf), "操作失败 (0x%lX / %s)",
                         (unsigned long)GetLastError(),
                         type[7] == 's' ? "NtSuspendThread" : "NtResumeThread");
                si_json_set_bool(out, "ok", 0);
                si_json_set_str(out, "error", buf);
            } else {
                si_json_set_int(out, "tid", tid);
                si_json_set_int(out, "prev_suspend_count", (long long)prev);
                si_json_set_int(out, "suspend_count", sc);
                si_json_set_bool(out, "ok", 1);
            }
        }

    } else if (strcmp(type, "mem_regions") == 0) {
        si_json                 *arr = si_json_new_array();
        MEMORY_BASIC_INFORMATION mbi;
        SYSTEM_INFO              sys;
        unsigned char           *base, *end;

        GetSystemInfo(&sys);
        base = (unsigned char *)sys.lpMinimumApplicationAddress;
        end  = (unsigned char *)sys.lpMaximumApplicationAddress;
        while (base < end) {
            if (VirtualQuery(base, &mbi, sizeof(mbi)) == 0) break;
            if (mbi.State == MEM_COMMIT) {
                si_json *o = si_json_new();
                si_json_set_int(o, "base", (long long)(uintptr_t)mbi.BaseAddress);
                si_json_set_int(o, "size", (long long)mbi.RegionSize);
                si_json_set_int(o, "protect", (long long)mbi.Protect);
                si_json_set_str(o, "type", si_mem_type(mbi.Protect));
                si_json_array_push(arr, o);
            }
            if (mbi.RegionSize == 0) break;
            base = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        }
        si_json_set_arr(out, "regions", arr);
        si_json_set_bool(out, "ok", 1);

    } else if (strcmp(type, "mem_search") == 0) {
        const char *hex = si_json_get_str(msg, "pattern", "");
        const char *mhex = si_json_get_str(msg, "mask", "");
        long long   maxr = si_json_get_int(msg, "max", 512);
        size_t      plen = strlen(hex) / 2;
        unsigned char *pat = si_hex_to_bytes(hex, NULL);
        unsigned char *msk = mhex[0] ? si_hex_to_bytes(mhex, NULL) : NULL;
        if (pat && plen > 0) {
            mem_search(pat, plen, msk, (size_t)maxr, out);
            si_json_set_bool(out, "ok", 1);
        } else {
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "bad pattern");
        }
        free(pat);
        free(msk);

    } else if (strcmp(type, "mem_read") == 0) {
        long long    addr = si_json_get_int(msg, "address", 0);
        long long    size = si_json_get_int(msg, "size", 256);
        unsigned char tmp[8192];
        SIZE_T       got = 0;
        char         msg_err[64];
        if (size <= 0) size = 256;
        if (size > (long long)sizeof(tmp)) size = (long long)sizeof(tmp);
        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)addr,
                              tmp, (SIZE_T)size, &got) && got > 0) {
            char *hex = si_bytes_to_hex(tmp, got);
            si_json_set_str(out, "hex", hex);
            si_json_set_int(out, "size", (long long)got);
            si_json_set_bool(out, "ok", 1);
            si_free(hex);
        } else {
            snprintf(msg_err, sizeof(msg_err), "ReadProcessMemory 失败 (0x%lX)",
                     (unsigned long)GetLastError());
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", msg_err);
        }

    } else if (strcmp(type, "mem_write") == 0) {
        long long      addr = si_json_get_int(msg, "address", 0);
        const char    *hex  = si_json_get_str(msg, "hex", "");
        size_t         n    = strlen(hex) / 2;
        unsigned char *b    = si_hex_to_bytes(hex, NULL);
        if (b && n > 0) {
            int  patched = 0;
            char err[320];   /* 给「哪一步失败 + 区域属性」留足空间（-Werror=format-truncation） */
            err[0] = 0;
            if (mem_write_bytes((void *)(uintptr_t)addr, b, n, &patched,
                                err, sizeof(err))) {
                si_json_set_bool(out, "ok", 1);
                si_json_set_int(out, "written", (long long)n);
                si_json_set_bool(out, "protection_changed", patched);
            } else {
                si_json_set_bool(out, "ok", 0);
                si_json_set_str(out, "error", err[0] ? err : "写入失败");
            }
        } else {
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "bad hex");
        }
        free(b);

    } else if (strcmp(type, "mem_snapshot") == 0) {
        /*
         * 拉取指定 regions 的逐页 SHA-256 + 前 64 字节快照。
         * msg.regions 缺省时直接当 mem_regions 的当前视图：自己拉一遍。
         * 区域元数据 + 页细节全部回 JSON，控制器侧持久化（不用 DLL 落盘）。
         */
        si_json         *regions_msg = si_json_get(msg, "regions");
        si_json         *regs         = NULL;
        MEMORY_BASIC_INFORMATION  mbi;
        SYSTEM_INFO               sys;
        unsigned char *base, *end;
        si_snap_page_t *pages;
        unsigned int    pages_used = 0;
        unsigned long long total_bytes = 0;
        unsigned char     global_sha[32];

        pages = (si_snap_page_t *)calloc(SI_SNAP_MAX_PAGES, sizeof(*pages));
        if (!pages) {
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "alloc");
            goto mem_snapshot_done;
        }

        if (regions_msg && si_json_is_array(regions_msg)) {
            regs = si_json_new_array();
            if (!regs) {
                free(pages);
                si_json_set_bool(out, "ok", 0);
                si_json_set_str(out, "error", "alloc");
                goto mem_snapshot_done;
            }
            /* 深拷贝 regions —— 之后 si_collect_pages 不依赖调用方生命周期。 */
            {
                size_t i;
                size_t n = si_json_count(regions_msg);
                for (i = 0; i < n; i++) {
                    si_json *r = si_json_at(regions_msg, i);
                    si_json *o = si_json_new();
                    if (!o) continue;
                    si_json_set_int(o, "base",
                                    si_json_get_int(r, "base", 0));
                    si_json_set_int(o, "size",
                                    si_json_get_int(r, "size", 0));
                    si_json_array_push(regs, o);
                }
            }
        } else {
            /* 缺省：拉一次 mem_regions 当前视图（只采 MEM_COMMIT）。 */
            regs = si_json_new_array();
            if (!regs) {
                free(pages);
                si_json_set_bool(out, "ok", 0);
                si_json_set_str(out, "error", "alloc");
                goto mem_snapshot_done;
            }
            GetSystemInfo(&sys);
            base = (unsigned char *)sys.lpMinimumApplicationAddress;
            end  = (unsigned char *)sys.lpMaximumApplicationAddress;
            while (base < end) {
                if (VirtualQuery(base, &mbi, sizeof(mbi)) == 0) break;
                if (mbi.State == MEM_COMMIT) {
                    si_json *o = si_json_new();
                    if (o) {
                        si_json_set_int(o, "base",
                                        (long long)(uintptr_t)mbi.BaseAddress);
                        si_json_set_int(o, "size",
                                        (long long)mbi.RegionSize);
                        si_json_array_push(regs, o);
                    }
                }
                if (mbi.RegionSize == 0) break;
                base = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
            }
        }

        if (!si_collect_pages(regs, pages, &pages_used)) {
            si_json_free(regs);
            free(pages);
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "页数超限");
            goto mem_snapshot_done;
        }

        /* 把 pages 序列化成 JSON；同时算一次大 SHA（所有 page sha 串起来再 hash
         * 一遍——方便侧对比两次快照是否完全一致）。 */
        {
            si_json *arr = si_json_new_array();
            si_sha256_ctx gctx;
            int gi;
            if (!arr) {
                si_json_free(regs);
                free(pages);
                si_json_set_bool(out, "ok", 0);
                si_json_set_str(out, "error", "alloc");
                goto mem_snapshot_done;
            }
            si_sha256_init(&gctx);
            for (gi = 0; gi < (int)pages_used; gi++) {
                si_json *o = si_json_new();
                char hex[65], hhead[SI_SNAP_HEAD_BYTES * 2 + 1];
                int kk;
                if (!o) continue;
                si_json_set_int(o, "addr", (long long)pages[gi].addr);
                si_json_set_int(o, "size", (long long)pages[gi].size);
                for (kk = 0; kk < 32; kk++)
                    sprintf(hex + kk * 2, "%02x", pages[gi].sha[kk]);
                hex[64] = 0;
                si_json_set_str(o, "sha", hex);
                for (kk = 0; kk < (int)pages[gi].size && kk < SI_SNAP_HEAD_BYTES; kk++)
                    sprintf(hhead + kk * 2, "%02x", pages[gi].head[kk]);
                hhead[SI_SNAP_HEAD_BYTES * 2] = 0;
                si_json_set_str(o, "head64", hhead);
                si_json_array_push(arr, o);
                si_sha256_update(&gctx, pages[gi].sha, 32);
                total_bytes += pages[gi].size;
            }
            si_sha256_final(&gctx, global_sha);
            {
                char ghex[65];
                int kk;
                for (kk = 0; kk < 32; kk++)
                    sprintf(ghex + kk * 2, "%02x", global_sha[kk]);
                ghex[64] = 0;
                si_json_set_str(out, "name",
                                si_json_get_str(msg, "name", ""));
                si_json_set_int(out, "count", (long long)pages_used);
                si_json_set_int(out, "bytes", (long long)total_bytes);
                si_json_set_str(out, "sha256", ghex);
                si_json_set_arr(out, "pages", arr);
                si_json_set_bool(out, "ok", 1);
            }
        }
        si_json_free(regs);
        free(pages);
    mem_snapshot_done:
        ;

    } else if (strcmp(type, "mem_diff") == 0) {
        /*
         * 接收两个已存快照的 pages 列表（来自控制器），按 SHA 比对；
         * 不同页直接回两侧 head64 给前端的 hex diff 视图。
         * 这里**不**直接读盘 —— DLL 不持有快照，所有数据都从控制器推过来。
         *
         * a_pages / b_pages: 形如 [{addr, size, sha, head64}, ...] 的数组；
         * 同时支持 size=0 的"差异占位项"（只有 addr / sha），用空 head64 兜底。
         */
        si_json *a_pages = si_json_get(msg, "a_pages");
        si_json *b_pages = si_json_get(msg, "b_pages");
        si_json *changed = si_json_new_array();
        si_json *only_in_a = si_json_new_array();
        long long unchanged = 0;
        size_t ai, bi;
        if (!a_pages || !si_json_is_array(a_pages) ||
            !si_json_is_array(b_pages) || !changed || !only_in_a) {
            if (changed) si_json_free(changed);
            if (only_in_a) si_json_free(only_in_a);
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "a_pages / b_pages 必填数组");
        } else {
            /* 对每个 a 页找 b 里同 addr 项，按 sha 比较。 */
            for (ai = 0; ai < si_json_count(a_pages); ai++) {
                si_json *pa = si_json_at(a_pages, ai);
                long long a_addr = si_json_get_int(pa, "addr", 0);
                const char *a_sha = si_json_get_str(pa, "sha", "");
                const char *a_hd = si_json_get_str(pa, "head64", "");
                long long a_sz  = si_json_get_int(pa, "size", 0);
                int matched_addr = 0;
                int matched_sha = 0;
                for (bi = 0; bi < si_json_count(b_pages); bi++) {
                    si_json *pb = si_json_at(b_pages, bi);
                    long long b_addr = si_json_get_int(pb, "addr", 0);
                    if (b_addr != a_addr) continue;
                    matched_addr = 1;
                    if (strcmp(a_sha, si_json_get_str(pb, "sha", "")) == 0)
                        matched_sha = 1;
                    if (matched_addr && !matched_sha) {
                        /* 同地址但 sha 不同 → changed。 */
                        si_json *o = si_json_new();
                        if (o) {
                            si_json_set_int(o, "addr", a_addr);
                            si_json_set_int(o, "size", a_sz);
                            si_json_set_str(o, "old_sha", a_sha);
                            si_json_set_str(o, "new_sha",
                                            si_json_get_str(pb, "sha", ""));
                            si_json_set_str(o, "old_bytes", a_hd);
                            si_json_set_str(o, "new_bytes",
                                            si_json_get_str(pb, "head64", ""));
                            si_json_array_push(changed, o);
                        }
                    }
                    break;
                }
                if (!matched_addr) {
                    si_json *o = si_json_new();
                    if (o) {
                        si_json_set_int(o, "addr", a_addr);
                        si_json_set_int(o, "size", a_sz);
                        si_json_set_str(o, "old_sha", a_sha);
                        si_json_set_str(o, "new_sha", "");
                        si_json_set_str(o, "old_bytes", a_hd);
                        si_json_set_str(o, "new_bytes", "");
                        si_json_array_push(only_in_a, o);
                    }
                } else if (matched_sha) {
                    unchanged++;
                }
            }
            si_json_set_int(out, "unchanged_count", unchanged);
            si_json_set_arr(out, "changed", changed);
            si_json_set_arr(out, "only_in_a", only_in_a);
            si_json_set_bool(out, "ok", 1);
        }

    } else if (strcmp(type, "resources") == 0) {
        dump_resources(out);
        si_json_set_bool(out, "ok", 1);

    } else if (strcmp(type, "bp_set") == 0) {
        /*
         * 装载一条硬件断点（优先硬件 DR 槽，不够用 VEH 模拟）。
         *
         * 协议字段：
         *   tid           1=指定线程（SetThreadContext 装 DR），0=进程级（VEH 模拟）
         *   address       ULONG_PTR ——必须给
         *   type          "exec"/"read"/"write"/"rw"
         *   len           1/2/4/8（对 exec/rw 有效；默认 1）
         *
         * 命中后通过 event:breakpoint 推送，参见 si_veh_breakpoint_dispatch
         * 与 si_send_breakpoint_event。
         */
        long long    addr_ll = si_json_get_int(msg, "address", 0);
        DWORD        tid     = (DWORD)si_json_get_int(msg, "tid", 0);
        const char  *type_s  = si_json_get_str(msg, "type", "exec");
        int          len     = (int)si_json_get_int(msg, "len", 1);
        int          code    = si_bp_type_to_code(type_s);
        ULONG_PTR    addr    = (ULONG_PTR)addr_ll;
        if (code < 0) {
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "invalid type");
        } else if (addr == 0) {
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "missing address");
        } else if (tid != 0) {
            int slot = si_bp_find_free_hw();
            if (slot < 0 && si_bp_find_free_veh() < 0) {
                si_json_set_bool(out, "ok", 0);
                si_json_set_str(out, "error", "no_slot_available");
            } else if (slot >= 0 && si_bp_set_hw(slot, tid, addr, code, len)) {
                g_hw_bps[slot].addr    = addr;
                g_hw_bps[slot].tid     = tid;
                g_hw_bps[slot].type    = code;
                g_hw_bps[slot].len     = len;
                g_hw_bps[slot].slot    = slot;
                g_hw_bps[slot].enabled = 1;
                g_hw_bps[slot].hit_count = 0;
                si_json_set_int(out, "addr",   (long long)addr);
                si_json_set_int(out, "tid",    (long long)tid);
                si_json_set_int(out, "slot",   (long long)slot);
                si_json_set_int(out, "kind",   0);  /* 0=hw */
                si_json_set_str(out, "type",   type_s);
                si_json_set_int(out, "len",    (long long)len);
                si_json_set_bool(out, "ok", 1);
            } else {
                /* hw 失败/不可用 → 退化到 VEH 模拟（同样适用 tid>0） */
                int idx = -1, pidx = -1;
                if (!si_bp_set_veh(addr, code, len, &idx, &pidx)) {
                    si_json_set_bool(out, "ok", 0);
                    si_json_set_str(out, "error", "no_slot_available");
                } else {
                    si_json_set_int(out, "addr", (long long)addr);
                    si_json_set_int(out, "tid",  (long long)tid);
                    si_json_set_int(out, "slot", -1);
                    si_json_set_int(out, "kind", 1);
                    si_json_set_str(out, "type", type_s);
                    si_json_set_int(out, "len",  (long long)len);
                    si_json_set_bool(out, "ok", 1);
                }
            }
        } else {
            /* tid == 0：直接 VEH 模拟 */
            int idx = -1, pidx = -1;
            if (!si_bp_set_veh(addr, code, len, &idx, &pidx)) {
                si_json_set_bool(out, "ok", 0);
                si_json_set_str(out, "error", "no_slot_available");
            } else {
                si_json_set_int(out, "addr", (long long)addr);
                si_json_set_int(out, "tid",  0);
                si_json_set_int(out, "slot", -1);
                si_json_set_int(out, "kind", 1);
                si_json_set_str(out, "type", type_s);
                si_json_set_int(out, "len",  (long long)len);
                si_json_set_bool(out, "ok", 1);
            }
        }

    } else if (strcmp(type, "bp_list") == 0) {
        si_bp_dump(out);
        si_json_set_bool(out, "ok", 1);

    } else if (strcmp(type, "bp_remove") == 0) {
        /*
         * 卸一条断点：按 address 找（hw 用 tid+addr 限缩）。
         *   addr   必填
         *   tid    hw 路径下用作定位，veh 忽略
         */
        long long addr_ll = si_json_get_int(msg, "address", 0);
        DWORD     tid     = (DWORD)si_json_get_int(msg, "tid", 0);
        ULONG_PTR addr    = (ULONG_PTR)addr_ll;
        int removed_hw  = 0, removed_veh = 0;
        if (addr != 0) {
            int i;
            for (i = 0; i < SI_BP_MAX_DR_SLOTS; i++) {
                if (g_hw_bps[i].enabled && g_hw_bps[i].addr == addr &&
                    (tid == 0 || g_hw_bps[i].tid == tid)) {
                    DWORD otid = g_hw_bps[i].tid;
                    si_bp_clear_hw(i, otid);
                    g_hw_bps[i].enabled = 0;
                    g_hw_bps[i].addr = 0;
                    removed_hw++;
                }
            }
            for (i = 0; i < SI_BP_MAX_VEH; i++) {
                if (g_veh_bps[i].enabled && g_veh_bps[i].addr == addr) {
                    si_veh_unpatch(i);
                    g_veh_bps[i].enabled = 0;
                    g_veh_bps[i].addr = 0;
                    g_veh_bps[i].type = 0;
                    g_veh_bps[i].hit_count = 0;
                    g_veh_patch[i].used = 0;
                    g_veh_patch[i].addr = 0;
                    g_veh_patch[i].orig_byte = 0;
                    removed_veh++;
                }
            }
        }
        si_json_set_int(out, "removed_hw",  (long long)removed_hw);
        si_json_set_int(out, "removed_veh", (long long)removed_veh);
        si_json_set_bool(out, "ok", 1);

    } else if (strcmp(type, "bp_clear") == 0) {
        si_bp_clear_all(out);
        si_json_set_bool(out, "ok", 1);

    } else if (strcmp(type, "patch_inject") == 0) {
        long long addr = si_json_get_int(msg, "address", 0);
        const char *hex = si_json_get_str(msg, "hex", "");
        size_t   n     = strlen(hex) / 2;
        if (!addr || n == 0 || n > 1024) {
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "参数无效（address / hex）");
        } else {
            unsigned char *b = si_hex_to_bytes(hex, NULL);
            char err[320] = {0};
            if (!b) {
                si_json_set_bool(out, "ok", 0);
                si_json_set_str(out, "error", "bad hex");
            } else if (do_patch_inject((ULONGLONG)addr, b, n,
                                       err, sizeof(err))) {
                si_json_set_int(out, "address", addr);
                si_json_set_int(out, "version",
                                (long long)g_patch_seq);
                si_json_set_bool(out, "ok", 1);
            } else {
                si_json_set_bool(out, "ok", 0);
                si_json_set_str(out, "error", err[0] ? err : "patch 失败");
            }
            free(b);
        }

    } else if (strcmp(type, "patch_list") == 0) {
        si_json *arr = si_json_new_array();
        int i;
        if (!arr) {
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "alloc");
        } else {
            for (i = 0; i < SI_MAX_PATCHES; i++) {
                if (g_patches[i].used) {
                    si_json *o = patch_to_json(&g_patches[i]);
                    if (o) si_json_array_push(arr, o);
                }
            }
            si_json_set_arr(out, "patches", arr);
            si_json_set_int(out, "count", (long long)(int)
                            (sizeof(g_patches) / sizeof(g_patches[0])));
            si_json_set_bool(out, "ok", 1);
        }

    } else if (strcmp(type, "patch_revert") == 0) {
        long long addr = si_json_get_int(msg, "address", 0);
        int slot = find_patch_slot_for_target(
            (ULONGLONG)addr, 0);
        if (!addr || slot < 0) {
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "未找到对应 patch");
        } else {
            revert_one(&g_patches[slot]);
            si_json_set_int(out, "address", addr);
            si_json_set_bool(out, "ok", 1);
        }

    } else if (strcmp(type, "patch_clear") == 0) {
        int i;
        for (i = 0; i < SI_MAX_PATCHES; i++)
            revert_one(&g_patches[i]);
        g_patch_used_trampoline = 0;
        si_json_set_bool(out, "ok", 1);
        si_json_set_str(out, "message", "all reverted");

    } else if (strcmp(type, "terminate") == 0) {
        si_json_set_bool(out, "ok", 1);
        send_json(out);
        si_json_free(out);
        si_json_free(msg);
        Sleep(300);
        ExitProcess(0);

    } else if (strcmp(type, "unload") == 0) {
        si_json_set_bool(out, "ok", 1);
        send_json(out);
        si_json_free(out);
        si_json_free(msg);
        /*
         * 必须先断开连接：socket 属于进程而不是线程，FreeLibraryAndExitThread
         * 只结束线程，连接会一直留着，控制器永远等不到断开，重新注入就会
         * 误判成「已注入」。
         */
        if (g_sock != INVALID_SOCKET) {
            shutdown(g_sock, SD_BOTH);
            closesocket(g_sock);
            g_sock = INVALID_SOCKET;
        }
        Sleep(200);
        FreeLibraryAndExitThread(g_module, 0);

    } else {
        si_json_set_bool(out, "ok", 0);
        si_json_set_str(out, "error", "unknown command");
    }

    send_json(out);
    log_msg("命令 %s 处理完成 用时=%lums", type,
            (unsigned long)(GetTickCount() - t0));
    si_json_free(out);
    si_json_free(msg);
}

static DWORD WINAPI agent_thread(LPVOID param)
{
    (void)param;
    log_open();
    log_msg("agent 线程启动 pid=%lu 版本=%s", (unsigned long)g_pid, SI_VERSION);
    if (!agent_connect()) {
        log_msg("未建立控制通道，线程退出");
        return 0;
    }
    send_hello();
    log_msg("hello 已发出，进入读循环等待命令");

    for (;;) {
        char *payload = NULL;
        if (g_sock == INVALID_SOCKET) break;
        if (!recv_frame(&payload)) break;
        agent_handle(payload);
        free(payload);
    }
    log_msg("读循环结束，关闭连接");
    if (g_sock != INVALID_SOCKET) {
        shutdown(g_sock, SD_BOTH);
        closesocket(g_sock);
        g_sock = INVALID_SOCKET;
    }
    WSACleanup();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_module = (HMODULE)inst;
        g_pid    = GetCurrentProcessId();
        DisableThreadLibraryCalls(inst);
        /* 装崩溃转储 handler —— 这一步不能在加载器锁里做大型分配，
         * SetUnhandledExceptionFilter / AddVectoredExceptionHandler 自身
         * 是轻量调用，副作用在目标进程触发异常时才真正发生，所以这里
         * 直接装没问题。 */
        si_send_cs_init();
        agent_install_crash_handlers();
        /*
         * 在线程里建连、收发（不在 DllMain 里做 I/O）：
         * DllMain 持着加载器锁，任何可能触发模块加载的调用都可能卡住。
         */
        CreateThread(NULL, 0, agent_thread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        if (g_sock != INVALID_SOCKET) {
            shutdown(g_sock, SD_BOTH);
            closesocket(g_sock);
            g_sock = INVALID_SOCKET;
        }
        /* P2 — 把所有 bp 还原回原字节以免卸 DLL 后留下"被改成 0xCC 的代码"。 */
        {
            int i;
            for (i = 0; i < SI_BP_MAX_VEH; i++) {
                if (g_veh_bps[i].enabled && g_veh_patch[i].used) {
                    /* 这里只 unpatch，不动 g_hw_bps —— hw 在线程 detach 时
                     * 已经由线程退出流程处理。 */
                    DWORD old_prot = 0;
                    if (VirtualProtect((LPVOID)g_veh_patch[i].addr, 1,
                                       PAGE_EXECUTE_READWRITE, &old_prot)) {
                        (void)WriteProcessMemory(GetCurrentProcess(),
                                                  (LPVOID)g_veh_patch[i].addr,
                                                  (LPCVOID)&g_veh_patch[i].orig_byte,
                                                  1, NULL);
                        VirtualProtect((LPVOID)g_veh_patch[i].addr, 1,
                                       old_prot, &old_prot);
                    }
                }
            }
        }
        agent_uninstall_crash_handlers();
        break;
    default:
        break;
    }
    return TRUE;
}
