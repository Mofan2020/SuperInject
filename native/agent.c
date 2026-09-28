/*
 * SuperInject Agent - 被注入的 DLL
 *
 * 目标：在被调试进程内建立一条反向控制通道（命名管道），
 * 接受 SuperInject 控制器的指令：
 *   ping / info / mem_regions / mem_search / mem_read / mem_write
 *   resources（提取内存里的图片/音频/视频：PE 资源 + 内存映射文件）
 *   terminate（自我结束）/ unload（自行卸载）
 *
 * 注意：冻结由控制器侧用 NtSuspendProcess 完成（挂起全部线程），
 * 这里不做「冻结」——从进程内部挂起自己只会让唯一的工作线程睡死，
 * 既冻结不了目标，也永远回不来。
 *
 * 协议：4 字节小端长度 + UTF-8 JSON
 * 管道名：\\.\pipe\SuperInject-<controllerPid>-<targetPid>
 *
 * 仅供开发人员调试自己的程序使用，禁止用于未授权的第三方进程。
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "superinject_json.h"

#define SI_VERSION "1.0.1"

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

/* NtQueryVirtualMemory 信息类（等价于 winternl.h 的 MemoryMappedFilenameInformation） */
#define SI_MemoryMappedFilenameInformation 2

typedef LONG(NTAPI *si_NtQueryVirtualMemory_t)(HANDLE, LPCVOID, ULONG,
                                               PVOID, SIZE_T, PSIZE_T);

static HMODULE g_module = NULL;
static HANDLE  g_pipe   = INVALID_HANDLE_VALUE;
static HANDLE  g_done   = NULL;
static DWORD   g_pid    = 0;
static HANDLE  g_log    = INVALID_HANDLE_VALUE;

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

/* ------------------------- 管道传输 ------------------------- */

static int write_all(const char *buf, DWORD len)
{
    DWORD sent = 0;
    while (sent < len) {
        DWORD w = 0;
        if (!WriteFile(g_pipe, buf + sent, len - sent, &w, NULL) || w == 0)
            return 0;
        sent += w;
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
    ok = write_all(frame, n + 4);
    si_free(text);
    free(frame);
    if (!ok) log_msg("send_json: 写管道失败 err=%lu bytes=%lu",
                     (unsigned long)GetLastError(), (unsigned long)(n + 4));
    return ok;
}

/* 帧长度可能被拆到多次 ReadFile 返回，必须读满 */
static int read_exact(void *buf, DWORD len)
{
    char *p = (char *)buf;
    DWORD got_total = 0;
    while (got_total < len) {
        DWORD got = 0;
        if (!ReadFile(g_pipe, p + got_total, len - got_total, &got, NULL))
            return 0;
        if (got == 0)
            return 0;
        got_total += got;
    }
    return 1;
}

/* 找到控制端 SuperInject.exe 的 PID，用于构造唯一的管道名 */
static DWORD find_controller_pid(void)
{
    HANDLE          snap;
    PROCESSENTRY32W pe;
    DWORD           srv = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 1;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"SuperInject.exe") == 0) {
                srv = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return srv ? srv : 1;
}

static int try_connect(const wchar_t *full)
{
    HANDLE h = CreateFileW(full, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        g_pipe = h;
        return 1;
    }
    return 0;
}

static int agent_connect(void)
{
    wchar_t full[320], name[160], suffix[64];
    DWORD   phase1_end, deadline;

    swprintf(suffix, 64, L"-%lu", g_pid);
    deadline = GetTickCount() + 60000;

    /* 阶段 1：按约定尝试（控制器通常就是 SuperInject.exe） */
    phase1_end = GetTickCount() + 3000;
    while (GetTickCount() < phase1_end) {
        swprintf(name, 160, L"SuperInject-%lu-%lu", find_controller_pid(), g_pid);
        swprintf(full, 320, L"\\\\.\\pipe\\%s", name);
        if (try_connect(full)) {
            log_msg("已连接(阶段1) %ls handle=%p", full, (void *)g_pipe);
            return 1;
        }
        if (WaitForSingleObject(g_done, 100) == WAIT_OBJECT_0) return 0;
    }
    log_msg("阶段1未找到 SuperInject.exe，转入管道枚举");

    /*
     * 阶段 2：枚举命名管道命名空间，寻找以 "-<本进程PID>" 结尾的
     * SuperInject 管道。这样即使控制器不是 SuperInject.exe
     * （例如从源码用 python 启动、或 exe 被重命名）也能连上。
     */
    while (GetTickCount() < deadline) {
        WIN32_FIND_DATAW fd;
        HANDLE f = FindFirstFileW(L"\\\\.\\pipe\\SuperInject-*", &fd);
        if (f != INVALID_HANDLE_VALUE) {
            do {
                size_t n  = wcslen(fd.cFileName);
                size_t sl = wcslen(suffix);
                if (n > sl && _wcsicmp(fd.cFileName + n - sl, suffix) == 0) {
                    swprintf(full, 320, L"\\\\.\\pipe\\%s", fd.cFileName);
                    if (try_connect(full)) {
                        FindClose(f);
                        log_msg("已连接(阶段2) %ls handle=%p", full, (void *)g_pipe);
                        return 1;
                    }
                    log_msg("连接 %ls 失败 err=%lu", full,
                            (unsigned long)GetLastError());
                }
            } while (FindNextFileW(f, &fd));
            FindClose(f);
        }
        if (WaitForSingleObject(g_done, 200) == WAIT_OBJECT_0) return 0;
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
    log_msg("发送 hello 版本=%s 镜像=%s", SI_VERSION, mpath);
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

/* ------------------------- 指令分发 ------------------------- */

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
                    si_json_array_push(mods, m);
                } while (Module32NextW(snap, &me));
            }
            CloseHandle(snap);
        }
        si_json_set_arr(out, "modules", mods);
        si_json_set_bool(out, "ok", 1);

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
        long long    addr = si_json_get_int(msg, "address", 0);
        const char  *hex  = si_json_get_str(msg, "hex", "");
        size_t       n    = strlen(hex) / 2;
        unsigned char *b  = si_hex_to_bytes(hex, NULL);
        if (b && n > 0) {
            SIZE_T put = 0;
            LPVOID target = (LPVOID)(uintptr_t)addr;
            int    ok = WriteProcessMemory(GetCurrentProcess(), target,
                                           b, (SIZE_T)n, &put) && put == n;
            int    patched = 0;
            DWORD  old_prot = 0;
            if (!ok) {
                /*
                 * 代码段/只读数据段（例如 PE 头）默认不可写。调试器要改这些地方
                 * 必须先临时换页属性 —— 改完立刻还原，并冲刷指令缓存。
                 */
                if (VirtualProtect(target, n, PAGE_EXECUTE_READWRITE, &old_prot)) {
                    put = 0;
                    ok = WriteProcessMemory(GetCurrentProcess(), target,
                                            b, (SIZE_T)n, &put) && put == n;
                    patched = 1;
                    if (ok) {
                        DWORD tmp;
                        FlushInstructionCache(GetCurrentProcess(), target, n);
                        VirtualProtect(target, n, old_prot, &tmp);
                    }
                }
            }
            if (ok) {
                si_json_set_bool(out, "ok", 1);
                si_json_set_int(out, "written", (long long)put);
                si_json_set_bool(out, "protection_changed", patched);
            } else {
                char msg_err[64];
                snprintf(msg_err, sizeof(msg_err),
                         "WriteProcessMemory 失败 (0x%lX)",
                         (unsigned long)GetLastError());
                si_json_set_bool(out, "ok", 0);
                si_json_set_str(out, "error", msg_err);
            }
        } else {
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "bad hex");
        }
        free(b);

    } else if (strcmp(type, "resources") == 0) {
        dump_resources(out);
        si_json_set_bool(out, "ok", 1);

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
         * 必须先关掉管道：句柄属于进程而不是线程，FreeLibraryAndExitThread
         * 只结束线程，句柄会一直留着，控制器永远等不到断开，重新注入就连不上。
         */
        if (g_pipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_pipe);
            g_pipe = INVALID_HANDLE_VALUE;
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
        DWORD len = 0;
        char *payload;
        DWORD t_read;
        if (g_pipe == INVALID_HANDLE_VALUE) break;
        t_read = GetTickCount();
        if (!read_exact(&len, 4) || len == 0) {
            log_msg("读帧头失败 err=%lu（对端已断开）", (unsigned long)GetLastError());
            break;
        }
        if (len > (32u * 1024u * 1024u)) {
            log_msg("帧长度异常 len=%lu，断开", (unsigned long)len);
            break;
        }
        log_msg("读到帧 len=%lu（等待 %lums）", (unsigned long)len,
                (unsigned long)(GetTickCount() - t_read));
        payload = (char *)malloc(len + 1);
        if (!payload) break;
        if (!read_exact(payload, len)) {
            log_msg("读帧正文失败 err=%lu len=%lu", (unsigned long)GetLastError(),
                    (unsigned long)len);
            free(payload);
            break;
        }
        payload[len] = 0;
        agent_handle(payload);
        free(payload);
    }
    log_msg("读循环结束，关闭管道");
    if (g_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
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
        g_done = CreateEventW(NULL, TRUE, FALSE, NULL);
        CreateThread(NULL, 0, agent_thread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        if (g_done) SetEvent(g_done);
        break;
    default:
        break;
    }
    return TRUE;
}
