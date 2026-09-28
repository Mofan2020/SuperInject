/*
 * SuperInject Agent - 被注入的 DLL
 *
 * 目标：在被调试进程内建立一条反向控制通道（命名管道），
 * 接受 SuperInject 控制器的指令：
 *   ping / info / mem_regions / mem_search / mem_read / mem_write
 *   resources（提取加载模块中的图片/音视频资源）
 *   freeze（冻结主线程）/ terminate（自我结束）/ unload（自行卸载）
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "superinject_json.h"

#define SI_VERSION "1.0.0"

static HMODULE g_module = NULL;
static HANDLE  g_pipe   = INVALID_HANDLE_VALUE;
static HANDLE  g_done   = NULL;
static DWORD   g_pid    = 0;

/* 资源提取输出目录与结果数组（仅在命令处理线程内使用） */
static char  g_out_dir[MAX_PATH] = {0};
static int   g_res_seq = 0;

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
    if (!text) return 0;
    n = (DWORD)strlen(text);
    ok = write_all((const char *)&n, 4) && write_all(text, n);
    si_free(text);
    return ok;
}

/* 找到控制端 SuperInject.exe 的 PID，用于构造唯一的管道名 */
static DWORD find_controller_pid(void)
{
    HANDLE          snap;
    PROCESSENTRY32W pe;
    DWORD           srv = 0;
    WCHAR           self[MAX_PATH];

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 1;
    pe.dwSize = sizeof(pe);
    GetModuleFileNameW(NULL, self, MAX_PATH);
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
        if (try_connect(full)) return 1;
        if (WaitForSingleObject(g_done, 100) == WAIT_OBJECT_0) return 0;
    }

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
                        return 1;
                    }
                }
            } while (FindNextFileW(f, &fd));
            FindClose(f);
        }
        if (WaitForSingleObject(g_done, 200) == WAIT_OBJECT_0) return 0;
    }
    return 0;
}

static void send_hello(void)
{
    si_json     *j = si_json_new();
    SYSTEM_INFO  sys;
    WCHAR        wpath[MAX_PATH];
    char         mpath[MAX_PATH];

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
    send_json(j);
    si_json_free(j);
}

/* ------------------------- 内存搜索 ------------------------- */

static int mem_search(const unsigned char *pat, size_t plen,
                      const unsigned char *mask, size_t max_results,
                      si_json *out)
{
    si_json                 *arr = si_json_new_array();
    MEMORY_BASIC_INFORMATION mbi;
    SYSTEM_INFO              sys;
    unsigned char           *base, *end;
    DWORD                    old = 0;
    size_t                   found = 0;

    GetSystemInfo(&sys);
    base = (unsigned char *)sys.lpMinimumApplicationAddress;
    end  = (unsigned char *)sys.lpMaximumApplicationAddress;

    while (base < end && found < max_results) {
        int changed = 0;
        if (VirtualQuery(base, &mbi, sizeof(mbi)) == 0) break;
        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS &&
            mbi.Protect != PAGE_GUARD && plen > 0 &&
            mbi.RegionSize >= plen) {
            if (mbi.Protect == PAGE_EXECUTE_READWRITE ||
                mbi.Protect == PAGE_READWRITE ||
                mbi.Protect == PAGE_WRITECOPY) {
                changed = 1;
            } else if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize,
                                      PAGE_READWRITE, &old)) {
                changed = 1;
            }
            if (changed) {
                size_t i, limit = mbi.RegionSize - plen;
                const unsigned char *p = (const unsigned char *)mbi.BaseAddress;
                for (i = 0; i <= limit; i++) {
                    size_t k = 0;
                    while (k < plen) {
                        if (mask && mask[k] == 0) { k++; continue; }
                        if (p[i + k] != pat[k]) break;
                        k++;
                    }
                    if (k == plen) {
                        si_json *o = si_json_new();
                        si_json_set_int(o, "address", (long long)(uintptr_t)(p + i));
                        si_json_set_int(o, "region", (long long)(uintptr_t)mbi.BaseAddress);
                        si_json_set_int(o, "size", (long long)mbi.RegionSize);
                        si_json_set_int(o, "protect", (long long)mbi.Protect);
                        si_json_set_str(o, "type", si_mem_type(mbi.Protect));
                        si_json_array_push(arr, o);
                        if (++found >= max_results) break;
                    }
                }
                if (old != 0 && mbi.Protect != PAGE_EXECUTE_READWRITE &&
                    mbi.Protect != PAGE_READWRITE &&
                    mbi.Protect != PAGE_WRITECOPY) {
                    DWORD tmp;
                    VirtualProtect(mbi.BaseAddress, mbi.RegionSize,
                                   mbi.Protect, &tmp);
                }
            }
        }
        if (mbi.RegionSize == 0) break;
        base = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
    }
    si_json_set_arr(out, "results", arr);
    si_json_set_int(out, "count", (long long)found);
    return (int)found;
}

/* ------------------------- 资源提取 ------------------------- */

static si_json *g_res_arr = NULL;

static BOOL CALLBACK res_name_cb(HMODULE mod, LPCWSTR type, LPWSTR name, LONG_PTR lp)
{
    HRSRC  hres;
    DWORD  size;
    HGLOBAL hglob;
    const unsigned char *ptr;
    (void)lp;

    hres = FindResourceW(mod, name, type);
    if (!hres) return TRUE;
    size = SizeofResource(mod, hres);
    if (size == 0 || size > 512u * 1024u * 1024u) return TRUE;
    hglob = LoadResource(mod, hres);
    if (!hglob) return TRUE;
    ptr = (const unsigned char *)LockResource(hglob);
    if (ptr && g_res_arr) {
        const unsigned char *p = ptr;
        WORD   rtype = IS_INTRESOURCE(type) ? (WORD)(uintptr_t)type : 0;
        const char *ext = "bin";
        char   path[MAX_PATH * 2];
        char   mpath[MAX_PATH * 2];

        if (size >= 3 && p[0] == 0x89 && p[1] == 'P' && p[2] == 'N') ext = "png";
        else if (size >= 3 && p[0] == 0xFF && p[1] == 0xD8) ext = "jpg";
        else if (size >= 6 && memcmp(p, "GIF8", 4) == 0) ext = "gif";
        else if (size >= 2 && p[0] == 'B' && p[1] == 'M') ext = "bmp";
        else if (size >= 4 && memcmp(p, "RIFF", 4) == 0) ext = "wav";
        else if (size >= 4 && memcmp(p, "OggS", 4) == 0) ext = "ogg";
        else if (size >= 3 && memcmp(p, "ID3", 3) == 0) ext = "mp3";
        else if (rtype == 2)  ext = "bmp";   /* RT_BITMAP */
        else if (rtype == 3)  ext = "ico";   /* RT_ICON   */
        else if (rtype == 1)  ext = "cur";   /* RT_CURSOR */

        snprintf(path, sizeof(path), "%s\\res_%lu_%d.%s",
                 g_out_dir, g_pid, ++g_res_seq, ext);
        {
            HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (f != INVALID_HANDLE_VALUE) {
                DWORD w = 0;
                WriteFile(f, ptr, size, &w, NULL);
                CloseHandle(f);
            }
        }
        {
            WCHAR wmod[MAX_PATH];
            si_json *o = si_json_new();
            si_json_set_int(o, "type", (long long)rtype);
            si_json_set_str(o, "ext", ext);
            si_json_set_int(o, "size", (long long)size);
            si_json_set_str(o, "path", path);
            if (GetModuleFileNameW(mod, wmod, MAX_PATH))
                utf8_path(wmod, mpath, MAX_PATH * 2);
            else
                mpath[0] = 0;
            si_json_set_str(o, "module", mpath);
            si_json_array_push(g_res_arr, o);
        }
    }
    FreeResource(hglob);
    return TRUE;
}

static BOOL CALLBACK res_type_cb(HMODULE mod, LPWSTR type, LONG_PTR lp)
{
    (void)lp;
    EnumResourceNamesW(mod, type, res_name_cb, 0);
    return TRUE;
}

static int dump_resources(si_json *out)
{
    HANDLE         snap;
    MODULEENTRY32W me;
    WCHAR          tmp[MAX_PATH];

    if (GetTempPathW(MAX_PATH, tmp) == 0) return 0;
    {
        wchar_t sub[64];
        int    i;
        swprintf(sub, 64, L"SuperInject\\%lu", g_pid);
        lstrcatW(tmp, sub);
        CreateDirectoryW(tmp, NULL);
        /* 多级目录逐级创建 */
        for (i = 0; tmp[i]; i++) {
            if (tmp[i] == '\\' && i > 3) {
                tmp[i] = 0;
                CreateDirectoryW(tmp, NULL);
                tmp[i] = '\\';
            }
        }
    }
    utf8_path(tmp, g_out_dir, MAX_PATH);
    g_res_seq = 0;
    g_res_arr = si_json_new_array();

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_pid);
    if (snap != INVALID_HANDLE_VALUE) {
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                HMODULE mod = (HMODULE)me.modBaseAddr;
                if (mod) EnumResourceTypesW(mod, res_type_cb, 0);
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }
    {
        int n = (int)si_json_count(g_res_arr);
        si_json_set_arr(out, "items", g_res_arr);
        g_res_arr = NULL;
        si_json_set_str(out, "dir", g_out_dir);
        si_json_set_int(out, "count", (long long)n);
        return n;
    }
}

/* ------------------------- 指令分发 ------------------------- */

static void agent_handle(const char *text)
{
    si_json     *msg = si_json_parse(text);
    const char  *type;
    si_json     *out;

    if (!msg) {
        out = si_json_new();
        si_json_set_str(out, "type", "error");
        si_json_set_str(out, "error", "invalid json");
        send_json(out);
        si_json_free(out);
        return;
    }

    type  = si_json_get_str(msg, "type", "");
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
            si_json_set_bool(out, "ok", 0);
            si_json_set_int(out, "error", (long long)GetLastError());
        }

    } else if (strcmp(type, "mem_write") == 0) {
        long long    addr = si_json_get_int(msg, "address", 0);
        const char  *hex  = si_json_get_str(msg, "hex", "");
        size_t       n    = strlen(hex) / 2;
        unsigned char *b  = si_hex_to_bytes(hex, NULL);
        if (b && n > 0) {
            SIZE_T put = 0;
            if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)addr,
                                   b, (SIZE_T)n, &put)) {
                si_json_set_bool(out, "ok", 1);
                si_json_set_int(out, "written", (long long)put);
            } else {
                si_json_set_bool(out, "ok", 0);
                si_json_set_int(out, "error", (long long)GetLastError());
            }
        } else {
            si_json_set_bool(out, "ok", 0);
            si_json_set_str(out, "error", "bad hex");
        }
        free(b);

    } else if (strcmp(type, "resources") == 0) {
        dump_resources(out);
        si_json_set_bool(out, "ok", 1);

    } else if (strcmp(type, "freeze") == 0) {
        si_json_set_bool(out, "ok", 1);
        send_json(out);
        si_json_free(out);
        si_json_free(msg);
        Sleep(300);
        for (;;) Sleep(1000);   /* 永久阻塞该 agent 线程，即“冻结” */

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
        Sleep(300);
        FreeLibraryAndExitThread(g_module, 0);

    } else {
        si_json_set_bool(out, "ok", 0);
        si_json_set_str(out, "error", "unknown command");
    }

    send_json(out);
    si_json_free(out);
    si_json_free(msg);
}

static DWORD WINAPI agent_thread(LPVOID param)
{
    (void)param;
    if (!agent_connect()) return 0;
    send_hello();

    for (;;) {
        DWORD len = 0, got = 0;
        char *payload;
        if (!ReadFile(g_pipe, &len, 4, &got, NULL) || got != 4 || len == 0) break;
        if (len > (32u * 1024u * 1024u)) break;
        payload = (char *)malloc(len + 1);
        if (!payload) break;
        if (!ReadFile(g_pipe, payload, len, &got, NULL) || got == 0) {
            free(payload);
            break;
        }
        payload[got] = 0;
        agent_handle(payload);
        free(payload);
    }
    CloseHandle(g_pipe);
    g_pipe = INVALID_HANDLE_VALUE;
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
