/*
 * SuperInject 极简 JSON 实现（C99，零依赖）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>   /* 只有尾部的 si_mem_type/si_is_elevated 需要；JSON 层本身是纯 C99 */
#endif
#include "superinject_json.h"

typedef struct si_member {
    char              *key;
    si_json           *val;
    struct si_member  *next;
} si_member;

struct si_json {
    si_type    type;
    double     num;
    int        bval;
    char      *str;
    si_member *head;
    si_member *tail;
    size_t     count;   /* 数组元素数 */
};

static si_json *j_new(si_type t)
{
    si_json *j = (si_json *)calloc(1, sizeof(si_json));
    if (j) j->type = t;
    return j;
}

si_json *si_json_new(void)      { return j_new(SI_OBJ); }
si_json *si_json_new_array(void) { return j_new(SI_ARR); }

void si_free(void *p) { free(p); }

void si_json_free(si_json *j)
{
    si_member *m;
    if (!j) return;
    m = j->head;
    while (m) {
        si_member *nx = m->next;
        free(m->key);
        si_json_free(m->val);
        free(m);
        m = nx;
    }
    free(j->str);
    free(j);
}

/*
 * 自带 strdup：本层不依赖 _strdup（MSVC 专有），保持纯 C99、可在任意主机上编译自测。
 */
static char *si_dup(const char *s)
{
    size_t n;
    char  *p;
    if (!s) s = "";
    n = strlen(s) + 1;
    p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static void obj_set(si_json *j, const char *key, si_json *val)
{
    si_member *m;
    if (!j || !val) { si_json_free(val); return; }
    if (j->type != SI_OBJ && j->type != SI_ARR) { si_json_free(val); return; }
    m = (si_member *)calloc(1, sizeof(si_member));
    if (!m) { si_json_free(val); return; }
    m->key = si_dup(key ? key : "");   /* 数组元素 key 为空串，序列化时忽略 */
    m->val = val;
    if (j->tail) j->tail->next = m; else j->head = m;
    j->tail = m;
    j->count++;
}

void si_json_set_str(si_json *j, const char *key, const char *val)
{
    si_json *v = j_new(SI_STR);
    if (!v) return;
    v->str = si_dup(val ? val : "");
    obj_set(j, key, v);
}

void si_json_set_int(si_json *j, const char *key, long long val)
{
    si_json *v = j_new(SI_NUM);
    if (!v) return;
    v->num = (double)val;
    obj_set(j, key, v);
}

void si_json_set_bool(si_json *j, const char *key, int val)
{
    si_json *v = j_new(SI_BOOL);
    if (!v) return;
    v->bval = val ? 1 : 0;
    obj_set(j, key, v);
}

void si_json_set_obj(si_json *j, const char *key, si_json *val) { obj_set(j, key, val); }
void si_json_set_arr(si_json *j, const char *key, si_json *val) { obj_set(j, key, val); }

void si_json_array_push(si_json *arr, si_json *item)
{
    if (!arr || !item) { si_json_free(item); return; }
    /*
     * 只走 obj_set 一条路（obj_set 对 SI_ARR 也是直接追加成员、自增 count）。
     * 早期版本这里 obj_set 又回调本函数，两个函数无限互递归：凡是真往
     * 数组里塞过元素的命令（info 模块表 / mem_regions 内存区 / mem_search
     * 匹配结果）全部永久卡死，而数组恰好为空的 resources 反而「正常」，
     * 解析器解析数组走同一条路 —— 含数组的 JSON 也解析不了。
     */
    obj_set(arr, "", item);
}

size_t si_json_count(si_json *arr) { return arr ? arr->count : 0; }

si_json *si_json_get(si_json *j, const char *key)
{
    si_member *m;
    if (!j) return NULL;
    for (m = j->head; m; m = m->next) {
        if (j->type == SI_ARR || strcmp(m->key, key) == 0) return m->val;
    }
    return NULL;
}

si_json *si_json_at(si_json *arr, size_t idx)
{
    size_t i = 0;
    si_member *m;
    if (!arr) return NULL;
    for (m = arr->head; m; m = m->next, i++) {
        if (i == idx) return m->val;
    }
    return NULL;
}

const char *si_json_get_str(si_json *j, const char *key, const char *def)
{
    si_json *v = si_json_get(j, key);
    return (v && v->type == SI_STR) ? v->str : def;
}

long long si_json_get_int(si_json *j, const char *key, long long def)
{
    si_json *v = si_json_get(j, key);
    if (!v) return def;
    if (v->type == SI_NUM) return (long long)v->num;
    if (v->type == SI_BOOL) return v->bval;
    if (v->type == SI_STR) return strtoll(v->str, NULL, 10);
    return def;
}

int si_json_get_bool(si_json *j, const char *key, int def)
{
    si_json *v = si_json_get(j, key);
    if (!v) return def;
    if (v->type == SI_BOOL) return v->bval;
    if (v->type == SI_NUM)  return v->num != 0;
    return def;
}

/* ----------------------------- 序列化 ----------------------------- */

typedef struct { char *buf; size_t len, cap; } sbuf;

static void sb_need(sbuf *b, size_t extra)
{
    if (b->len + extra + 1 > b->cap) {
        size_t ncap = b->cap ? b->cap : 256;
        while (ncap < b->len + extra + 1) ncap *= 2;
        b->buf = (char *)realloc(b->buf, ncap);
        b->cap = ncap;
    }
}

static void sb_puts(sbuf *b, const char *s)
{
    size_t n = strlen(s);
    sb_need(b, n);
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = 0;
}

static void sb_putc(sbuf *b, char c)
{
    sb_need(b, 1);
    b->buf[b->len++] = c;
    b->buf[b->len] = 0;
}

static void dump_str(sbuf *b, const char *s)
{
    sb_putc(b, '"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  sb_puts(b, "\\\""); break;
        case '\\': sb_puts(b, "\\\\"); break;
        case '\n': sb_puts(b, "\\n");  break;
        case '\r': sb_puts(b, "\\r");  break;
        case '\t': sb_puts(b, "\\t");  break;
        case '\b': sb_puts(b, "\\b");  break;
        case '\f': sb_puts(b, "\\f");  break;
        default:
            if (c < 0x20) {
                char tmp[8];
                snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                sb_puts(b, tmp);
            } else {
                sb_putc(b, (char)c);
            }
        }
    }
    sb_putc(b, '"');
}

static void dump_val(sbuf *b, si_json *v)
{
    char tmp[64];
    if (!v) { sb_puts(b, "null"); return; }
    switch (v->type) {
    case SI_NULL: sb_puts(b, "null"); break;
    case SI_BOOL: sb_puts(b, v->bval ? "true" : "false"); break;
    case SI_NUM:
        if (v->num == (double)(long long)v->num)
            snprintf(tmp, sizeof(tmp), "%lld", (long long)v->num);
        else
            snprintf(tmp, sizeof(tmp), "%g", v->num);
        sb_puts(b, tmp);
        break;
    case SI_STR: dump_str(b, v->str ? v->str : ""); break;
    case SI_ARR: {
        si_member *m;
        int first = 1;
        sb_putc(b, '[');
        for (m = v->head; m; m = m->next) {
            if (!first) sb_putc(b, ',');
            first = 0;
            dump_val(b, m->val);
        }
        sb_putc(b, ']');
        break;
    }
    case SI_OBJ: {
        si_member *m;
        int first = 1;
        sb_putc(b, '{');
        for (m = v->head; m; m = m->next) {
            if (!first) sb_putc(b, ',');
            first = 0;
            dump_str(b, m->key ? m->key : "");
            sb_putc(b, ':');
            dump_val(b, m->val);
        }
        sb_putc(b, '}');
        break;
    }
    }
}

char *si_json_dump(si_json *j)
{
    sbuf b;
    b.buf = NULL; b.len = 0; b.cap = 0;
    sb_need(&b, 0);
    b.buf[0] = 0;
    dump_val(&b, j);
    if (!b.buf) {
        b.buf = (char *)calloc(1, 1);
    }
    return b.buf;
}

/* ----------------------------- 反序列化 ----------------------------- */

typedef struct { const char *p; int ok; } parser;

static void skip_ws(parser *ps)
{
    while (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r')
        ps->p++;
}

static si_json *parse_val(parser *ps);

static char *parse_string_raw(parser *ps)
{
    sbuf b;
    if (*ps->p != '"') { ps->ok = 0; return NULL; }
    ps->p++;
    b.buf = NULL; b.len = 0; b.cap = 0;
    sb_need(&b, 0);
    b.buf[0] = 0;
    while (*ps->p && *ps->p != '"') {
        if (*ps->p == '\\') {
            ps->p++;
            switch (*ps->p) {
            case 'n': sb_putc(&b, '\n'); ps->p++; break;
            case 't': sb_putc(&b, '\t'); ps->p++; break;
            case 'r': sb_putc(&b, '\r'); ps->p++; break;
            case 'b': sb_putc(&b, '\b'); ps->p++; break;
            case 'f': sb_putc(&b, '\f'); ps->p++; break;
            case 'u': {
                unsigned code = 0;
                int i;
                ps->p++;
                for (i = 0; i < 4 && *ps->p; i++) {
                    char c = *ps->p++;
                    code <<= 4;
                    if (c >= '0' && c <= '9') code |= (unsigned)(c - '0');
                    else if (c >= 'a' && c <= 'f') code |= (unsigned)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') code |= (unsigned)(c - 'A' + 10);
                    else { ps->ok = 0; }
                }
                if (code < 0x80) {
                    sb_putc(&b, (char)code);
                } else if (code < 0x800) {
                    sb_putc(&b, (char)(0xC0 | (code >> 6)));
                    sb_putc(&b, (char)(0x80 | (code & 0x3F)));
                } else {
                    sb_putc(&b, (char)(0xE0 | (code >> 12)));
                    sb_putc(&b, (char)(0x80 | ((code >> 6) & 0x3F)));
                    sb_putc(&b, (char)(0x80 | (code & 0x3F)));
                }
                break;
            }
            default: sb_putc(&b, *ps->p); ps->p++; break;
            }
        } else {
            sb_putc(&b, *ps->p++);
        }
    }
    if (*ps->p != '"') { ps->ok = 0; free(b.buf); return NULL; }
    ps->p++;
    return b.buf;
}

static si_json *parse_val(parser *ps)
{
    skip_ws(ps);
    if (*ps->p == '{') {
        si_json *o = si_json_new();
        ps->p++;
        skip_ws(ps);
        if (*ps->p == '}') { ps->p++; return o; }
        for (;;) {
            char *key;
            si_json *val;
            skip_ws(ps);
            key = parse_string_raw(ps);
            if (!ps->ok) { si_json_free(o); return NULL; }
            skip_ws(ps);
            if (*ps->p != ':') { free(key); si_json_free(o); ps->ok = 0; return NULL; }
            ps->p++;
            val = parse_val(ps);
            if (!val) { free(key); si_json_free(o); return NULL; }
            obj_set(o, key ? key : "", val);
            free(key);
            skip_ws(ps);
            if (*ps->p == ',') { ps->p++; continue; }
            if (*ps->p == '}') { ps->p++; return o; }
            ps->ok = 0; si_json_free(o); return NULL;
        }
    }
    if (*ps->p == '[') {
        si_json *a = si_json_new_array();
        ps->p++;
        skip_ws(ps);
        if (*ps->p == ']') { ps->p++; return a; }
        for (;;) {
            si_json *val = parse_val(ps);
            if (!val) { si_json_free(a); return NULL; }
            si_json_array_push(a, val);
            skip_ws(ps);
            if (*ps->p == ',') { ps->p++; continue; }
            if (*ps->p == ']') { ps->p++; return a; }
            ps->ok = 0; si_json_free(a); return NULL;
        }
    }
    if (*ps->p == '"') {
        si_json *s;
        char   *raw = parse_string_raw(ps);
        if (!raw) return NULL;
        s = j_new(SI_STR);
        s->str = raw;
        return s;
    }
    if (strncmp(ps->p, "true", 4) == 0) {
        si_json *v = j_new(SI_BOOL); v->bval = 1; ps->p += 4; return v;
    }
    if (strncmp(ps->p, "false", 5) == 0) {
        si_json *v = j_new(SI_BOOL); v->bval = 0; ps->p += 5; return v;
    }
    if (strncmp(ps->p, "null", 4) == 0) {
        ps->p += 4;
        return j_new(SI_NULL);
    }
    if (*ps->p == '-' || (*ps->p >= '0' && *ps->p <= '9')) {
        si_json *v = j_new(SI_NUM);
        char *endp = NULL;
        v->num = strtod(ps->p, &endp);
        if (endp == ps->p) { si_json_free(v); ps->ok = 0; return NULL; }
        ps->p = endp;
        return v;
    }
    ps->ok = 0;
    return NULL;
}

si_json *si_json_parse(const char *text)
{
    parser ps;
    si_json *v;
    ps.p = text ? text : "";
    ps.ok = 1;
    v = parse_val(&ps);
    if (!ps.ok) { si_json_free(v); return NULL; }
    return v;
}

/* ----------------------------- 工具 ----------------------------- */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void *si_hex_to_bytes(const char *hex, size_t *out_len)
{
    size_t n, i;
    unsigned char *buf;
    if (!hex) return NULL;
    n = strlen(hex) / 2;
    if (n == 0) return NULL;
    buf = (unsigned char *)malloc(n);
    if (!buf) return NULL;
    for (i = 0; i < n; i++) {
        int hi = hexval(hex[i * 2]);
        int lo = hexval(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) { free(buf); return NULL; }
        buf[i] = (unsigned char)((hi << 4) | lo);
    }
    if (out_len) *out_len = n;
    return buf;
}

char *si_bytes_to_hex(const void *bytes, size_t len)
{
    static const char *digits = "0123456789ABCDEF";
    const unsigned char *p = (const unsigned char *)bytes;
    char *out = (char *)malloc(len * 2 + 1);
    size_t i;
    if (!out) return NULL;
    for (i = 0; i < len; i++) {
        out[i * 2]     = digits[p[i] >> 4];
        out[i * 2 + 1] = digits[p[i] & 0x0F];
    }
    out[len * 2] = 0;
    return out;
}

#if defined(_WIN32)

const char *si_mem_type(unsigned long protect)
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

int si_is_elevated(void)
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

#endif /* _WIN32：非 Windows 主机上只编译 JSON 层，便于用本机编译器做单元测试 */
