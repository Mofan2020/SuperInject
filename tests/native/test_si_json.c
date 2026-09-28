/*
 * JSON 层自测（宿主编译器可直接编译运行，不需要 Windows）。
 *
 * 存在的理由：早期 si_json_array_push 与 obj_set 无条件互相回调，任何真的
 * 往数组里塞过元素的路径都会无限递归卡死 —— info / mem_regions / mem_search
 * 三个命令因此在真实注入后永久挂住，而数组恰好为空的 resources 看起来正常。
 * 这个自测把「数组能 push、能 dump、能解析回来」钉死成回归测试。
 *
 * 编译运行（任意平台）：
 *     cc -std=c99 -Wall -Wextra -Werror -I native \
 *        tests/native/test_si_json.c native/superinject_json.c -o test_si_json
 *     ./test_si_json
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "superinject_json.h"

static int g_fail = 0;

static void ck(int cond, const char *what)
{
    if (!cond) {
        printf("FAIL: %s\n", what);
        g_fail = 1;
    }
}

static int count_substr(const char *hay, const char *needle)
{
    int      n = 0;
    size_t   nl = strlen(needle);
    const char *p = hay;
    if (nl == 0) return 0;
    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += nl;
    }
    return n;
}

/* 1) 数组：push 必须终止、count 正确、dump 合法、能被自己解析回来 */
static void test_array_push(void)
{
    int    i;
    si_json *arr = si_json_new_array();
    char   *text;

    ck(arr != NULL, "new_array");
    ck(si_json_count(arr) == 0, "空数组 count == 0");

    for (i = 0; i < 2000; i++) {
        si_json *o = si_json_new();
        si_json_set_int(o, "i", i);
        si_json_set_str(o, "s", "C:\\Windows\\SYSTEM32\\kernel32.dll");
        si_json_set_bool(o, "ok", 1);
        si_json_array_push(arr, o);
    }
    ck(si_json_count(arr) == 2000, "push 2000 个元素后 count == 2000");

    text = si_json_dump(arr);
    ck(text != NULL, "dump 数组非空");
    if (text) {
        size_t n = strlen(text);
        ck(n > 2000 * 30, "dump 长度随元素数增长");
        ck(text[0] == '[' && text[n - 1] == ']', "dump 是数组文本");
        ck(count_substr(text, "\"i\":") == 2000, "dump 里元素个数正确");

        {
            si_json *back = si_json_parse(text);
            ck(back != NULL, "dump 结果可被自己解析");
            ck(si_json_count(back) == 2000, "解析回来元素数一致");
            if (back) {
                si_json *first = si_json_at(back, 0);
                si_json *last  = si_json_at(back, 1999);
                ck(first && si_json_get_int(first, "i", -1) == 0, "第 0 个元素 i == 0");
                ck(last && si_json_get_int(last, "i", -1) == 1999,
                   "第 1999 个元素 i == 1999");
                ck(si_json_at(back, 2000) == NULL, "越界取元素返回 NULL");
                si_json_free(back);
            }
        }
        si_free(text);
    }
    si_json_free(arr);
}

/* 2) 对象里嵌数组（info/mem_regions 的响应结构） */
static void test_object_with_array(void)
{
    si_json *out = si_json_new();
    si_json *mods = si_json_new_array();
    char    *text;

    si_json_set_str(out, "type", "response");
    si_json_set_int(out, "id", 7);
    {
        si_json *a = si_json_new();
        si_json_set_str(a, "name", "kernel32.dll");
        si_json_set_int(a, "base", 0x7FFD00000000LL);
        si_json_array_push(mods, a);
        a = si_json_new();
        si_json_set_str(a, "name", "ntdll.dll");
        si_json_array_push(mods, a);
    }
    si_json_set_arr(out, "modules", mods);
    si_json_set_bool(out, "ok", 1);

    ck(si_json_count(si_json_get(out, "modules")) == 2, "对象里的数组 count == 2");

    text = si_json_dump(out);
    ck(text != NULL, "dump 对象非空");
    if (text) {
        ck(strstr(text, "\"modules\":[") != NULL, "dump 含 modules 数组");
        ck(strstr(text, "kernel32.dll") != NULL, "dump 含数组元素内容");
        ck(count_substr(text, "\"name\":") == 2, "dump 里数组元素个数正确");

        {
            si_json *back = si_json_parse(text);
            ck(back != NULL, "对象可被解析回来");
            if (back) {
                si_json *arr = si_json_get(back, "modules");
                ck(arr != NULL, "解析回来能取到 modules");
                ck(si_json_count(arr) == 2, "解析回来 modules 元素数一致");
                ck(si_json_get_int(back, "id", -1) == 7, "解析回来 id == 7");
                ck(si_json_get_bool(back, "ok", 0) == 1, "解析回来 ok == true");
                ck(si_json_get_str(back, "type", "")[0] == 'r', "解析回来 type 正确");
                {
                    si_json *e0 = si_json_at(arr, 0);
                    ck(e0 && strcmp(si_json_get_str(e0, "name", ""), "kernel32.dll") == 0,
                       "数组第 0 个元素字段正确");
                    ck(e0 && si_json_get_int(e0, "base", 0) == 0x7FFD00000000LL,
                       "大整数（64 位地址）往返不丢精度");
                }
                si_json_free(back);
            }
        }
        si_free(text);
    }
    si_json_free(out);
}

/* 3) 解析器：数组/对象/字符串转义/类型都要对 */
static void test_parse(void)
{
    const char *doc =
        "{\"a\":[1,2,3],\"b\":{\"c\":[true,false,null]},"
        "\"d\":\"引号\\\"与反斜杠\\\\\",\"e\":-12}";
    si_json *j = si_json_parse(doc);
    si_json *a;

    ck(j != NULL, "解析混合文档");
    if (!j) return;

    a = si_json_get(j, "a");
    ck(a != NULL && si_json_count(a) == 3, "数组元素数 == 3");
    /*
     * 标量数组元素没有 key，公开接口只提供 si_json_at + si_json_dump
     * （DLL 侧只会收到扁平的命令对象，不需要按 key 读数组标量）。
     */
    {
        char *t = si_json_dump(si_json_at(a, 2));
        ck(t != NULL && strcmp(t, "3") == 0, "数组第 2 个元素是 3");
        si_free(t);
    }

    a = si_json_get(j, "b");
    ck(a != NULL, "取到嵌套对象 b");
    if (a) {
        si_json *c = si_json_get(a, "c");
        ck(c != NULL && si_json_count(c) == 3, "嵌套数组元素数 == 3");
        ck(c && si_json_at(c, 2) != NULL, "嵌套数组含 null");
    }

    ck(strcmp(si_json_get_str(j, "d", ""), "引号\"与反斜杠\\") == 0, "字符串转义往返");
    ck(si_json_get_int(j, "e", 0) == -12, "负数解析");

    /* dump 后再解析一次必须结构等价 */
    {
        char *text = si_json_dump(j);
        si_json *back = text ? si_json_parse(text) : NULL;
        ck(back != NULL, "二次往返可解析");
        if (back) {
            si_json *a2 = si_json_get(back, "a");
            ck(a2 && si_json_count(a2) == 3, "二次往返数组元素数一致");
            ck(strcmp(si_json_get_str(back, "d", ""), "引号\"与反斜杠\\") == 0,
               "二次往返字符串一致");
            si_json_free(back);
        }
        si_free(text);
    }
    si_json_free(j);
}

/* 4) 畸形输入不能崩、不能死循环 */
static void test_bad_input(void)
{
    static const char *bad[] = {
        "", "{", "[", "[1,", "{\"a\":,}", "{\"a\" 1}", "tru", "\"未闭合",
        "{\"a\":[1,2}", "[[[[[[[[[[", NULL
    };
    int i;
    for (i = 0; bad[i]; i++) {
        si_json *j = si_json_parse(bad[i]);
        if (j) si_json_free(j);   /* 能解析就解析，不能解析必须返回 NULL 而不是崩 */
    }
    ck(1, "畸形输入全部安全返回");
}

/* 5) hex 工具（mem_read/mem_write 用它） */
static void test_hex(void)
{
    static const char *hex = "DEADBEEF00FF";
    size_t n = 0;
    unsigned char *b = (unsigned char *)si_hex_to_bytes(hex, &n);
    ck(b != NULL && n == 6, "hex 长度正确");
    ck(b && b[0] == 0xDE && b[1] == 0xAD && b[5] == 0xFF, "hex 数值正确");
    if (b) {
        char *back = si_bytes_to_hex(b, n);
        ck(back != NULL && strcmp(back, hex) == 0, "hex 往返一致");
        si_free(back);
    }
    si_free(b);
    ck(si_hex_to_bytes("ZZ", NULL) == NULL, "非法 hex 返回 NULL");
    ck(si_hex_to_bytes("", NULL) == NULL, "空 hex 返回 NULL");
}

int main(void)
{
    test_array_push();
    test_object_with_array();
    test_parse();
    test_bad_input();
    test_hex();

    if (g_fail) {
        printf("SI_JSON_SELFTEST_FAILED\n");
        return 1;
    }
    printf("SI_JSON_SELFTEST_OK\n");
    return 0;
}
