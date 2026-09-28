/*
 * SuperInject 极简 JSON / 工具库（被注入 DLL 使用，零外部依赖）
 */
#ifndef SUPERINJECT_JSON_H
#define SUPERINJECT_JSON_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SI_JSON_PROTO 1

typedef enum {
    SI_NULL, SI_BOOL, SI_NUM, SI_STR, SI_ARR, SI_OBJ
} si_type;

typedef struct si_json si_json;

/* 构造 */
si_json *si_json_new(void);
si_json *si_json_new_array(void);
void     si_json_free(si_json *j);

/* 赋值（嵌套对象/数组所有权转移给父节点） */
void si_json_set_str(si_json *j, const char *key, const char *val);
void si_json_set_int(si_json *j, const char *key, long long val);
void si_json_set_bool(si_json *j, const char *key, int val);
void si_json_set_obj(si_json *j, const char *key, si_json *val);
void si_json_set_arr(si_json *j, const char *key, si_json *val);
void si_json_array_push(si_json *arr, si_json *item);
size_t si_json_count(si_json *arr);

/* 读取（对象） */
const char *si_json_get_str(si_json *j, const char *key, const char *def);
long long    si_json_get_int(si_json *j, const char *key, long long def);
int          si_json_get_bool(si_json *j, const char *key, int def);
si_json     *si_json_get(si_json *j, const char *key);
si_json     *si_json_at(si_json *arr, size_t idx);

/* 序列化 / 反序列化 */
char    *si_json_dump(si_json *j);      /* 调用方用 si_free 释放 */
si_json *si_json_parse(const char *text);

/* 工具 */
void       *si_hex_to_bytes(const char *hex, size_t *out_len); /* malloc */
char      *si_bytes_to_hex(const void *bytes, size_t len);      /* si_free */
void        si_free(void *p);

#if defined(_WIN32)
/*
 * Win32 专用（只有 agent.dll 用）。参数故意写成 unsigned long 而不是 DWORD：
 * 本头文件不拉 windows.h，保持自包含，JSON 层才能被本机编译器直接编译自测。
 */
const char *si_mem_type(unsigned long protect);
int         si_is_elevated(void);
#endif

#ifdef __cplusplus
}
#endif
#endif /* SUPERINJECT_JSON_H */
