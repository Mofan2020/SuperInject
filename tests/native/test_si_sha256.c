/*
 * SHA-256 自测 —— 验证 native/agent.c 里 si_sha256 系列算法。
 *
 * 不直接 #include agent.c（它引了 windows.h）——只是把同款算法搬过来验证。
 * 算法必须与 agent.c 一一对应；修改时两边必须同步。
 *
 * 用 cc -std=c99 -Wall -Wextra -Werror 编译跑。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

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
    unsigned long long bits = c->bits + (unsigned long long)c->buf_len * 8;
    unsigned char len_be[8];
    int i;
    int first_block_had_80;
    if (c->buf_len >= 56) {
        if (c->buf_len == 64) {
            si_sha256_compress(c, c->buf);
            c->bits += (unsigned long long)sizeof(c->buf) * 8;
            c->buf_len = 0;
        } else {
            si_sha256_update(c, pad, 64 - c->buf_len);
        }
        first_block_had_80 = 1;
    } else {
        first_block_had_80 = 0;
    }
    if (!first_block_had_80) {
        si_sha256_update(c, pad, 56 - c->buf_len);
    } else {
        static const unsigned char zeros[56] = { 0 };
        si_sha256_update(c, zeros, 56 - c->buf_len);
    }
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

static void si_sha256(const void *data, size_t len, unsigned char out[32])
{
    si_sha256_ctx c;
    si_sha256_init(&c);
    si_sha256_update(&c, data, len);
    si_sha256_final(&c, out);
}

static void hex(const unsigned char *b, size_t n, char *out)
{
    static const char *dig = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[i * 2]     = dig[b[i] >> 4];
        out[i * 2 + 1] = dig[b[i] & 0xf];
    }
    out[n * 2] = 0;
}

static int check(const char *label, const void *msg, size_t len, const char *want)
{
    unsigned char h[32];
    char got[65];
    si_sha256(msg, len, h);
    hex(h, 32, got);
    if (strcmp(got, want) == 0) {
        printf("[PASS] %-20s len=%-7zu %s\n", label, len, got);
        return 1;
    }
    printf("[FAIL] %-20s len=%-7zu\n  want %s\n  got  %s\n", label, len, want, got);
    return 0;
}

int main(void)
{
    int total = 0, passed = 0;
    /* FIPS 180-4 标准向量（含一个 1MB 边界覆盖）。 */
    passed += check("empty", "", 0,
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); total++;
    passed += check("abc", "abc", 3,
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"); total++;
    passed += check("abcdbcde...56",
                    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"); total++;
    /* 边界：64 字节 / 65 字节 / 119 字节（差一字节到 120）/ 120 字节（恰好 56 之后） */
    passed += check("64 zero bytes",
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 64,
                    "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"); total++;
    passed += check("55 zero bytes",
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0", 55,
                    "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7"); total++;
    passed += check("63 zero bytes", "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                     "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                     "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                     "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 63,
                    "c7723fa1e0127975e49e62e753db53924c1bd84b8ac1ac08df78d09270f3d971"); total++;
    passed += check("65 zero bytes",
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0", 65,
                    "98ce42deef51d40269d542f5314bef2c7468d401ad5d85168bfab4c0108f75f7"); total++;
    /* 56→57 字节：最后一块大小从刚到 56 撑到 57，要额外压一块 */
    passed += check("56 zero bytes", "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                     "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                     "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                     "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 56,
                    "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb"); total++;
    passed += check("57 zero bytes",
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                    "\0\0\0\0\0\0\0\0", 57,
                    "65a16cb7861335d5ace3c60718b5052e44660726da4cd13bb745381b235a1785"); total++;
    /* 修正上一条：56 字节 "a" */
    passed += check("56 'a' bytes",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 56,
                    "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"); total++;
    passed += check("quick-fox 43", "The quick brown fox jumps over the lazy dog", 43,
                    "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"); total++;
    passed += check("quick-fox 86",
                    "The quick brown fox jumps over the lazy dog"
                    "The quick brown fox jumps over the lazy dog", 86,
                    "cce97087f477acafa60f6e74bfe5dd17d9d099b87fb93a2fb779dbb527a08fe7"); total++;
    /* 1MB "a" —— SHA256 块大小 = 64 字节，1MB = 16384 块。重点验 padding & 多压缩。 */
    if (1) {
        size_t n = 1000000;
        unsigned char *big = (unsigned char *)malloc(n);
        size_t i;
        unsigned char h[32];
        char got[65];
        if (!big) {
            printf("[FAIL] out of memory for 1MB test\n");
        } else {
            for (i = 0; i < n; i++) big[i] = 'a';
            si_sha256(big, n, h);
            hex(h, 32, got);
            const char *want1m =
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
            if (strcmp(got, want1m) == 0) {
                printf("[PASS] %-20s len=%-7zu %s\n", "NIST 1MB 'a'", n, got);
                passed++;
            } else {
                printf("[FAIL] %-20s len=%-7zu\n  want %s\n  got  %s\n",
                       "NIST 1MB 'a'", n, want1m, got);
            }
            total++;
            free(big);
        }
    }
    printf("\nResult: %d/%d passed\n", passed, total);
    return passed == total ? 0 : 1;
}
