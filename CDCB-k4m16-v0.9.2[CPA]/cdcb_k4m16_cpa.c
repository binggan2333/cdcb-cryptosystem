#include "cdcb_k4m16_cpa.h"
#include "cdcb_k4m16.h"      // 复用原先的 cdcb_encrypt / cdcb_decrypt 等基础函数
#include <string.h>

/* ==================================================================
 * 内置软件 SHA-256 (命名: cdcb_sha256)
 * 完全独立实现，无任何平台依赖
 * ================================================================== */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)     (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x)     (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x)    (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x)    (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void cdcb_sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a,b,c,d,e,f,g,h,t1,t2,m[64];
    int i;
    for (i=0; i<16; i++)
        m[i] = ((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)|
               ((uint32_t)data[i*4+2]<<8)|((uint32_t)data[i*4+3]);
    for (; i<64; i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];
    for (i=0; i<64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + sha256_k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

void cdcb_sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    uint32_t state[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint8_t block[64];
    size_t i;

    for (i=0; i+64 <= len; i+=64)
        cdcb_sha256_transform(state, data+i);

    size_t rem = len - i;
    memcpy(block, data+i, rem);
    block[rem] = 0x80;
    rem++;
    if (rem <= 56) {
        memset(block+rem, 0, 56-rem);
    } else {
        memset(block+rem, 0, 64-rem);
        cdcb_sha256_transform(state, block);
        memset(block, 0, 56);
    }

    uint64_t bits = (uint64_t)len * 8;
    for (i=0; i<8; i++)
        block[56+i] = (bits >> (56 - i*8)) & 0xFF;
    cdcb_sha256_transform(state, block);

    for (i=0; i<8; i++) {
        hash[i*4]   = (state[i]>>24) & 0xFF;
        hash[i*4+1] = (state[i]>>16) & 0xFF;
        hash[i*4+2] = (state[i]>>8)  & 0xFF;
        hash[i*4+3] = state[i] & 0xFF;
    }
}

/* ==================================================================
 * 内部辅助：用 master_key 和 nonce 派生临时码本
 * ================================================================== */
static void derive_temp_codebook(cdcb_k4m16_t *tmp_cb,
                                 const uint8_t master_key[32],
                                 const uint16_t base_codes[4],
                                 uint64_t nonce,
                                 const uint32_t knowledge[16],
                                 const uint8_t *plaintext,
                                 const uint32_t plain_len) {
    // 1. 用 SHA-256 计数器模式派生 32 字节临时密钥 material
    //    输入：master_key || nonce (8字节大端) || 0x00 (作为计数器)
    uint8_t keymat[32];
    uint8_t buf[32+8+1];  // master_key + nonce + counter (这里 counter 只用 0，因为只生成一组)
    memcpy(buf, master_key, 32);
    for (int i=0; i<8; i++) buf[32+i] = (nonce >> (56 - i*8)) & 0xFF;
    buf[40] = 0x00; // 计数器0
    cdcb_sha256(buf, sizeof(buf), keymat);

    // 2. 用 keymat 和基码调用原 cdcb 更新函数，生成临时码本
    cdcb_key_k4m16_update(tmp_cb, keymat, base_codes, knowledge, plaintext, plain_len);
}

/* ==================================================================
 * 公开接口实现
 * ================================================================== */
void cdcb_msg_init(cdcb_msg_ctx_t *ctx,
                   const uint8_t master_key[32],
                   const uint16_t base_codes[4],
                   uint64_t init_nonce) {
    memcpy(ctx->master_key, master_key, 32);
    memcpy(ctx->base_codes, base_codes, 4*sizeof(uint16_t));
    ctx->nonce = init_nonce;
}

int cdcb_msg_encrypt(cdcb_msg_ctx_t *ctx,
                     const uint8_t *plain, size_t plain_len,
                     uint8_t *cipher, size_t *cipher_len) {
    if (!ctx || !plain || !cipher || !cipher_len) return -1;

    // 生成临时码本
    cdcb_k4m16_t tmp_cb;
    derive_temp_codebook(&tmp_cb, ctx->master_key, ctx->base_codes, ctx->nonce,NULL,NULL,0);

    // 加密明文（原 cdcb_encrypt 输出长度 = 4 * plain_len）
    uint32_t ct_len = 0;
    uint8_t *ct_buf = cipher + 8;   // 前面 8 字节留给 nonce
    int ret = cdcb_encrypt(plain, (uint32_t)plain_len, ct_buf, &ct_len, &tmp_cb);
    if (ret != 0) return ret;

    // 前置 nonce
    for (int i=0; i<8; i++)
        cipher[i] = (ctx->nonce >> (56 - i*8)) & 0xFF;

    *cipher_len = 8 + ct_len;
    ctx->nonce++;   // 递增 nonce，准备下一条消息
    return 0;
}

int cdcb_msg_decrypt(cdcb_msg_ctx_t *ctx,
                     const uint8_t *cipher, size_t cipher_len,
                     uint8_t *plain, size_t *plain_len) {
    if (!ctx || !cipher || !plain || !plain_len || cipher_len < 8) return -1;

    // 提取 nonce
    uint64_t nonce = 0;
    for (int i=0; i<8; i++)
        nonce = (nonce << 8) | cipher[i];

    // 重建临时码本（与加密端相同）
    cdcb_k4m16_t tmp_cb;
    derive_temp_codebook(&tmp_cb, ctx->master_key, ctx->base_codes, nonce,NULL,NULL,0);

    // 解密（密文体在 cipher+8）
    const uint8_t *ct = cipher + 8;
    size_t ct_len = cipher_len - 8;
    uint32_t pt_len = 0;
    int ret = cdcb_decrypt(ct, (uint32_t)ct_len, plain, &pt_len, &tmp_cb);
    if (ret != 0) return ret;

    *plain_len = pt_len;
    return 0;
}