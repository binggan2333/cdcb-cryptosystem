/**
 * CDCB-CPA 消息加密演示程序
 * 
 * 依赖: cdcb_k4m16_cpa.h / cdcb_k4m16_cpa.c (含内置 SHA-256)
 *       cdcb_k4m16.h / cdcb_k4m16.c         (基础码本与旋转)
 * 
 * 编译示例 (gcc): 
 *   gcc -o demo demo.c cdcb_k4m16.c cdcb_k4m16_cpa.c -I.
 */

/*
static const uint16_t KID_POOL_PUBLIC[8] = {0x0001,0x0003,0x0007,0x000F,0x001F,0x003F,0x007F,0x00FF};
static const uint16_t KID_POOL_BASE[64] = {0x0217,0x04AD,0x04AF,0x04C5,0x13C9,0x13D7,0x13E3,0x1467,
                                           0x168D,0x17A7,0x1949,0x1999,0x1A8F,0x1BF9,0x1CA9,0x1D7B,
                                           0x24AF,0x24D5,0x25AF,0x25E7,0x26CB,0x2735,0x2795,0x29EF,
                                           0x2A6F,0x2B4D,0x2CB7,0x2D97,0x2DEF,0x2E5D,0x2ECD,0x2FCD,
                                           0x369F,0x37AB,0x39CF,0x39ED,0x3A9F,0x3AFD,0x3B4F,0x3BEF,
                                           0x3CFB,0x3D5B,0x3DAF,0x3DF5,0x3EAF,0x3ED7,0x3F5B,0x3FB5,
                                           0x56AF,0x56B7,0x56DB,0x56FB,0x576F,0x57EB,0x5AEF,0x5AFB,
                                           0x5B7F,0x5BDF,0x5DAF,0x5DEF,0x5EBF,0x5EF7,0x5F7B,0x5FB7};

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cdcb_k4m16_cpa.h"

int main() {
    /* ---------- 1. 预共享密钥与基码 (双方约定) ---------- */
    uint8_t  master_key[32] = {
        0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF,
        0x01,0x23,0x45,0x67, 0x89,0xAB,0xCD,0xEF,
        0x12,0x34,0x56,0x78, 0x9A,0xBC,0xDE,0xF0
    };
    uint16_t base_codes[4] = {0x168D, 0x5BDF, 0x17A7, 0x1949};   /* 可从私有池挑选 */

    /* ---------- 2. 初始化加密/解密上下文 ---------- */
    cdcb_msg_ctx_t enc_ctx, dec_ctx;
    cdcb_msg_init(&enc_ctx, master_key, base_codes, 0);  // 发送方 nonce 从 0 开始
    cdcb_msg_init(&dec_ctx, master_key, base_codes, 0);  // 接收方初始 nonce 同步

    /* ---------- 3. 准备明文 ---------- */
    const char *plain_text = "Hello CDCB-CPA! This message is encrypted with dynamic codebooks.";
    uint8_t plain_buf[256];
    size_t plain_len = strlen(plain_text);
    memcpy(plain_buf, plain_text, plain_len);

    printf("========== CDCB-CPA 消息加密演示 ==========\n");
    printf("明文 (%zu 字节): %s\n", plain_len, plain_buf);

    /* ---------- 4. 加密 ---------- */
    uint8_t cipher_buf[512] = {0};
    size_t cipher_len = 0;
    int ret = cdcb_msg_encrypt(&enc_ctx, plain_buf, plain_len, cipher_buf, &cipher_len);
    if (ret != 0) {
        printf("加密失败！\n");
        return -1;
    }
    printf("\n加密成功，密文长度: %zu 字节\n", cipher_len);
    printf("Nonce (十六进制): ");
    for (int i = 0; i < 8; i++) printf("%02X ", cipher_buf[i]);
    printf("\n密文 (前16字节): ");
    for (int i = 8; i < 24 && i < cipher_len; i++) printf("%02X ", cipher_buf[i]);
    printf("...\n");

    /* ---------- 5. 模拟传输后，接收方解密 ---------- */
    uint8_t dec_buf[256] = {0};
    size_t dec_len = 0;
    ret = cdcb_msg_decrypt(&dec_ctx, cipher_buf, cipher_len, dec_buf, &dec_len);
    if (ret != 0) {
        printf("\n解密失败！\n");
        return -1;
    }

    printf("\n解密成功，明文长度: %zu 字节\n", dec_len);
    dec_buf[dec_len] = '\0';   // 便于打印
    printf("解密后的明文: %s\n", dec_buf);

    /* ---------- 6. 验证一致性 ---------- */
    if (dec_len == plain_len && memcmp(plain_buf, dec_buf, plain_len) == 0) {
        printf("\n✅ 验证通过: 解密结果与原始明文一致！\n");
    } else {
        printf("\n❌ 验证失败: 解密结果与原始明文不一致！\n");
    }

    /* ---------- 7. 再加密一条消息，展示 Nonce 递增 ---------- */
    const char *second_msg = "Second message, nonce auto-increment.";
    plain_len = strlen(second_msg);
    memcpy(plain_buf, second_msg, plain_len);

    ret = cdcb_msg_encrypt(&enc_ctx, plain_buf, plain_len, cipher_buf, &cipher_len);
    if (ret == 0) {
        printf("\n--- 第二条消息加密成功，Nonce: ");
        for (int i = 0; i < 8; i++) printf("%02X ", cipher_buf[i]);
        printf(" ---\n");
    }

    return 0;
}