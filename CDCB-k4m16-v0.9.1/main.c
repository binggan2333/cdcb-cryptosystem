#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "cdcb_k4m16.h"

int main()
{
    // 初始化随机数种子（全程序只一次）
    srand((unsigned int)time(NULL));

    // 1. 定义密钥、基码、测试明文
    uint8_t test_key[32] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                            0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
                            0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
                            0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0};

    uint16_t test_kid[4] = {0x1234, 0x5678, 0x9ABC, 0xDEF0};
    uint8_t  plain_buf[16] = "Hello CDCB Test!";
    uint8_t  cipher_buf[64] = {0};
    uint8_t  dec_buf[16] = {0};
    uint32_t cipher_len = 0;
    uint32_t dec_len = 0;

    // 2. 初始化结构体
    cdcb_k4m16_t key_ctx;
    cdcb_key_k4m16_update(&key_ctx, test_key, test_kid, NULL, NULL, 0);

    // 3. 加密
    printf("原始明文: %s\n", plain_buf);
    uint8_t enc_ret = cdcb_encrypt(plain_buf, 16, cipher_buf, &cipher_len, &key_ctx);
    if(enc_ret != 0) {
        printf("加密失败\n");
        return -1;
    }
    printf("加密成功，密文长度: %d\n", cipher_len);

    // 4. 解密
    uint8_t dec_ret = cdcb_decrypt(cipher_buf, cipher_len, dec_buf, &dec_len, &key_ctx);
    if(dec_ret != 0) {
        printf("解密失败\n");
        return -1;
    }
    printf("解密成功，明文长度: %d\n", dec_len);
    printf("解密结果: %s\n", dec_buf);

    return 0;
}