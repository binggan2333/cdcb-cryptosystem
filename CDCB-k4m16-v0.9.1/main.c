#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "cdcb_k4m16.h"

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

int main()
{
    // 初始化随机数种子（全程序只一次）
    srand((unsigned int)time(NULL));

    // 1. 定义密钥、基码、测试明文
    uint8_t test_key[32] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                            0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
                            0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
                            0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0};

    uint16_t test_kid[4] = {0x168D, 0x5BDF, 0x17A7, 0x1949}; // 从私有基码池中选择4个基码
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
