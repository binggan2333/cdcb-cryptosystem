#ifndef __CDCB_K4M16_H
#define __CDCB_K4M16_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define CDCB_K4M16_KEY_LEN 32
#define CDCB_SAFE_KID_BITS 16

/**
 * @brief CDCB算法核心结构体（k=4组，m=16码字）
 */
typedef struct {
    uint8_t  cdcb_key[32];        // 32字节主密钥
    uint16_t key_total_len;        // 密钥长度固定32
    uint16_t base_codes[4];        // 4组基础基码
    uint8_t  k;                    // 分组数量 = 4
    uint8_t  m;                    // 单组码本长度 = 16
    uint8_t  bias[16][4];          // 16个符号的4组概率区间
    uint8_t  codebook[4][16];      // 正向码本 4×16
    uint8_t  codebook_inv[4][16];  // 反向码本（加速解密）
} cdcb_k4m16_t;

/**
 * @brief CDCB密钥/码本/偏置更新函数
 * @param key 结构体指针（不能为空）
 * @param cdcb_key 32字节密钥，为NULL则不更新
 * @param kid 4组基码，为NULL则不更新
 * @param knowledge 16个符号先验概率，为NULL则不使用
 * @param plaintext 明文数据，用于统计概率
 * @param plain_len 明文长度
 * @return 0=成功，1=失败
 */
uint8_t cdcb_key_k4m16_update(cdcb_k4m16_t *key,
                            const uint8_t cdcb_key[32],
                            const uint16_t kid[4],
                            const uint32_t knowledge[16],
                            const uint8_t *plaintext,
                            const uint32_t plain_len);

/**
 * @brief 半字节加密（4bit → 16bit密文）
 * @param plain_4bit 4位明文
 * @param k 密钥结构体
 * @return 16位密文，0xFFFF=失败
 */
uint16_t cdcb_encrypt_nibble(const uint8_t plain_4bit, void *k);

/**
 * @brief 半字节解密（16bit → 4bit明文）
 * @param cipher 16位密文
 * @param k 密钥结构体
 * @return 4位明文，0xFF=失败
 */
uint8_t cdcb_decrypt_nibble(const uint16_t cipher, void *k);

/**
 * @brief 整字节批量加密
 * @param plaintext 明文
 * @param plain_len 明文长度
 * @param ciphertext 输出密文
 * @param cipher_len 输出密文长度
 * @param key 结构体
 * @return 0=成功，1=失败
 */
uint8_t cdcb_encrypt(void *key, 
                    const uint8_t *plaintext,
                    const uint32_t plain_len,
                    uint8_t *ciphertext,
                    uint32_t *cipher_len);

/**
 * @brief 整字节批量解密
 * @param ciphertext 密文
 * @param cipher_len 密文长度
 * @param plaintext 输出明文
 * @param plain_len 输出明文长度
 * @param key 结构体
 * @return 0=成功，1=失败
 */
uint8_t cdcb_decrypt(void *key,
                    uint8_t *plaintext,
                    uint32_t *plain_len,
                    const uint8_t *ciphertext,
                    const uint32_t cipher_len);

// 外部依赖函数（需自行实现）
uint16_t CDCB_kid_rotate(uint16_t base, uint8_t offset);
uint16_t CDCB_kid_to_base(uint16_t cipher, uint8_t *offset);

#endif