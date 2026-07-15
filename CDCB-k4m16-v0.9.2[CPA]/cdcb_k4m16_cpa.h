#ifndef CDCB_K4M16_CPA_H
#define CDCB_K4M16_CPA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 消息加密上下文
typedef struct {
    uint8_t  master_key[32];          // 主密钥 (256位)
    uint16_t base_codes[4];           // 4组基码 (需与解密端一致)
    uint64_t nonce;                   // 消息序号，自动递增，也可由外部设置
} cdcb_msg_ctx_t;

/**
 * @brief 初始化消息加密上下文
 * @param ctx        上下文指针
 * @param master_key 32字节主密钥
 * @param base_codes 4个16位基码（例如 {0x0001, 0x0003, 0x0007, 0x000F}）
 * @param init_nonce 初始 nonce (通常为 0)
 */
void cdcb_msg_init(cdcb_msg_ctx_t *ctx,
                   const uint8_t master_key[32],
                   const uint16_t base_codes[4],
                   uint64_t init_nonce);

/**
 * @brief 加密一条消息 (抗 CPA)
 * @param ctx       加密上下文
 * @param plain     明文
 * @param plain_len 明文长度 (字节)
 * @param cipher    输出密文缓冲区 (由调用者分配，至少 plain_len*4 + 8 字节)
 * @param cipher_len 输出密文实际长度
 * @return 0 成功，非0 失败
 */
int cdcb_msg_encrypt(cdcb_msg_ctx_t *ctx,
                     const uint8_t *plain, size_t plain_len,
                     uint8_t *cipher, size_t *cipher_len);

/**
 * @brief 解密一条消息
 * @param ctx        解密上下文 (与加密端共享 master_key 和 base_codes)
 * @param cipher     密文
 * @param cipher_len 密文长度
 * @param plain      输出明文缓冲区 (由调用者分配，至少 cipher_len/4 字节)
 * @param plain_len  输出明文实际长度
 * @return 0 成功，非0 失败
 */
int cdcb_msg_decrypt(cdcb_msg_ctx_t *ctx,
                     const uint8_t *cipher, size_t cipher_len,
                     uint8_t *plain, size_t *plain_len);

#ifdef __cplusplus
}
#endif

#endif // CDCB_K4M16_CPA_H