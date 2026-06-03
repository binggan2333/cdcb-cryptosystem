#include "cdcb_k4m16.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

/**
 * @brief 根据先验概率计算Bias区间
 */
static bool cdcb_do_bias(cdcb_k4m16_t *key, const uint32_t knowledge[16])
{
    uint32_t p=0;
    for(uint8_t i=0;i<16;i++) if(knowledge[i]>p) p=knowledge[i];
    p = p/4;
    for(uint8_t k=0;k<16;k++)
    {
        if (knowledge[k] < 4)
        {
            for (uint8_t i = 0; i < 4; i++) key->bias[k][i] = i*64;
            continue;
        }
        int c_tmp=knowledge[k]-4,p_tmp=p-1,splits[4]= {0};
        for(uint8_t i=0;i<4;i++)
        {
            if(c_tmp>p_tmp)
            {
                splits[i] = (uint8_t)((p_tmp+1)*256/knowledge[k]); // 计算分割点长度
                c_tmp-=p;
            } 
            else if(c_tmp>0)
            {
                splits[i] = (uint8_t)((c_tmp)*256/knowledge[k]); // 计算分割点长度
                c_tmp=0;
            }
            else splits[i] = 1;
        }
        if(c_tmp>0) splits[3] +=c_tmp;
        // 洗牌分割点，增加安全性。这里使用Fisher-Yates洗牌算法，基于salt生成随机数。
        for (uint8_t i = 0; i < 4; i++)
        {
            uint8_t idx = rand() % (i + 1);
            uint8_t temp = splits[i];
            splits[i] = splits[idx];
            splits[idx] = temp;
        }
        key->bias[k][0]=0;
        for (uint8_t i = 1; i < 4; i++) key->bias[k][i] = key->bias[k][i-1]+splits[i-1];
    }
    return true;
}

// ==============================
// 密钥 & 码本 & 偏置 更新
// ==============================
uint8_t cdcb_key_k4m16_update(cdcb_k4m16_t *key,
                            const uint8_t cdcb_key[32],
                            const uint16_t kid[4],
                            const uint32_t knowledge[16],
                            const uint8_t *plaintext,
                            const uint32_t plain_len)
{
    if (!key ) return 0x01;
    key->k = 4;
    key->m = 16;
    key->key_total_len = 32;

    // 1. 更新密钥（如果提供）
    if(cdcb_key)
    {
        memcpy(key->cdcb_key, cdcb_key, 32);
        for(uint8_t i=0;i<4;i++)
        {
            for(uint8_t j=0;j<16;j++)
            {
                key->codebook[i][j] = j;
            }
            // 洗牌码本，增加安全性。这里使用Fisher-Yates洗牌算法，基于salt生成随机数。
            for (uint8_t j = 0; j < 16; j++)
            {
                // 基于cdcb_key和当前索引生成随机数，确保每次更新结果不同，但对称双方一致。
                uint8_t raw = (uint8_t)((cdcb_key[(i*16 + j)/2] >> ((j%2)*4)) & 0x0F);
                uint8_t k_idx = raw % (j + 1);
                
                uint8_t temp = key->codebook[i][j];
                key->codebook[i][j] = key->codebook[i][k_idx];
                key->codebook[i][k_idx] = temp;
            }
            // 更新反向码本，优化解密性能
            for (uint8_t j = 0; j < 16; j++)
                key->codebook_inv[i][key->codebook[i][j]] = j;
        }
    }
    // 2. 更新基码（如果提供）
    if(kid)memcpy(key->base_codes, kid, 4 * sizeof(uint16_t));
    
    // 3. 更新偏置 bias
    //    优先级：knowledge > 明文统计 > 随机更新
    uint32_t klg[16]= {0};
    if(knowledge) {
        // 使用先验知识更新偏置
        memcpy(klg, knowledge, 16 * sizeof(uint32_t));
        cdcb_do_bias(key, klg);
        return 0x00;
    } else if(plaintext && plain_len > 0) {
        // 使用明文统计更新偏置
        for(uint32_t i=0;i<plain_len;i++)
        {
            klg[(plaintext[i]&0x0F)]++;
            klg[((plaintext[i]>>4)&0x0F)]++;
        }
        cdcb_do_bias(key, klg);
        return 0x00;
    } else {
        // 随机更新偏置
        for(uint8_t k=0;k<16;k++)
        {
            uint8_t min_len=10,splits[3];
            for (uint8_t i = 0; i < 3; i++)
            {
                splits[i] = (rand() % (256 - min_len*4)) ;
            }
            // 对splits进行排序，确保分割点递增
            for (uint8_t i = 0; i < 2; i++) {
                for (uint8_t j = 0; j < 2 - i; j++) {
                    if (splits[j] > splits[j + 1]) {
                        uint8_t temp = splits[j];
                        splits[j] = splits[j + 1];
                        splits[j + 1] = temp;
                    }
                }
            }
            key->bias[k][0] = 0;//每段的下届
            for (uint8_t i = 1; i < 4; i++) key->bias[k][i] = splits[i-1]+min_len*i;
        }
        return 0x00;
    }
}

// ==============================
// 半字节加密
// ==============================
uint16_t cdcb_encrypt_nibble(const uint8_t plain_4bit, void *k) {
    cdcb_k4m16_t *key = (cdcb_k4m16_t *)k;
    if (!key || plain_4bit >= 16) return 0xFFFF; // 参数检查
    uint8_t group = 0,raw = rand() % 256;
    while (group < 3 && raw >= key->bias[plain_4bit][group + 1]) {
        group++;
    }
    uint8_t offset = key->codebook[group][plain_4bit];
    return CDCB_kid_rotate(key->base_codes[group], offset);
}

// ==============================
// 半字节解密
// ==============================
uint8_t cdcb_decrypt_nibble(const uint16_t cipher,void *k)
{
    cdcb_k4m16_t *key = (cdcb_k4m16_t *)k;
    if (!key) return 0xFF; // 参数检查
    uint8_t offset;
    uint16_t base = CDCB_kid_to_base(cipher, &offset);
    int8_t idx = -1;
    for (uint8_t i = 0; i < 4; i++) {
        if (key->base_codes[i] == base) {
            idx = i;
            break;
        }
    }
    if (idx < 0) return 0xFF; // 未找到对应基码
    return key->codebook_inv[idx][offset]; // 使用反向码本解密
}

// ==============================
// 整字节加密
// ==============================
uint8_t cdcb_encrypt(void *key, 
                    const uint8_t *plaintext,
                    const uint32_t plain_len,
                    uint8_t *ciphertext,
                    uint32_t *cipher_len)
{
    if (!plaintext || !ciphertext || !cipher_len || !key) return 0x01;
    for(uint32_t i=0;i<plain_len;i++)
    {
        uint16_t cipher[2];
        uint8_t high = (plaintext[i] >> 4) & 0x0F;
        uint8_t low  = plaintext[i] & 0x0F;
        cipher[0] = cdcb_encrypt_nibble(high, key);
        cipher[1] = cdcb_encrypt_nibble(low, key);
        if(cipher[0] == 0xFFFF || cipher[1] == 0xFFFF) return 0x01; // 加密失败
        memcpy(ciphertext + i*4, cipher, 4); // 每个半字节对应2字节密文
    }
    *cipher_len = plain_len * 4;
    return 0x00; // 成功加密
}

// ==============================
// 整字节解密
// ==============================
uint8_t cdcb_decrypt(void *key,
                    uint8_t *plaintext,
                    uint32_t *plain_len,
                    const uint8_t *ciphertext,
                    const uint32_t cipher_len)
{
    if (!ciphertext || !plaintext || !plain_len || !key || cipher_len % 4 != 0) return 0x01;
    for(uint32_t i=0;i<cipher_len/4;i++)
    {
        uint16_t cipher[2];
        memcpy(cipher, ciphertext + i*4, 4);
        uint8_t high = cdcb_decrypt_nibble(cipher[0], key);
        uint8_t low  = cdcb_decrypt_nibble(cipher[1], key);
        if (high == 0xFF || low == 0xFF) return 0x01; // 解密失败
        plaintext[i] = (high << 4) | low;
    }
    *plain_len = cipher_len / 4;
    return 0x00; // 成功解密
}

// ==============================
// 外部依赖函数示例（可自行实现）
// ==============================
//n位左旋转函数，用于生成KID
uint16_t CDCB_kid_rotate(uint16_t code, uint8_t n) {
    n = n % CDCB_SAFE_KID_BITS; // 确保n在0-15范围内
    uint16_t new_code = ((code << n) | (code >> (CDCB_SAFE_KID_BITS - n))) & 0xFFFF; // 左旋n位
    return new_code;
}
//复原返回基码值和相对基码的偏移
uint16_t CDCB_kid_to_base(uint16_t kid, uint8_t* offset) {
    // 循环旋转kid找到最小值，并记录旋转次数作为kid_offset
    uint16_t min_kid = kid;
    uint8_t base_offset = 0;
    for (uint8_t i = 1; i < CDCB_SAFE_KID_BITS; i++) {
        //每次向右旋转1位，寻找其相对于KID_POOL_BASE的偏移，找到最小值对应的偏移即为kid_offset
        kid = (kid << (CDCB_SAFE_KID_BITS - 1)) | (kid >> 1); 
        if (kid < min_kid) {
            min_kid = kid;
            base_offset = i;
        }
    }
    if (offset) *offset = base_offset;
    return min_kid;
}