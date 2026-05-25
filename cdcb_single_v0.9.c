#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define CDCB_SAFE_KID_BITS    16
#define CDCB_SAFE_POOL_SIZE   64
#define CDCB_SAFE_CODEBOOKS   4

// 为方便快速验证，仅使用单个c文件进行代码演示，实际使用中建议分离为头文件和源文件，并进行适当的模块化设计。
// For quick and easy verification, this demonstration uses a single C file only.
// In production use, it is recommended to separate into header files and source files,
// and implement proper modular design.


// =========================== SAFE通用标准声明模块 ===========================
// 基码：旋转不等价码在旋转周期内最小的那个值，用于作为本组旋转不等价码的标识和索引基准
// CDCB公用基码池
static const uint16_t KID_POOL_PUBLIC[8] = {0x0001,0x0003,0x0007,0x000F,0x001F,0x003F,0x007F,0x00FF};
// CDCB私有基码池，建议分散分布以增加安全性，且不与公用池重叠
static const uint16_t KID_POOL_BASE[CDCB_SAFE_POOL_SIZE] = {0x0217,0x04AD,0x04AF,0x04C5,0x13C9,0x13D7,0x13E3,0x1467,
                                                           0x168D,0x17A7,0x1949,0x1999,0x1A8F,0x1BF9,0x1CA9,0x1D7B,
                                                           0x24AF,0x24D5,0x25AF,0x25E7,0x26CB,0x2735,0x2795,0x29EF,
                                                           0x2A6F,0x2B4D,0x2CB7,0x2D97,0x2DEF,0x2E5D,0x2ECD,0x2FCD,
                                                           0x369F,0x37AB,0x39CF,0x39ED,0x3A9F,0x3AFD,0x3B4F,0x3BEF,
                                                           0x3CFB,0x3D5B,0x3DAF,0x3DF5,0x3EAF,0x3ED7,0x3F5B,0x3FB5,
                                                           0x56AF,0x56B7,0x56DB,0x56FB,0x576F,0x57EB,0x5AEF,0x5AFB,
                                                           0x5B7F,0x5BDF,0x5DAF,0x5DEF,0x5EBF,0x5EF7,0x5F7B,0x5FB7};

/************************** 安全警告 **************************
 * 本代码中的rand()和prng64_seed_fallback()仅用于演示目的！
 * 生产环境必须替换为以下安全随机数接口：
 * - Linux/macOS: getentropy()
 * - Windows: CryptGenRandom()
 * - ESP32: esp_random()
 * - STM32: HAL_RNG_GenerateRandomNumber()
 *************************************************************/

// 平台抽象：安全随机数生成器
#ifndef CDCB_SAFE_RANDOM
#define CDCB_SAFE_RANDOM() rand() // 跨平台演示用，生产环境必须替换
#endif

///******************** 核心全局变量 ********************/

// 主盐值（对称加密时码本生成的核心秘密）
// 基础版：暂时约定为xxxxx，保证对称加密的对称性。
// 工业版：可周期性更新以增强安全性。
// 作为单边通道标签时不使用本参数，作为双边加密协议时使用。
/* 4个独立盐值，分别对应4组码本（每组16个码字）。
 *
 * 设计意图：
 * - 4组码本独立洗牌，消除跨码本统计学关联。
 * - 4个salt相互独立，确保一组泄露不影响其他组安全。
 * - 每组salt可来源于不同的熵源或派生路径，增强深度防御。
 *
 * 唯一要求：对称加密双方必须保证4个salt完全一致。
 * 生成方式不限：预共享密钥、随机生成协商、基于公共事件派生等。
 */
static uint64_t cdcb_safe_salt[CDCB_SAFE_CODEBOOKS] = {0};
// 这里选择最简短明显的基码作为示例，16bit基码空间理论上有4079个满足旋转周期为16的基码，但实际使用中建议分散分布以增加安全性，且不与公用池重叠。
static uint16_t cdcb_safe_base[CDCB_SAFE_CODEBOOKS] = {0x0001,0x0003,0x0007,0x000F}; 
static uint8_t cdcb_safe_codebook[CDCB_SAFE_CODEBOOKS][16]={0};// 当前正向码本
static uint8_t cdcb_safe_codebook_inv[CDCB_SAFE_CODEBOOKS][16]={0};// 当前反向码本（优化解密）

// 固定偏置权重（富集系数/单边权重）：明文对码本的偏好程度
// 偏高频码本概率：(p-1)/p(a)；偏低频码本概率：1/p(a)
// 由盐值固定生成，对攻击者保密，无需解密方同步
static uint8_t cdcb_safe_bias[16][CDCB_SAFE_CODEBOOKS] = {0};


// 主项目摘出，部分无关声明
static uint8_t cdcb_safe_kid_ofs[CDCB_SAFE_POOL_SIZE] = {0};
static uint8_t cdcb_safe_ch_ofs[CDCB_SAFE_KID_BITS] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

// =========================== 辅助函数：旋转等价码生成与解析——码本折叠 ===========================

/**
 * @brief 16位二进制数左旋转n位
 * @param code 输入16位码
 * @param n 旋转位数(0-15)
 * @return 旋转后的16位码
 */
uint16_t CDCB_kid_rotate(uint16_t code, uint8_t n) {
    n &= 0x0F; // 确保n在0-15范围内
    return ((code << n) | (code >> (16 - n))) & 0xFFFF;
}

/**
 * @brief 从密文kid还原基码和相对偏移
 * @param kid 输入16位密文标记
 * @param offset 输出相对基码的偏移量(0-15)，可为NULL
 * @return 对应的基码值
 */
uint16_t CDCB_kid_to_base(uint16_t kid, uint8_t* offset) {
    uint16_t min_kid = kid;
    uint8_t base_offset = 0;
    
    for (uint8_t i = 1; i < CDCB_SAFE_KID_BITS; i++) {
        // 向右旋转1位，寻找最小值作为基码
        kid = (kid << 15) | (kid >> 1);
        if (kid < min_kid) {
            min_kid = kid;
            base_offset = i;
        }
    }
    
    if (offset) *offset = base_offset;
    return min_kid;
}

// 主项目摘出，部分无关声明
bool CDCB_safe_kid_init(){
    for (uint8_t i = 0; i < CDCB_SAFE_POOL_SIZE; i++)
    {
        cdcb_safe_kid_ofs[i] = (uint8_t)(CDCB_SAFE_RANDOM() & 0x0F); // 随机生成0-15的偏移
    }
    return true;
}

// =========================== 可控动态码本加密体系CDCB ===========================

// ===================== 64位随机数核心示例（纯标准C，无硬件依赖）=====================
// 初始化随机种子（自动获取系统熵，无需外部输入）
// 此处仅为演示，为了您能快速进行加密验证，或者在没有安全随机数生成器的环境中使用。
// 请自行替代为适合你平台的安全随机数生成方案。
#ifndef CDCB_SAFE_PRODUCTION

static uint64_t prng64_seed_fallback(void) {
    uint64_t seed = 0;

    /* 
     * 预留未初始化SRAM噪声区
     * 注意：此数组绝不初始化，以保留上电时的随机电荷残留。
     * 仅在冷启动时有效，热启动或运行期调用时熵极低。
     */
    volatile uint32_t sram_noise[16];
    for (int i = 0; i < 16; i++) {
        seed ^= (uint64_t)sram_noise[i] << ((i % 4) * 16);
    }

    /*
     * 栈地址混合（仅在有ASLR的系统上提供有限额外熵）
     * 这里取地址而非值，地址的随机性来自ASLR而非数组内容。
     */
    volatile uint8_t addr_probe;
    seed ^= (uint64_t)(uintptr_t)&addr_probe << 32;
    
    /* 用rand()引入微小时序抖动，增加扰动 */
    volatile int delay = rand() & 0x3F;
    while (delay > 0) { delay--; }

    /* 雪崩搅拌 */
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;

    return (seed == 0) ? 1 : seed;
}

#endif /* !CDCB_SAFE_PRODUCTION */

bool CDCB_salt_init(uint64_t *external_salts, int count){
    // 1. 设备唯一ID或这个您和对端约定的密码（确保对称加密双方一致）
    if(external_salts && count >= CDCB_SAFE_CODEBOOKS)
    {
        for (uint8_t i = 0; i < CDCB_SAFE_CODEBOOKS; i++)
        {
            cdcb_safe_salt[i] = external_salts[i];
        }
        return true;
    }
    const uint32_t DEVICE_UNIQUE_ID = 0x12345678; 
    for (uint8_t i = 0; i < CDCB_SAFE_CODEBOOKS; i++)
    {
        // 这里只是演示一种salt的生成方式，最终您只要生成对应位数的salt即可，不影响加密步骤。
        // 但是需要保证对称加密双方的salt生成方式和结果一致。
        uint64_t prng64_seed = prng64_seed_fallback();
        uint64_t x = prng64_seed;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        cdcb_safe_salt[i] = x ^ ((uint64_t)DEVICE_UNIQUE_ID << 32) ^ (x >> 16);
    }
    return true;
}

bool CDCB_codebook_init(){
    // 1.初始化码本，生成对称加密双方一致的动态码本。
    for (uint8_t i = 0; i < CDCB_SAFE_CODEBOOKS; i++)
    {
        for (uint8_t j = 0; j < 16; j++)
        {
            cdcb_safe_codebook[i][j] = j;
        }
    // 2.洗牌码本，增加安全性。这里使用Fisher-Yates洗牌算法，基于salt生成随机数。
        for (uint8_t j = 0; j < 16; j++)
        {
            // 基于salt和当前索引生成随机数，确保每次初始化结果不同，但对称双方一致。
            uint8_t raw = (uint8_t)((cdcb_safe_salt[i] >> ((15 - j) * 4)) & 0x0F);
            uint8_t k = raw % (j + 1);
            uint8_t temp = cdcb_safe_codebook[i][j];
            cdcb_safe_codebook[i][j] = cdcb_safe_codebook[i][k];
            cdcb_safe_codebook[i][k] = temp;
        }
        // 3.生成反向码本，优化解密性能
        for (uint8_t j = 0; j < 16; j++)
        {
            cdcb_safe_codebook_inv[i][cdcb_safe_codebook[i][j]] = j;
        }
    }
    return true;
}

/**
 * @brief 根据偏置权重表选择码本
 * @param symbol 4位明文符号(0-15)
 * @return 选中的码本索引(0-3)
 */
static uint8_t CDCB_select_codebook(uint8_t symbol) {
    uint8_t r = (uint8_t)(CDCB_SAFE_RANDOM() % 256);
    symbol &= 0x0F;
    
    if (r < cdcb_safe_bias[symbol][1]) return 0;
    if (r < cdcb_safe_bias[symbol][2]) return 1;
    if (r < cdcb_safe_bias[symbol][3]) return 2;
    return 3;
}

// =========================== CDCB 加密/解密 ===========================

bool CDCB_bias_init(const uint8_t *buf, int len){
    if(len == 0 )
    {//随机偏置权重
        for(uint8_t k=0;k<16;k++)
        {
            const uint8_t min_len=10;
            uint8_t splits[3];
            for (uint8_t i = 0; i < 3; i++)
            {
                splits[i] = (uint8_t)(CDCB_SAFE_RANDOM() % (256 - min_len*4)) ;
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
            cdcb_safe_bias[k][0] = 0;//每段的下界
            cdcb_safe_bias[k][1] = splits[0] + min_len;
            cdcb_safe_bias[k][2] = splits[1] + 2 * min_len;
            cdcb_safe_bias[k][3] = splits[2] + 3 * min_len;
        }
    }
    else
    {//双峰极化权重
        int count[16] = {0},max_count=0,p=0;
        for(int i=0;i<len;i++)
        {
            uint8_t high = (buf[i] >> 4) & 0x0F;
            uint8_t low  = buf[i] & 0x0F;
            count[high]++;
            count[low]++;
        }
        for (uint8_t i = 0; i < 16; i++)
        {
            if(count[i]>max_count) max_count = count[i];
        }
        p = (max_count + 3) / 4; // 向上取整避免p=0
        
        for(uint8_t k=0;k<16;k++)
        {
            int total = count[k];
            if (total == 0) total = 1; // 防止除零错误
            
            int remaining = total;
            uint8_t seg_len[4];
            
            // 分配各段长度
            for (uint8_t i = 0; i < 4; i++) {
                if (remaining >= p) {
                    seg_len[i] = (uint8_t)((p * 256 + total / 2) / total); // 四舍五入
                    remaining -= p;
                } else if (remaining > 0) {
                    seg_len[i] = (uint8_t)((remaining * 256 + total / 2) / total);
                    remaining = 0;
                } else {
                    seg_len[i] = 1; // 保证每段至少1字节
                }
            }
            
            // 修正总长度为精确256
            int sum = seg_len[0] + seg_len[1] + seg_len[2] + seg_len[3];
            int diff = 256 - sum;
            if (diff > 0) {
                seg_len[3] += (uint8_t)diff;
            } else if (diff < 0) {
                seg_len[3] -= (uint8_t)(-diff);
            }
            
            // Fisher-Yates洗牌：随机打乱分段顺序
            for (uint8_t i = 3; i > 0; i--) {
                uint8_t idx = (uint8_t)(CDCB_SAFE_RANDOM() % (i + 1));
                uint8_t temp = seg_len[i];
                seg_len[i] = seg_len[idx];
                seg_len[idx] = temp;
            }
            
            // 计算最终分段下界
            cdcb_safe_bias[k][0] = 0;
            cdcb_safe_bias[k][1] = seg_len[0];
            cdcb_safe_bias[k][2] = seg_len[0] + seg_len[1];
            cdcb_safe_bias[k][3] = seg_len[0] + seg_len[1] + seg_len[2];
        }
    }
    return true;
}

/**
 * 加密半个字节（4-bit明文）
 * @param plain_4bit 明文（低4位有效，0-15）
 * @return 16位密文标记
 */
uint16_t CDCB_encrypt_nibble(uint8_t plain_4bit) {
    // 参数检查
    if (plain_4bit >= 16) {
        return 0xFFFF; // 返回无效标记
    }
    
    // 根据偏置权重自动选择码本组
    uint8_t group = CDCB_select_codebook(plain_4bit);
    uint8_t offset = cdcb_safe_codebook[group][plain_4bit];
    return CDCB_kid_rotate(cdcb_safe_base[group], offset);
}

/**
 * 解密半个字节（4-bit明文）
 * @param cipher   16位密文标记
 * @param plain_4bit 输出明文（低4位）
 * @param group    输出基码组索引（可为NULL）
 * @return true成功, false失败（标记不属于任何基码）
 */
bool CDCB_decrypt_nibble(uint16_t cipher, uint8_t *plain_4bit, uint8_t *group) {
    // 1. 找到密文对应的基码
    uint8_t offset;
    uint16_t base = CDCB_kid_to_base(cipher, &offset);
    
    // 2. 确定基码组索引
    int8_t idx = -1;
    for (uint8_t i = 0; i < CDCB_SAFE_CODEBOOKS; i++) {
        if (cdcb_safe_base[i] == base) {
            idx = i;
            break;
        }
    }
    if (idx < 0) return false;
    
    // 3. 反向码本O(1)查找明文
    *plain_4bit = cdcb_safe_codebook_inv[idx][offset];
    if (group) *group = idx;
    return true;
}

/**
 * 加密一个字节（8-bit），返回两个16位密文
 * 高4位和低4位分别独立加密
 */
void CDCB_encrypt_byte(uint8_t plain_byte, uint16_t cipher[2]) {
    uint8_t high = (plain_byte >> 4) & 0x0F;
    uint8_t low  = plain_byte & 0x0F;
    
    // 使用偏置权重选择码本组
    cipher[0] = CDCB_encrypt_nibble(high);
    cipher[1] = CDCB_encrypt_nibble(low);
}

/**
 * 解密一个字节，输入两个16位密文，输出明文
 * @return true成功
 */
bool CDCB_decrypt_byte(const uint16_t cipher[2], uint8_t *plain_byte) {
    uint8_t high, low;
    if (!CDCB_decrypt_nibble(cipher[0], &high, NULL)) return false;
    if (!CDCB_decrypt_nibble(cipher[1], &low, NULL))  return false;
    *plain_byte = (high << 4) | low;
    return true;
}

/**
 * 更新4个盐值并立即重建码本
 * @param new_salts  新的4个uint64_t盐值数组
 * @return true成功
 */
bool CDCB_update_salts(const uint64_t new_salts[4]) {
    if (!new_salts) return false;
    for (uint8_t i = 0; i < CDCB_SAFE_CODEBOOKS; i++) {
        cdcb_safe_salt[i] = new_salts[i];
    }
    return CDCB_codebook_init();
}

/**
 * 基于外部协商的种子更新盐值（双方相同）
 * 例如利用通信双方都能观测到的公共事件（如最近一段密文的总数量、当前时间戳等）
 */
bool CDCB_update_salts_from_seed(uint64_t seed) {
    uint64_t new_salts[CDCB_SAFE_CODEBOOKS];
    for (uint8_t i = 0; i < CDCB_SAFE_CODEBOOKS; i++) {
        // 简单派生：seed XOR (index * magic) 并雪崩搅拌
        uint64_t x = seed ^ ((uint64_t)i * 0x9E3779B97F4A7C15ULL);
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        new_salts[i] = x;
    }
    return CDCB_update_salts(new_salts);
}

int main()
{
    //自动初始化，验证用
    CDCB_salt_init(NULL, 0);
    CDCB_codebook_init();
    CDCB_bias_init(NULL, 0);
    
    // 加密字节流
    uint8_t msg[] = {0xAB, 0xCD, 0x12, 0x34};
    uint16_t enc[8];
    for (int i = 0; i < 4; i++) {
        CDCB_encrypt_byte(msg[i], &enc[i*2]);
    }

    // 解密字节流
    uint8_t dec[4];
    bool success = true;
    for (int i = 0; i < 4; i++) {
        if (!CDCB_decrypt_byte(&enc[i*2], &dec[i])) {
            success = false;
            break;
        }
    }

    // 验证结果
    if (success && memcmp(msg, dec, 4) == 0) {
        printf("加密解密成功！\n");
    } else {
        printf("加密解密失败！\n");
    }

    return 0;
}
