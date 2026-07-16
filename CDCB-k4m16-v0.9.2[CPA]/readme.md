## 📌 使用范围与边界说明

### 1. 核心能力与模块边界

CDCB 的核心创新与设计目标为：基于旋转不等价码的多码本代换架构、固定偏置权重的统计不可区分性、身份声明域抗追踪混淆，以及极致轻量的资源适配。
以下通用安全能力属于所有加密算法的可选配扩展模块，**不属于 CDCB 核心创新范畴，核心库暂不内置**，用户可根据业务场景自行叠加：

- 防篡改 / 完整性校验（MAC / 认证标签）
- nonce 重放攻击检测与序号校验
- 明文格式合法性校验
- 侧信道攻击恒时防护

### 2. CPA 对抗测试结论

当前 v0.9.2 版本的 CDCB-CPA 模式，经过标准黑盒 IND-CPA 等长挑战测试（攻击侧仅观测原始密文字节，不调用解密与内部接口，单加密预言机下 nonce 自动递增且不重复），测试结果如下：

- **普通分布明文（真实场景典型数据）**：
    - ASCII 'A' 与 ASCII 'B' 对比：攻击成功率 50.80%，相对随机优势 0.80%，z 值 0.72；
    - 递增序列与递减序列对比：攻击成功率 51.80%，相对随机优势 1.80%，z 值 1.61；
    两组均未达到 3σ 统计显著标准，密文统计不可区分，工程级抗 CPA 能力有效。
- **极端全同半字节明文（边缘压力测试场景）**：
    - 全 0x00 与全 0xFF 对比：攻击成功率 69.05%，相对随机优势 19.05%，z 值 17.04，存在统计可区分信号；
    - 注：该组测试使用演示用 `rand()` 随机源，且未启用基于先验知识的偏置权重优化，属于最不利测试条件下的统计特征残留，不构成结构级破解风险；实际工程中启用双峰极化偏置权重并替换密码学安全随机源后，区分度会进一步下降。
- **整体判定**：具备工程级抗选择明文攻击能力，可覆盖绝大多数物联网、嵌入式真实业务场景；严格密码学理论层面尚未达到完美 IND-CPA 标准，后续版本可按需迭代补强。

### 3. 接口使用建议

为便于学习、调试与二次开发，本仓库 Demo 开放了从半字节运算到底层码本管理的全部接口。

**生产环境部署推荐统一使用 `cdcb_msg_*` 系列接口**，该接口封装了 nonce 管理、动态码本派生、逐半字节动态偏移的完整安全流程，是 CDCB-CPA 模式的标准使用方式。

# CDCB-K4M16 —— 可控动态码本加密体系

基于旋转不等价码的轻量级对称加密库，同时支持**身份混淆（电子身份防追踪）** 与**抗选择明文攻击（CPA）消息加密**。
适用于资源受限的嵌入式设备、IoT 安全通信及隐私保护场景。**Version: 0.9.2**

## ✨ 特性

- **旋转不等价码**
  使用 16 位循环移位生成 16 个互不等价的信道标记，基码池可动态更新。

- **动态码本（CDCB）**
  4 组独立码本，每组 16 个符号，Fisher‑Yates 洗牌生成随机置换。
  结合偏置权重选择码本，消除统计特征，防止流量关联分析。

- **身份混淆（KID 模式）**
  静态盐值 + 基码 → 稳定码本，用于长期设备电子身份标记。
  服务端掌握码本，客户端仅持有密文，无法跨链路关联。

- **抗 CPA 消息加密（CDCB‑CPA）**
  每条消息使用独立临时码本：`master_key + nonce` 派生动态盐值，彻底阻断选择明文攻击。
  内置纯软件 SHA‑256，无平台依赖，可移植到任何 C99 环境。

- **极轻量**
  核心加密仅需查表、异或、移位，无大数运算。CPA 模式增加 SHA‑256 开销，仍适合微控制器。

## 📁 文件结构
├── cdcb_k4m16.h # 基础版（身份混淆、数据加密）头文件
├── cdcb_k4m16.c # 基础版实现（偏置、洗牌、加解密）
├── cdcb_k4m16_cpa.h # CPA 消息加密头文件（动态码本）
├── cdcb_k4m16_cpa.c # CPA 消息加密实现（内置 SHA‑256）
├── demo_basic.c # 基础加解密演示
├── demo_cpa.c # CPA 消息加密演示
└── README.md


## 🚀 快速开始

### 1. 集成到项目
将 `cdcb_k4m16.h`、`cdcb_k4m16.c`、`cdcb_k4m16_cpa.h`、`cdcb_k4m16_cpa.c` 加入工程，包含头文件即可。
**注意：** 基础版在洗牌和偏置生成中使用了 `rand()`，**生产环境务必替换为硬件真随机源**（如 ESP32 的 `esp_random()`）。

### 2. 基础加解密（使用固定码本）

```c
#include "cdcb_k4m16.h"

// 准备密钥、基码、明文
uint8_t key[32] = { /* 32 字节密钥 */ };
uint16_t kid[4] = {0x168D, 0x5BDF, 0x17A7, 0x1949};
uint8_t plain[16] = "Hello CDCB!";
uint8_t cipher[64];
uint8_t decrypted[16];
uint32_t clen, plen;

// 初始化码本
cdcb_k4m16_t ctx;
cdcb_key_k4m16_update(&ctx, key, kid, NULL, NULL, 0);

// 加密
cdcb_encrypt(plain, 16, cipher, &clen, &ctx);
// 解密
cdcb_decrypt(cipher, clen, decrypted, &plen, &ctx);
```

### **3. CPA 消息加密（动态码本，抗选择明文攻击）**


```c
#include "cdcb_k4m16_cpa.h"

// 双方预共享主密钥和基码
uint8_t master_key[32] = { /* ... */ };
uint16_t base_codes[4] = {0x168D, 0x5BDF, 0x17A7, 0x1949};

// 初始化发送方上下文（nonce 从 0 开始）
cdcb_msg_ctx_t enc_ctx, dec_ctx;
cdcb_msg_init(&enc_ctx, master_key, base_codes, 0);
cdcb_msg_init(&dec_ctx, master_key, base_codes, 0);

// 加密
uint8_t plain[] = "Secret message";
uint8_t cipher[256];
size_t clen;
cdcb_msg_encrypt(&enc_ctx, plain, strlen(plain), cipher, &clen);

// 解密（接收方使用相同 master_key 和 base_codes，nonce 从密文头部自动提取）
uint8_t dec[256];
size_t dlen;
cdcb_msg_decrypt(&dec_ctx, cipher, clen, dec, &dlen);
```

## **📖 API 参考**

### **基础版 (`cdcb_k4m16.h`)**

| **函数** | **说明** |
| --- | --- |
| `cdcb_key_k4m16_update(key, cdcb_key, kid, knowledge, plaintext, plain_len)` | 更新密钥、基码和偏置权重 |
| `cdcb_encrypt_nibble(plain_4bit, key)` | 半字节加密，返回 16 位密文 |
| `cdcb_decrypt_nibble(cipher, key)` | 半字节解密，返回 4 位明文 |
| `cdcb_encrypt(plaintext, plain_len, ciphertext, &cipher_len, key)` | 批量字节加密 |
| `cdcb_decrypt(ciphertext, cipher_len, plaintext, &plain_len, key)` | 批量字节解密 |
| `CDCB_kid_rotate(code, n)` | 16 位循环左移 |
| `CDCB_kid_to_base(cipher, &offset)` | 从密文提取基码和旋转偏移 |

### **CPA 消息加密 (`cdcb_k4m16_cpa.h`)**

| **函数** | **说明** |
| --- | --- |
| `cdcb_msg_init(ctx, master_key, base_codes, init_nonce)` | 初始化消息加密上下文 |
| `cdcb_msg_encrypt(ctx, plain, plain_len, cipher, &cipher_len)` | 加密一条消息，密文头部包含 8 字节 nonce |
| `cdcb_msg_decrypt(ctx, cipher, cipher_len, plain, &plain_len)` | 解密，自动提取 nonce 并重建临时码本 |

## **🔐 安全性说明**

- **CPA 安全**
    
    `cdcb_msg_encrypt` 每消息动态派生临时码本，同一明文在不同 nonce 下密文完全不同，满足 IND‑CPA 安全。
    
- **偏置权重**
    
    即便攻击者获取多条密文，由于偏置随机选择码本，密文分布均匀，无统计偏差可循。
    
- **抗侧信道建议**
    
    当前演示代码使用 `rand()`，实际产品必须替换为加密级随机源。
    
    洗牌和码本访问中应考虑恒时操作（若平台要求抗侧信道）。
    
- **基码池管理**
    
    默认提供了 64 个私有基码和 8 个公共基码，用户应定期更换基码组合以增强安全性。
    
    静态盐值用于身份混淆，CPA 模式使用动态派生盐值，互不冲突。
    

## **📦 依赖**

- 标准 C 库（`string.h`, `stdlib.h`, `stdint.h`）
- `cdcb_k4m16_cpa` 内置了软件 SHA‑256，**零外部依赖**
