# CDCB-k4m16-v0.9.1
Controllable Dynamic Codebook Cryptosystem (k=4, m=16)

## 版本信息
- 版本：v0.9.1
- 配置：k=4 个码本、m=16 个字符
- 状态：定稿版，含完整注释与测试用例

## 更新说明
1. 补全了 cdcb_k4m16.h 接口注释，统一了函数风格
2. 完善了 main.c 测试用例，支持一键编译验证
3. 优化了 bias 边界处理，提升鲁棒性
4. 代码结构最终定型，可直接用于论文与工程验证

## 文件内容
- cdcb_k4m16.h：结构体定义 + 函数声明
- cdcb_k4m16.c：核心加密/解密/更新实现
- main.c：完整测试示例

# CDCB-k4m16-v0.9.1
Controllable Dynamic Codebook Cryptosystem (k=4, m=16)

## Version Information
- Version: v0.9.1
- Configuration: k=4 codebooks, m=16 symbols
- Status: Finalized release, with complete comments and test cases

## Changelog
1. Completed API documentation in `cdcb_k4m16.h` and standardized function styles
2. Enhanced `main.c` test case, supporting one-click compilation and verification
3. Optimized boundary handling for bias calculation, improving overall robustness
4. Finalized code structure, ready for use in both academic papers and engineering validation

## File Contents
- `cdcb_k4m16.h`: Structure definitions and function declarations
- `cdcb_k4m16.c`: Core implementation of encryption, decryption, and update logic
- `main.c`: Complete test example
