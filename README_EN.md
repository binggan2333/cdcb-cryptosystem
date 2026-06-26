# CDCB - Controllable Dynamic Codebook Cryptosystem

A lightweight cryptosystem designed for resource-constrained devices to resist AI statistical attacks.
This system provides statistical indistinguishability guarantees and targets a minimum theoretical security strength of 161 bits for constrained MCUs.

## Table of Contents

- [Project Background](#project-background)
- [Key Features](#key-features)
- [Quick Start](#quick-start)
- [API Documentation](#api-documentation)
- [Security Configuration](#security-configuration)
- [Theoretical Background](#theoretical-background)
- [Intellectual Property Statement](#intellectual-property-statement)
- [Contributing & Contact](#contributing--contact)
- [Versioning & Anchoring Information](#versioning--anchoring-information)

## Project Background

Traditional dynamic codebook encryption suffers from the "statistical equivalence" problem: switching codebooks by time or by uniform random selection still leaves exploitable frequency artifacts. This project breaks statistical correlations between codebooks using rotation-inequivalent codes and fixed-bias weights (one-sided weights). The result is a ciphertext leakage reduced to 0.14 bits and an effective theoretical security strength of 161 bits on 8-bit MCUs.

The idea originated when the author investigated whether a key-hint module could leak user behavior features. Early simple designs were flagged by AI security analysis tools for statistical leakage. That motivated a deeper study into the statistical security of multi-codebook encryption. To invite scrutiny and help others reproduce the results, the implementation, mathematical derivations and experimental data are fully open-sourced. This work is the author's independent research and is unrelated to their institution.

## Key Features

- Statistical indistinguishability: fixed-bias weights make plaintext→ciphertext mappings converge into two frequency tiers, preventing attackers from aligning codebooks.
- Local unsolvability: a single codebook cannot be independently verified — attackers must jointly break all codebooks, turning the search cost into a product rather than a sum.
- Lightweight: only requires rotate, table lookup and shuffle operations, with very low resource usage on 8-bit MCUs.
- One-sided bias: the encrypter decides weights independently; the decrypter identifies the codebook automatically using base codes.
- Dynamically updatable: replacing salts generates a completely new set of codebooks without rebuilding the base-code pool.

## Quick Start

```c
int main() {
    // 1. Initialize salts (uses default RNG if NULL)
    CDCB_salt_init(NULL, 0);
    // 2. Generate dynamic codebooks
    CDCB_codebook_init();
    // 3. Configure bias weights (random mode)
    CDCB_bias_init(NULL, 0);

    // 4. Encrypt some bytes
    uint8_t msg[] = {0xAB, 0xCD, 0x12, 0x34};
    uint16_t enc[8];
    for (int i = 0; i < 4; i++) {
        CDCB_encrypt_byte(msg[i], &enc[i*2]);
    }

    // 5. Decrypt
    uint8_t dec[4];
    bool ok = true;
    for (int i = 0; i < 4; i++) {
        if (!CDCB_decrypt_byte(&enc[i*2], &dec[i])) ok = false;
    }
    // ok == true, dec equals msg
    return 0;
}
```

> Warning: The example uses rand() as the default RNG for demonstration only. Replace with a cryptographically secure RNG in production. See [Security Configuration](#security-configuration).

## API Documentation

### Initialization

| Function | Description |
| --- | --- |
| `CDCB_salt_init(external_salts, count)` | Initialize four independent salts. Accepts external salts or auto-generates them. |
| `CDCB_codebook_init()` | Generate / update dynamic codebooks and inverse maps. |
| `CDCB_bias_init(buf, len)` | Configure fixed bias weights. len=0 => random mode; len>0 => bimodal polarization mode. |
| `CDCB_safe_kid_init()` | Initialize base-code offsets (used in one-sided label scenarios). |

### Encryption / Decryption

| Function | Description |
| --- | --- |
| `CDCB_encrypt_nibble(plain_4bit)` | Encrypt 4-bit plaintext, returns 16-bit ciphertext token. |
| `CDCB_decrypt_nibble(cipher, &plain_4bit, &group)` | Decrypt 4-bit ciphertext, returns plaintext and codebook index. |
| `CDCB_encrypt_byte(plain_byte, cipher[2])` | Encrypt one byte, outputs two 16-bit tokens. |
| `CDCB_decrypt_byte(cipher[2], &plain_byte)` | Decrypt one byte. |

### Helpers

| Function | Description |
| --- | --- |
| `CDCB_kid_rotate(code, n)` | 16-bit left rotation by n. |
| `CDCB_kid_to_base(kid, &offset)` | Extract base code and relative offset from ciphertext. |
| `CDCB_update_salts(new_salts)` | Update salts and rebuild codebooks. |
| `CDCB_update_salts_from_seed(seed)` | Update salts derived from an agreed seed. |

### Configuration Macros

| Macro | Default | Description |
| --- | ---: | --- |
| `CDCB_SAFE_KID_BITS` | 16 | Rotation period / code length. |
| `CDCB_SAFE_POOL_SIZE` | 64 | Private base-code pool size. |
| `CDCB_SAFE_CODEBOOKS` | 4 | Number of simultaneous codebooks. |
| `CDCB_SAFE_PRODUCTION` | undefined | When defined, demo RNG disabled; must provide `CDCB_SAFE_RANDOM()`. |
| `CDCB_SAFE_RANDOM()` | `rand()` | RNG macro — must be replaced with secure RNG in production. |

## Security Configuration

### 1. Replace the RNG (mandatory)

The default `rand()` used in examples is not cryptographically secure. Replace it with a platform-appropriate secure RNG:

```c
// Linux/macOS
#define CDCB_SAFE_RANDOM() ({ \
    uint8_t r; \
    if (getentropy(&r, sizeof(r)) != 0) abort(); \
    r; \
})

// ESP32
#define CDCB_SAFE_RANDOM() esp_random()

// STM32 HAL
#define CDCB_SAFE_RANDOM() ({ \
    uint32_t r; \
    HAL_RNG_GenerateRandomNumber(&hrng, &r); \
    (uint8_t)r; \
})
```

### Salt management

Both parties must use the same four 64-bit salts. Derive or distribute salts via a pre-shared key, secure negotiation, or from shared public events.

### Bias weight configuration

- Random mode: use when there is no prior knowledge about plaintext frequencies. Each plaintext value gets a fixed, non-uniform random weight.
- Bimodal polarization mode: shape high-frequency and low-frequency tiers according to known plaintext symbol frequencies to further reduce leakage.

### Codebook updates

Periodically call `CDCB_update_salts_from_seed()` to update codebooks. After an update, ciphertexts generated under an old codebook cannot be decrypted by the new codebook—ensure both parties synchronize updates.

## Theoretical Background

See the preprint "Controllable Dynamic Codebook Cryptosystem: From Eliminating Statistical Equivalence to Local Unsolvability Proof" for complete proofs. Core claims include:

1. Decoupling algebraic equivalence and statistical equivalence: public rotational redundancy combined with bias weights breaks statistical equivalence.
2. Information-theoretic proof for fixed-bias weights: shows p(c_i | C_i) ≠ p(a), leakage limited to 0.14 bits.
3. Local unsolvability and multiplicative complexity: a single codebook cannot be independently verified; an attacker must jointly break all codebooks.
4. Optimality of bimodal polarization: four statistical metrics show the strategy reduces attacker classification accuracy to ~61.3% (near random).

Links: preprint (arXiv), detailed docs in `docs/`.

## Intellectual Property Statement

- Open-source license: non-commercial code and documentation are provided under the **Apache 2.0 license**. Individuals and organizations may download, use, modify and redistribute the code for non-commercial purposes.
- Patent: a patent application has been filed covering core techniques `202610926538.8`. The scope of patent protection covers core innovations including the construction method of rotationally inequivalent base code pools, the multi-codebook encryption architecture with fixed bias weights, the bimodal polarization weight allocation mechanism, and the zero-synchronization codebook self-identification decryption system.
- Commercial licensing: commercial use requires prior written authorization.

## Contributing & Contact

### How to Contribute
- Code contributions: PRs for bug fixes, performance improvements, and new features are welcome; follow the existing code style.
- Security audits: independent cryptanalysis and attack testing are encouraged.
- Documentation: help improve technical docs, examples, and tutorials.
- Academic collaboration: researchers in cryptography, embedded security, and AI security are invited to contribute to proofs and experiments.

### Authorship Principles
- Core theoretical parts (decoupling algebraic/statistical equivalence, fixed-bias proofs, local unsolvability) favor first authorship.
- Implementation and engineering credit is proportional to contribution.
- AI defense & extension work included in authorship discussions.

### Contact
- WeChat: 18337606556
- Phone: +86 18337606556
- QQ: 1424993158
- Email: 1424993158@qq.com
- GitHub: https://github.com/binggan2333/cdcb-cryptosystem.git

This project is an independent research effort and open to flexible collaboration.

## Versioning & Anchoring Information

To ensure provenance, this release contains the following anchors:

- Core finalized version: v0.9
- Archive SHA256 checksum: DC7AD469884A6CBE550740DD85D580C57F37461FF6D3DF2E083090A259515185
- Blockchain anchor hash: 0xe15f394f0f39c94fa793c83d10d8e99ab08654f5ce16c31246243557fef81314
- Anchoring platform: Ethereum [View Transaction Record](https://etherscan.io/tx/0xe15f394f0f39c94fa793c83d10d8e99ab08654f5ce16c31246243557fef81314 "CDCB v0.9 Ethereum Notarization Transaction")
- Anchor date: May 25, 2026 (UTC+8)

Any user may verify the integrity and provenance of the released files using the checksum and anchor information above.

### Version History
- v0.9 (2026-05-24): initial public release containing core encryption/decryption functionality, random bias mode and bimodal polarization distribution.
