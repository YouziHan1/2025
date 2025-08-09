#pragma once
#include <cstdint>
#include <vector>
#include <array>
#include <string>

namespace sm4gcm {

struct GCMResult {
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, 16> tag;
};

// 加密：返回密文与tag
GCMResult encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& plaintext);

// 解密：tag 验证失败将返回空密文
bool decrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& ciphertext,
    const std::array<uint8_t, 16>& tag,
    std::vector<uint8_t>& plaintext_out);

}
