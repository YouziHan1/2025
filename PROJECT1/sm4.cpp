#include <iostream>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <iomanip>
#include <chrono>

using namespace std;

// S盒
const uint8_t S_BOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// F
const uint32_t FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

// CK
const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// 循环左移
uint32_t rotLeft(uint32_t word, int bits) {
    return (word << bits) | (word >> (32 - bits));
}

// 字节数组转32位字
uint32_t bytesToWord(const uint8_t* bytes) {
    return (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 | (uint32_t)bytes[2] << 8 | (uint32_t)bytes[3];
}

// 32位字转字节数组
void wordToBytes(uint32_t word, uint8_t* bytes) {
    bytes[0] = (word >> 24) & 0xFF;
    bytes[1] = (word >> 16) & 0xFF;
    bytes[2] = (word >> 8) & 0xFF;
    bytes[3] = word & 0xFF;
}

// 密钥扩展中的T'变换
uint32_t T_transform_key(uint32_t word) {
    uint8_t bytes_in[4];
    wordToBytes(word, bytes_in);
    uint8_t bytes_out[4];
    for (int i = 0; i < 4; ++i) {
        bytes_out[i] = S_BOX[bytes_in[i]];
    }
    uint32_t word_after_sbox = bytesToWord(bytes_out);
    return word_after_sbox ^ rotLeft(word_after_sbox, 13) ^ rotLeft(word_after_sbox, 23);
}

// 密钥扩展
vector<uint32_t> generate_round_keys(const vector<uint8_t>& master_key) {
    if (master_key.size() != 16) {
        throw invalid_argument("Master key must be 16 bytes (128 bits) long.");
    }

    vector<uint32_t> mk_words(4);
    for (int i = 0; i < 4; ++i) {
        mk_words[i] = bytesToWord(&master_key[i * 4]);
    }

    vector<uint32_t> k(36);
    for (int i = 0; i < 4; ++i) {
        k[i] = mk_words[i] ^ FK[i];
    }

    vector<uint32_t> round_keys(32);
    for (int i = 0; i < 32; ++i) {
        uint32_t key_arg = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i];
        k[i + 4] = k[i] ^ T_transform_key(key_arg);
        round_keys[i] = k[i + 4];
    }
    return round_keys;
}

// 加解密中的T变换
uint32_t T_transform_crypt(uint32_t word) {
    uint8_t bytes_in[4];
    wordToBytes(word, bytes_in);
    uint8_t bytes_out[4];
    for (int i = 0; i < 4; ++i) {
        bytes_out[i] = S_BOX[bytes_in[i]];
    }
    uint32_t word_after_sbox = bytesToWord(bytes_out);
    return word_after_sbox ^ rotLeft(word_after_sbox, 2) ^ rotLeft(word_after_sbox, 10) ^ rotLeft(word_after_sbox, 18) ^ rotLeft(word_after_sbox, 24);
}

// 加解密函数
vector<uint8_t> crypt_block(const vector<uint8_t>& block, const vector<uint32_t>& rk) {
    vector<uint32_t> x(36);
    for (int i = 0; i < 4; ++i) {
        x[i] = bytesToWord(&block[i * 4]);
    }

    for (int i = 0; i < 32; ++i) {
        uint32_t round_arg = x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i];
        x[i + 4] = x[i] ^ T_transform_crypt(round_arg);
    }

    vector<uint8_t> output_block(16);
    for (int i = 0; i < 4; ++i) {
        wordToBytes(x[35 - i], &output_block[i * 4]);
    }

    return output_block;
}


vector<uint8_t> sm4_encrypt(const vector<uint8_t>& plaintext, const vector<uint8_t>& key) {
    vector<uint32_t> round_keys = generate_round_keys(key);
    return crypt_block(plaintext, round_keys);
}


vector<uint8_t> sm4_decrypt(const vector<uint8_t>& ciphertext, const vector<uint8_t>& key) {
    vector<uint32_t> round_keys = generate_round_keys(key);
    reverse(round_keys.begin(), round_keys.end()); // 解密时逆序使用轮密钥
    return crypt_block(ciphertext, round_keys);
}



// 打印字节向量（以十六进制格式）
void print_hex(const string& label, const vector<uint8_t>& data) {
    cout << label;
    cout << hex << setfill('0');
    for (const auto& byte : data) {
        cout << setw(2) << static_cast<int>(byte);
    }
    cout << dec << endl;
}

// 十六进制字符串转换
vector<uint8_t> hex_to_bytes(const string& hex_str) {
    vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex_str.length(); i += 2) {
        string byteString = hex_str.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}


int main() {
    // GB/T 32907-2016 标准测试向量
    string key_hex = "0123456789abcdeffedcba9876543210";
    string plaintext_hex = "0123456789abcdeffedcba9876543210";
    string expected_ciphertext_hex = "681edf34d206965e86b3e94f536e4246";

    // 将十六进制字符串转换为字节向量
    vector<uint8_t> key = hex_to_bytes(key_hex);
    vector<uint8_t> plaintext = hex_to_bytes(plaintext_hex);

    cout << "--------------------------------------------------" << endl;
    print_hex("Key:", key);
    print_hex("Plaintext: ", plaintext);
    cout << "--------------------------------------------------" << endl;

    // 加密
    auto t1 = chrono::high_resolution_clock::now();
    vector<uint8_t> ciphertext = sm4_encrypt(plaintext, key);
    auto t2 = chrono::high_resolution_clock::now();
    auto enc_ns = chrono::duration_cast<chrono::nanoseconds>(t2 - t1).count();
    cout << "Encode_Totaltime: " << enc_ns << " ns" << endl;
    print_hex("Ciphertext: ", ciphertext);
    cout << "Expected_Ciphertext: " << expected_ciphertext_hex << endl;

    // 解密
    auto t3 = chrono::high_resolution_clock::now();
    vector<uint8_t> decrypted_text = sm4_decrypt(ciphertext, key);
    auto t4 = chrono::high_resolution_clock::now();
    auto dec_ns = chrono::duration_cast<chrono::nanoseconds>(t4 - t3).count();
    cout << "Decode_Totaltime: " << dec_ns << " ns" << endl;
    print_hex("Decode_Plaintext: ", decrypted_text);


    return 0;
}

