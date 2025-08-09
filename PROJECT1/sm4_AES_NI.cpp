//g++ -O3 -maes -mssse3 -o sm4_AES_NI.exe sm4_AES_NI.cpp
//./sm4_AES_NI.exe

#include <iostream>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <iomanip>
#include <cstring> 
#include <chrono>

#include <immintrin.h> // AVX, AVX2
#include <wmmintrin.h> // AES-NI
#include <tmmintrin.h> // SSSE3 for _mm_shuffle_epi8

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
const uint32_t FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

uint32_t rotLeft(uint32_t word, int bits) { return (word << bits) | (word >> (32 - bits)); }
uint32_t bytesToWord(const uint8_t* bytes) { return (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 | (uint32_t)bytes[2] << 8 | (uint32_t)bytes[3]; }
void wordToBytes(uint32_t word, uint8_t* bytes) { bytes[0] = (word >> 24) & 0xFF; bytes[1] = (word >> 16) & 0xFF; bytes[2] = (word >> 8) & 0xFF; bytes[3] = word & 0xFF; }

uint32_t T_transform_key(uint32_t word) {
    uint8_t bytes_in[4];
    wordToBytes(word, bytes_in);
    uint8_t bytes_out[4];
    for (int i = 0; i < 4; ++i) { bytes_out[i] = S_BOX[bytes_in[i]]; }
    uint32_t word_after_sbox = bytesToWord(bytes_out);
    return word_after_sbox ^ rotLeft(word_after_sbox, 13) ^ rotLeft(word_after_sbox, 23);
}

vector<uint32_t> generate_round_keys(const vector<uint8_t>& master_key) {
    if (master_key.size() != 16) { throw invalid_argument("Master key must be 16 bytes long."); }
    vector<uint32_t> mk_words(4);
    for (int i = 0; i < 4; ++i) { mk_words[i] = bytesToWord(&master_key[i * 4]); }
    vector<uint32_t> k(36);
    for (int i = 0; i < 4; ++i) { k[i] = mk_words[i] ^ FK[i]; }
    vector<uint32_t> round_keys(32);
    for (int i = 0; i < 32; ++i) {
        uint32_t key_arg = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i];
        k[i + 4] = k[i] ^ T_transform_key(key_arg);
        round_keys[i] = k[i + 4];
    }
    return round_keys;
}



#define XOR4(a,b,c,d) _mm_xor_si128(_mm_xor_si128(a,b), _mm_xor_si128(c,d))
#define XOR6(a,b,c,d,e,f) _mm_xor_si128(XOR4(a,b,c,d), _mm_xor_si128(e,f))
#define ROTL_EPI32(a, imm) _mm_or_si128(_mm_slli_epi32(a, imm), _mm_srli_epi32(a, 32 - imm))


inline __m128i MulMatrixToAES(__m128i x) {
    __m128i m0, m1, m2, m3, m4, m5, m6, m7;
    m0 = _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    m1 = _mm_set1_epi8(0x13); m2 = _mm_set1_epi8(0x39); m3 = _mm_set1_epi8(0x2a);
    m4 = _mm_set1_epi8(0x1f); m5 = _mm_set1_epi8(0x21); m6 = _mm_set1_epi8(0x19);
    m7 = _mm_set1_epi8(0x0a);
    m0 = _mm_shuffle_epi8(m1, _mm_and_si128(_mm_srli_epi16(x, 0), m0));
    m0 = _mm_xor_si128(m0, _mm_shuffle_epi8(m2, _mm_and_si128(_mm_srli_epi16(x, 1), m0)));
    m0 = _mm_xor_si128(m0, _mm_shuffle_epi8(m3, _mm_and_si128(_mm_srli_epi16(x, 2), m0)));
    m0 = _mm_xor_si128(m0, _mm_shuffle_epi8(m4, _mm_and_si128(_mm_srli_epi16(x, 3), m0)));
    m0 = _mm_xor_si128(m0, _mm_shuffle_epi8(m5, _mm_and_si128(_mm_srli_epi16(x, 4), m0)));
    m0 = _mm_xor_si128(m0, _mm_shuffle_epi8(m6, _mm_and_si128(_mm_srli_epi16(x, 5), m0)));
    m0 = _mm_xor_si128(m0, _mm_shuffle_epi8(m7, _mm_and_si128(_mm_srli_epi16(x, 6), m0)));
    m0 = _mm_xor_si128(m0, _mm_and_si128(_mm_srli_epi16(x, 7), m0));
    return m0;
}

inline __m128i MulMatrixBack(__m128i x) {
    __m128i m0, m1, m2, m3, m4, m5, m6, m7;
    m0 = _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    m1 = _mm_set1_epi8(0x45); m2 = _mm_set1_epi8(0x5d); m3 = _mm_set1_epi8(0x43);
    m4 = _mm_set1_epi8(0x4f); m5 = _mm_set1_epi8(0x15); m6 = _mm_set1_epi8(0x1f);
    m7 = _mm_set1_epi8(0x29);
    m0 = _mm_shuffle_epi8(m1, _mm_and_si128(_mm_srli_epi16(x, 0), m0));
    m0 = _mm_xor_si128(m0, _mm_shuffle_epi8(m2, _mm_and_si128(_mm_srli_epi16(x, 1), m0)));
    m0 = _mm_xor_si128(m0, _mm_shuffle_epi8(m3, _mm_and_si128(_mm_srli_epi16(x, 2), m0)));
    m0 = _mm_xor_si128(m0, _mm_shuffle_epi8(m4, _mm_and_si128(_mm_srli_epi16(x, 3), m0)));
    m0 = _mm_xor_si128(m0, _mm_shuffle_epi8(m5, _mm_and_si128(_mm_srli_epi16(x, 4), m0)));
    m0 = _mm_xor_si128(m0, _mm_shuffle_epi8(m6, _mm_and_si128(_mm_srli_epi16(x, 5), m0)));
    m0 = _mm_xor_si128(m0, _mm_shuffle_epi8(m7, _mm_and_si128(_mm_srli_epi16(x, 6), m0)));
    m0 = _mm_xor_si128(m0, _mm_and_si128(_mm_srli_epi16(x, 7), m0));
    return m0;
}

// S盒 利用AES-NI
inline __m128i SM4_SBox_TO_AES(__m128i x) {
    // 掩码，用于初始的位操作
    __m128i mask = _mm_set_epi8(0x03, 0x06, 0x09, 0x0c, 0x0f, 0x02, 0x05, 0x08,
                              0x0b, 0x0e, 0x01, 0x04, 0x07, 0x0a, 0x0d, 0x00);
    // 同构映射到AES域
    x = _mm_shuffle_epi8(x, mask);
    x = _mm_xor_si128(MulMatrixToAES(x), _mm_set1_epi8(0b00100011));
    // 使用AES-NI指令完成S盒操作
    x = _mm_aesenclast_si128(x, _mm_setzero_si128());
    // 同构逆映射回SM4域
    return _mm_xor_si128(MulMatrixBack(x), _mm_set1_epi8(0b00111011));
}

// 单轮迭代
#define SM4_ITERATION(Block, rk_val) \
    do { \
        __m128i temp; \
        __m128i k = _mm_set1_epi32(rk_val); \
        temp = XOR4(Block[1], Block[2], Block[3], k); \
        temp = SM4_SBox_TO_AES(temp); \
        temp = XOR6(Block[0], temp, ROTL_EPI32(temp, 2), \
                    ROTL_EPI32(temp, 10), ROTL_EPI32(temp, 18), \
                    ROTL_EPI32(temp, 24)); \
        Block[0] = Block[1]; \
        Block[1] = Block[2]; \
        Block[2] = Block[3]; \
        Block[3] = temp; \
    } while (0)

//加解密函数
void sm4_crypt_simd(uint8_t* output, const uint8_t* input, const uint32_t* rk, int enc) {
    __m128i Block[4];
    // 加载输入数据到SIMD寄存器
    Block[0] = _mm_loadu_si128((__m128i*)(input));
    Block[1] = _mm_loadu_si128((__m128i*)(input + 16));
    Block[2] = _mm_loadu_si128((__m128i*)(input + 32));
    Block[3] = _mm_loadu_si128((__m128i*)(input + 48));

    // 字节序反转
    const __m128i BSWAP_MASK = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    Block[0] = _mm_shuffle_epi8(Block[0], BSWAP_MASK);
    Block[1] = _mm_shuffle_epi8(Block[1], BSWAP_MASK);
    Block[2] = _mm_shuffle_epi8(Block[2], BSWAP_MASK);
    Block[3] = _mm_shuffle_epi8(Block[3], BSWAP_MASK);

    // 4x循环展开
    for (int i = 0; i < 32; i += 4) {
        uint32_t rk0 = (enc) ? rk[31 - (i + 0)] : rk[i + 0];
        uint32_t rk1 = (enc) ? rk[31 - (i + 1)] : rk[i + 1];
        uint32_t rk2 = (enc) ? rk[31 - (i + 2)] : rk[i + 2];
        uint32_t rk3 = (enc) ? rk[31 - (i + 3)] : rk[i + 3];
        SM4_ITERATION(Block, rk0);
        SM4_ITERATION(Block, rk1);
        SM4_ITERATION(Block, rk2);
        SM4_ITERATION(Block, rk3);
    }

    // 反序置换
    swap(Block[0], Block[3]);
    swap(Block[1], Block[2]);
    
    // 字节序反转
    Block[0] = _mm_shuffle_epi8(Block[0], BSWAP_MASK);
    Block[1] = _mm_shuffle_epi8(Block[1], BSWAP_MASK);
    Block[2] = _mm_shuffle_epi8(Block[2], BSWAP_MASK);
    Block[3] = _mm_shuffle_epi8(Block[3], BSWAP_MASK);

    // 将结果存回内存
    _mm_storeu_si128((__m128i*)(output), Block[0]);
    _mm_storeu_si128((__m128i*)(output + 16), Block[1]);
    _mm_storeu_si128((__m128i*)(output + 32), Block[2]);
    _mm_storeu_si128((__m128i*)(output + 48), Block[3]);
}

void print_hex(const string& label, const uint8_t* data, size_t len) {
    cout << label;
    cout << hex << setfill('0');
    for (size_t i = 0; i < len; ++i) {
        cout << setw(2) << static_cast<int>(data[i]);
    }
    cout << dec << endl;
}

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
    string key_hex = "0123456789abcdeffedcba9876543210";
    string plaintext_hex_single = "0123456789abcdeffedcba9876543210";
    string plaintext_hex = plaintext_hex_single + plaintext_hex_single + plaintext_hex_single + plaintext_hex_single;
    
    string expected_ciphertext_hex_single = "681edf34d206965e86b3e94f536e4246";
    string expected_ciphertext_hex = expected_ciphertext_hex_single + expected_ciphertext_hex_single + expected_ciphertext_hex_single + expected_ciphertext_hex_single;

    vector<uint8_t> key_vec = hex_to_bytes(key_hex);
    vector<uint8_t> plaintext_vec = hex_to_bytes(plaintext_hex);
    vector<uint8_t> ciphertext_vec(64);
    vector<uint8_t> decrypted_vec(64);

    // 生成轮密钥
    vector<uint32_t> rk = generate_round_keys(key_vec);
    

    cout << "SM4_SIMD_AES-NI:" << endl;
    cout << "--------------------------------------------------" << endl;
    print_hex("Key:", key_vec.data(), key_vec.size());
    print_hex("Plaintext: ", hex_to_bytes(plaintext_hex_single).data(), 16);
    cout << "--------------------------------------------------" << endl;

    // 加密
    auto start_time = chrono::high_resolution_clock::now();
    sm4_crypt_simd(ciphertext_vec.data(), plaintext_vec.data(), rk.data(), 1); // enc=1
    auto end_time = chrono::high_resolution_clock::now();
    auto encode_ns = chrono::duration_cast<chrono::nanoseconds>(end_time - start_time).count();
    cout << "Encode_Totaltime: " << encode_ns/4 << " ns" << endl;
    print_hex("Ciphertext: ", ciphertext_vec.data(), 16);
    cout << "Expected_Ciphertext: " << expected_ciphertext_hex_single << endl;



    // 解密
    start_time = chrono::high_resolution_clock::now();
    sm4_crypt_simd(decrypted_vec.data(), ciphertext_vec.data(), rk.data(), 0); // enc=0
    end_time = chrono::high_resolution_clock::now();
    auto decode_ns = chrono::duration_cast<chrono::nanoseconds>(end_time - start_time).count();
    cout << "Decode_Totaltime: " << decode_ns/4 << " ns" << endl;
    print_hex("Decode_Plaintext: ", decrypted_vec.data(), 16);
    
    return 0;
}
