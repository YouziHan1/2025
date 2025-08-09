#include "sm4_gcm.h"
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <iostream>

namespace {

static const uint8_t S_BOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};
static const uint32_t FK[4] = {0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc};
static const uint32_t CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

inline uint32_t rotLeft(uint32_t w, int b){return (w<<b)|(w>>(32-b));}
inline uint32_t bytesToWord(const uint8_t* p){return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | (uint32_t)p[3];}
inline void wordToBytes(uint32_t w, uint8_t* p){p[0]=w>>24; p[1]=(w>>16)&0xFF; p[2]=(w>>8)&0xFF; p[3]=w&0xFF;}

inline uint32_t T_key(uint32_t w){
    uint8_t in[4]; wordToBytes(w,in); uint8_t out[4];
    for(int i=0;i<4;++i) out[i]=S_BOX[in[i]];
    uint32_t t=bytesToWord(out);
    return t ^ rotLeft(t,13) ^ rotLeft(t,23);
}
inline uint32_t T_crypt(uint32_t w){
    uint8_t in[4]; wordToBytes(w,in); uint8_t out[4];
    for(int i=0;i<4;++i) out[i]=S_BOX[in[i]];
    uint32_t t=bytesToWord(out);
    return t ^ rotLeft(t,2) ^ rotLeft(t,10) ^ rotLeft(t,18) ^ rotLeft(t,24);
}

static void sm4_key_schedule(const std::vector<uint8_t>& key, std::array<uint32_t,32>& rk){
    if(key.size()!=16) throw std::invalid_argument("SM4 key must be 16 bytes");
    uint32_t MK[4];
    for(int i=0;i<4;++i) MK[i]=bytesToWord(&key[i*4]);
    uint32_t K[36];
    for(int i=0;i<4;++i) K[i]=MK[i]^FK[i];
    for(int i=0;i<32;++i){
        uint32_t t=K[i+1]^K[i+2]^K[i+3]^CK[i];
        K[i+4]=K[i]^T_key(t);
        rk[i]=K[i+4];
    }
}

static void sm4_encrypt_block(const std::array<uint32_t,32>& rk, const uint8_t in[16], uint8_t out[16]){
    uint32_t X[36];
    for(int i=0;i<4;++i) X[i]=bytesToWord(&in[i*4]);
    for(int i=0;i<32;++i){
        uint32_t t=X[i+1]^X[i+2]^X[i+3]^rk[i];
        X[i+4]=X[i]^T_crypt(t);
    }
    for(int i=0;i<4;++i) wordToBytes(X[35-i], &out[i*4]);
}

// CTR 增计数器（大端 32-bit 低位）
static void inc32(uint8_t J[16]){
    uint32_t c = (uint32_t)J[12]<<24 | (uint32_t)J[13]<<16 | (uint32_t)J[14]<<8 | (uint32_t)J[15];
    c = (c + 1) & 0xFFFFFFFFu;
    J[12] = (c>>24)&0xFF; J[13]=(c>>16)&0xFF; J[14]=(c>>8)&0xFF; J[15]=c&0xFF;
}

// GF(2^128) 乘法用二进制多项式（与GCM一致的x^128 + x^7 + x^2 + x + 1）
static void ghash_mul(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16]){
    uint8_t V[16]; std::memcpy(V,Y,16);
    uint8_t Zt[16]={0};
    for(int i=0;i<128;++i){
        int bit = (X[i/8] >> (7-(i%8))) & 1;
        if(bit){ for(int j=0;j<16;++j) Zt[j]^=V[j]; }
        // V = V * x mod P(x)
        int lsb = V[15] & 1;
        for(int j=15;j>=0;--j){
            uint8_t next = j?V[j-1]:0;
            V[j] = (V[j]>>1) | ((next&1)?0x80:0);
        }
        if(lsb){ V[0]^=0xe1; }
    }
    std::memcpy(Z,Zt,16);
}

static void ghash_acc(uint8_t H[16], const std::vector<uint8_t>& data, uint8_t Y[16]){
    uint8_t X[16];
    size_t n = (data.size()+15)/16;
    for(size_t i=0;i<n;++i){
        std::memset(X,0,16);
        size_t off = i*16; size_t len = std::min<size_t>(16, data.size()-off);
        std::memcpy(X, data.data()+off, len);
        for(int j=0;j<16;++j) Y[j]^=X[j];
        uint8_t t[16]; ghash_mul(Y,H,t); std::memcpy(Y,t,16);
    }
}

static void to_be64(uint64_t v, uint8_t out[8]){
    for(int i=0;i<8;++i) out[i]=(uint8_t)(v>>(56-8*i));
}

} // anonymous

namespace sm4gcm {

GCMResult encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& plaintext){

    std::array<uint32_t,32> rk; sm4_key_schedule(key,rk);

    // H = E(K, 0^128)
    uint8_t zero[16]={0}, H[16]; sm4_encrypt_block(rk, zero, H);

    // 计算 J0
    uint8_t J0[16]={0};
    if(iv.size()==12){
        std::memcpy(J0, iv.data(), 12);
        J0[15]=1; // 0x00000001
    } else {
        uint8_t Y[16]={0};
        ghash_acc(H, iv, Y);
        uint8_t S[16];
        std::memset(S,0,16);
        uint8_t Lbuf[16]={0};
        to_be64(iv.size()*8, Lbuf+8);
        for(int j=0;j<16;++j) Y[j]^=Lbuf[j];
        uint8_t t[16]; ghash_mul(Y,H,t); std::memcpy(J0,t,16);
    }

    // CTR 加密
    std::vector<uint8_t> ciphertext(plaintext.size());
    uint8_t ctr[16]; std::memcpy(ctr,J0,16); inc32(ctr);

    for(size_t off=0; off<plaintext.size(); off+=16){
        uint8_t S[16]; sm4_encrypt_block(rk, ctr, S);
        size_t n = std::min<size_t>(16, plaintext.size()-off);
        for(size_t i=0;i<n;++i) ciphertext[off+i]=plaintext[off+i]^S[i];
        inc32(ctr);
    }

    // GHASH over AAD || C || len(A)||len(C)
    uint8_t Y[16]={0};
    ghash_acc(H, aad, Y);
    ghash_acc(H, ciphertext, Y);
    uint8_t L[16]={0};
    to_be64((uint64_t)aad.size()*8, L);
    to_be64((uint64_t)ciphertext.size()*8, L+8);
    for(int j=0;j<16;++j) Y[j]^=L[j];
    uint8_t Sfin[16]; ghash_mul(Y,H,Sfin);

    // Tag = E(K,J0) xor S
    uint8_t E_J0[16]; sm4_encrypt_block(rk, J0, E_J0);
    std::array<uint8_t,16> tag{};
    for(int i=0;i<16;++i) tag[i]=E_J0[i]^Sfin[i];

    return { std::move(ciphertext), tag };
}

bool decrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& ciphertext,
    const std::array<uint8_t, 16>& tag,
    std::vector<uint8_t>& plaintext_out){

    std::array<uint32_t,32> rk; sm4_key_schedule(key,rk);

    // H
    uint8_t zero[16]={0}, H[16]; sm4_encrypt_block(rk, zero, H);

    // J0
    uint8_t J0[16]={0};
    if(iv.size()==12){
        std::memcpy(J0, iv.data(), 12); J0[15]=1;
    } else {
        uint8_t Y0[16]={0};
        ghash_acc(H, iv, Y0);
        uint8_t Lbuf[16]={0}; to_be64(iv.size()*8, Lbuf+8);
        for(int j=0;j<16;++j) Y0[j]^=Lbuf[j];
        uint8_t t[16]; ghash_mul(Y0,H,t); std::memcpy(J0,t,16);
    }

    // recompute tag
    uint8_t Y[16]={0};
    ghash_acc(H, aad, Y);
    ghash_acc(H, ciphertext, Y);
    uint8_t L[16]={0};
    to_be64((uint64_t)aad.size()*8, L);
    to_be64((uint64_t)ciphertext.size()*8, L+8);
    for(int j=0;j<16;++j) Y[j]^=L[j];
    uint8_t Sfin[16]; ghash_mul(Y,H,Sfin);

    uint8_t E_J0[16]; sm4_encrypt_block(rk, J0, E_J0);
    uint8_t tag_calc[16];
    for(int i=0;i<16;++i) tag_calc[i]=E_J0[i]^Sfin[i];

    // 常数时间比较
    uint8_t acc=0; for(int i=0;i<16;++i) acc |= (tag_calc[i]^tag[i]);
    if(acc!=0) return false;

    // CTR 解密
    plaintext_out.resize(ciphertext.size());
    uint8_t ctr[16]; std::memcpy(ctr,J0,16); inc32(ctr);
    for(size_t off=0; off<ciphertext.size(); off+=16){
        uint8_t S[16]; sm4_encrypt_block(rk, ctr, S);
        size_t n = std::min<size_t>(16, ciphertext.size()-off);
        for(size_t i=0;i<n;++i) plaintext_out[off+i]=ciphertext[off+i]^S[i];
        inc32(ctr);
    }
    return true;
}

} // namespace sm4gcm
