#include "sm4_gcm.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>

using namespace std;

static vector<uint8_t> hex_to_bytes(const string& s){
    vector<uint8_t> o; o.reserve(s.size()/2);
    for(size_t i=0;i<s.size();i+=2){ o.push_back((uint8_t)strtol(s.substr(i,2).c_str(), nullptr, 16)); }
    return o;
}
static void print_hex(const char* name, const vector<uint8_t>& d){
    cout << name << ": ";
    for(auto b:d) cout << hex << setw(2) << setfill('0') << (int)b;
    cout << dec << "\n";
}
static void print_hex_tag(const char* name, const array<uint8_t,16>& d){
    cout << name << ": ";
    for(auto b:d) cout << hex << setw(2) << setfill('0') << (int)b;
    cout << dec << "\n";
}

int main(){
    auto key = hex_to_bytes("0123456789abcdeffedcba9876543210");
    auto iv  = hex_to_bytes("00112233445566778899aabb"); // 12字节推荐
    vector<uint8_t> aad = {'h','e','l','l','o'};
    auto pt  = hex_to_bytes("00112233445566778899aabbccddeeff0011");

    // 计时：加密
    auto t1 = chrono::high_resolution_clock::now();
    auto enc = sm4gcm::encrypt(key, iv, aad, pt);
    auto t2 = chrono::high_resolution_clock::now();

    print_hex("cipher", enc.ciphertext);
    print_hex_tag("tag", enc.tag);

    // 计时：解密
    vector<uint8_t> decpt;
    auto t3 = chrono::high_resolution_clock::now();
    bool ok = sm4gcm::decrypt(key, iv, aad, enc.ciphertext, enc.tag, decpt);
    auto t4 = chrono::high_resolution_clock::now();

    cout << "auth: " << (ok?"ok":"fail") << "\n";
    print_hex("plain", decpt);

    auto enc_ns = chrono::duration_cast<chrono::nanoseconds>(t2 - t1).count();
    auto dec_ns = chrono::duration_cast<chrono::nanoseconds>(t4 - t3).count();
    cout << "encrypt_time:" << enc_ns << "ns\n";
    cout << "decrypt_time:" << dec_ns << "ns\n";

    return 0;
}
