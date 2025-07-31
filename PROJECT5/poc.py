import hmac
import math
import time
from typing import Tuple, Union, List

P = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF
A = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFC
B = 0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93
N = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123
Gx = 0x32C4AE2C_1F198119_5F990446_6A39C994_8FE30BBF_F2660BE1_715A4589_334C74C7
Gy = 0xBC3736A2_F4F6779C_59BDCEE3_6B692153_D0A9877C_C62A4740_02DF32E5_2139F0A0
Point = Tuple[int, int]

def _rotate_left(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
def _ff(x: int, y: int, z: int, j: int) -> int:
    return (x ^ y ^ z) if 0 <= j <= 15 else (x & y) | (x & z) | (y & z)
def _gg(x: int, y: int, z: int, j: int) -> int:
    return (x ^ y ^ z) if 0 <= j <= 15 else (x & y) | (~x & z)
def _p0(x: int) -> int:
    return x ^ _rotate_left(x, 9) ^ _rotate_left(x, 17)
def _p1(x: int) -> int:
    return x ^ _rotate_left(x, 15) ^ _rotate_left(x, 23)
def sm3_hash(data: bytes) -> bytes:
    iv = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
    length = len(data); padded_data = data + b'\x80' + b'\x00' * ((56 - (length + 1) % 64) % 64) + (length * 8).to_bytes(8, 'big')
    for i in range(0, len(padded_data), 64):
        block = padded_data[i:i+64]; w = [int.from_bytes(block[j:j+4], 'big') for j in range(0, 64, 4)]
        for j in range(16, 68): w.append(_p1(w[j-16] ^ w[j-9] ^ _rotate_left(w[j-3], 15)) ^ _rotate_left(w[j-13], 7) ^ w[j-6])
        w_prime = [(w[j] ^ w[j+4]) for j in range(64)]; a, b, c, d, e, f, g, h = iv
        for j in range(64):
            t_j = 0x79CC4519 if 0 <= j <= 15 else 0x7A879D8A
            ss1 = _rotate_left((_rotate_left(a, 12) + e + _rotate_left(t_j, j % 32)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ _rotate_left(a, 12); tt1 = (_ff(a, b, c, j) + d + ss2 + w_prime[j]) & 0xFFFFFFFF
            tt2 = (_gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c; c = _rotate_left(b, 9); b = a; a = tt1; h = g; g = _rotate_left(f, 19); f = e; e = _p0(tt2)
        iv = [(iv[k] ^ [a,b,c,d,e,f,g,h][k]) & 0xFFFFFFFF for k in range(8)]
    return b''.join(x.to_bytes(4, 'big') for x in iv)
def inv(a: int, n: int) -> int:
    if a == 0: raise ZeroDivisionError("inverse of 0 does not exist")
    lm, hm, low, high = 1, 0, a % n, n
    while low > 1:
        r = high // low; nm, new = hm - lm * r, high - low * r; lm, low, hm, high = nm, new, lm, low
    return lm % n
def point_add(p1: Point, p2: Point) -> Union[Point, None]:
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and y1 != y2: return None
    if x1 == x2: m = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else: m = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (m * m - x1 - x2) % P; y3 = (m * (x1 - x3) - y1) % P
    return x3, y3
def scalar_mult(k: int, p: Point) -> Union[Point, None]:
    if p is None or k % N == 0: return None
    result = None; addend = p
    while k:
        if k & 1: result = point_add(result, addend)
        addend = point_add(addend, addend); k >>= 1
    return result

def faulty_sm2_sign(private_key: int, public_key: Point, message: bytes, k_reused: int, user_id: str = "attacker@example.com") -> Tuple[int, int]:
    """一个有缺陷的签名函数，它使用一个固定的k值。"""
    G = (Gx, Gy)
    user_id_bytes = user_id.encode('utf-8')
    entl = (len(user_id_bytes) * 8).to_bytes(2, 'big')
    data_to_hash = entl + user_id_bytes + A.to_bytes(32, 'big') + B.to_bytes(32, 'big') + Gx.to_bytes(32, 'big') + Gy.to_bytes(32, 'big') + public_key[0].to_bytes(32, 'big') + public_key[1].to_bytes(32, 'big')
    z = sm3_hash(data_to_hash)
    
    m_prime = z + message
    e = int.from_bytes(sm3_hash(m_prime), 'big')
    
    # 使用固定的k
    k = k_reused
    x1, _ = scalar_mult(k, G)
    r = (e + x1) % N
    
    # 检查 r 是否有效
    if r == 0 or r + k == N:
        raise ValueError("r or r+k is invalid, try another k")

    d = private_key
    s1 = inv(1 + d, N)
    s2 = (k - r * d) % N
    s = (s1 * s2) % N

    if s == 0:
        raise ValueError("s is zero, try another k")
        
    return r, s

def recover_private_key(sig1: Tuple[int, int], sig2: Tuple[int, int], msg1_hash: bytes, msg2_hash: bytes) -> int:
    """根据两条签名和消息哈希，恢复私钥d。"""
    r1, s1 = sig1
    r2, s2 = sig2
    e1 = int.from_bytes(msg1_hash, 'big')
    e2 = int.from_bytes(msg2_hash, 'big')


    s1_minus_s2 = (s1 - s2 + N) % N
    term2_inv = inv((s2 + r2 - s1 - r1 + N) % N, N)
    
    recovered_d = (s1_minus_s2 * term2_inv) % N
    return recovered_d

if __name__ == '__main__':
    
    # 生成一个密钥对
    victim_d = int.from_bytes(b'This is a very secret key_12345', 'big') % (N-1) + 1
    victim_pk = scalar_mult(victim_d, (Gx, Gy))
    print(f"受害者原始私钥 (d): {hex(victim_d)}")

    message1 = b"Transaction details: send 10 BTC to Alice."
    message2 = b"Transaction details: send 1000 BTC to Bob."

    # 重用了k
    reused_k = int.from_bytes(b'A bad random number generator!!', 'big') % (N-1) + 1
    print(f"\n受害者使用了有缺陷的签名程序，重用了 k = {hex(reused_k)}")
    
    sig1 = faulty_sm2_sign(victim_d, victim_pk, message1, reused_k)
    sig2 = faulty_sm2_sign(victim_d, victim_pk, message2, reused_k)
    print(f"签名1 (r1, s1) for M1: ({hex(sig1[0])}, {hex(sig1[1])})")
    print(f"签名2 (r2, s2) for M2: ({hex(sig2[0])}, {hex(sig2[1])})")


    # 攻击者计算消息的哈希 e1, e2
    z_for_attack = faulty_sm2_sign.__defaults__[0]
    user_id_bytes = z_for_attack.encode('utf-8')
    entl = (len(user_id_bytes) * 8).to_bytes(2, 'big')
    data_to_hash = entl + user_id_bytes + A.to_bytes(32, 'big') + B.to_bytes(32, 'big') + Gx.to_bytes(32, 'big') + Gy.to_bytes(32, 'big') + victim_pk[0].to_bytes(32, 'big') + victim_pk[1].to_bytes(32, 'big')
    z = sm3_hash(data_to_hash)

    msg1_hash = sm3_hash(z + message1)
    msg2_hash = sm3_hash(z + message2)

    recovered_d = recover_private_key(sig1, sig2, msg1_hash, msg2_hash)
    print(f"\n攻击者通过计算恢复出的私钥: {hex(recovered_d)}")
    
    if recovered_d == victim_d:
        print("\n攻击成功，恢复的私钥与原始私钥一致")
    else:
        print("\n攻击失败。")