import hashlib
import random
from typing import Tuple, Union
import time

# ==================== [ 新增 ] ====================
# 导入 gmssl 库中的 sm3_hash 函数
from gmssl.sm3 import sm3_hash

# -- SM2 推荐曲线参数 (来自 GB/T 32918.2-2016) --
P = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF
A = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFC
B = 0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93
N = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123
Gx = 0x32C4AE2C_1F198119_5F990446_6A39C994_8FE30BBF_F2660BE1_715A4589_334C74C7
Gy = 0xBC3736A2_F4F6779C_59BDCEE3_6B692153_D0A9877C_C62A4740_02DF32E5_2139F0A0

Point = Tuple[int, int]  # 点定义为 (x, y)

# SM3实现
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

def get_hash(data: bytes) -> bytes:

    iv = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
          0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
    
    length = len(data)
    padded_data = data + b'\x80'
    padded_data += b'\x00' * ((56 - (length + 1) % 64) % 64)
    padded_data += (length * 8).to_bytes(8, 'big')

    for i in range(0, len(padded_data), 64):
        block = padded_data[i:i+64]
        

        w = [int.from_bytes(block[j:j+4], 'big') for j in range(0, 64, 4)]
        for j in range(16, 68):
            term = w[j-16] ^ w[j-9] ^ _rotate_left(w[j-3], 15)
            w.append(_p1(term) ^ _rotate_left(w[j-13], 7) ^ w[j-6])

        w_prime = [(w[j] ^ w[j+4]) for j in range(64)]


        a, b, c, d, e, f, g, h = iv
        for j in range(64):
            t_j = 0x79CC4519 if 0 <= j <= 15 else 0x7A879D8A
            
            ss1 = _rotate_left((_rotate_left(a, 12) + e + _rotate_left(t_j, j % 32)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ _rotate_left(a, 12)
            tt1 = (_ff(a, b, c, j) + d + ss2 + w_prime[j]) & 0xFFFFFFFF
            tt2 = (_gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = _rotate_left(b, 9)
            b = a
            a = tt1
            h = g
            g = _rotate_left(f, 19)
            f = e
            e = _p0(tt2)
        
        iv = [(iv[k] ^ [a,b,c,d,e,f,g,h][k]) & 0xFFFFFFFF for k in range(8)]

    return b''.join(x.to_bytes(4, 'big') for x in iv)

def inv(a: int, n: int) -> int:
    """计算 a 在模 n 下的逆元 (使用扩展欧几里得算法)"""
    if a == 0:
        raise ZeroDivisionError("inverse of 0 does not exist")
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


# -- 椭圆曲线运算 --
def is_on_curve(p: Point) -> bool:
    """检查点是否在曲线上"""
    if p is None:
        return True # 无穷远点
    x, y = p
    return (y * y - (x * x * x + A * x + B)) % P == 0

def point_neg(p: Point) -> Union[Point, None]:
    """计算点的负元"""
    if p is None:
        return None
    x, y = p
    result = (x, -y % P)
    return result

def point_add(p1: Point, p2: Point) -> Union[Point, None]:
    """椭圆曲线点加"""
    if p1 is None: return p2
    if p2 is None: return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        return None # p1 = -p2
    
    if x1 == x2: # Point doubling
        # m = (3 * x1^2 + A) / (2 * y1)
        m = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else: # Point addition
        # m = (y2 - y1) / (x2 - x1)
        m = (y2 - y1) * inv(x2 - x1, P) % P
        
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    
    return (x3, y3)

def scalar_mult(k: int, p: Point) -> Union[Point, None]:
    """
    标量乘法 (k * P)，使用二进制展开法（Double-and-add）
    这是最基础但效率较低的实现
    """
    if p is None or k % N == 0:
        return None
    
    result = None
    addend = p
    
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend) # Double
        k >>= 1
        
    return result

class SM2Key:
    def __init__(self, private_key: int = None, public_key: Point = None):
        self.G = (Gx, Gy)
        
        if private_key:
            self.private_key = private_key
            self.public_key = scalar_mult(private_key, self.G)
        elif public_key:
            self.public_key = public_key
            self.private_key = None
        else: # 生成新的密钥对
            self.private_key = random.randrange(1, N)
            self.public_key = scalar_mult(self.private_key, self.G)

    def _get_z(self, user_id: str) -> bytes:
        """计算Z值，用于签名前的预处理"""
        user_id_bytes = user_id.encode('utf-8')
        entl = (len(user_id_bytes) * 8).to_bytes(2, 'big')
        
        # Z = H(ENTL || ID || a || b || Gx || Gy || Px || Py)
        data_to_hash = entl + user_id_bytes
        data_to_hash += A.to_bytes(32, 'big')
        data_to_hash += B.to_bytes(32, 'big')
        data_to_hash += Gx.to_bytes(32, 'big')
        data_to_hash += Gy.to_bytes(32, 'big')
        data_to_hash += self.public_key[0].to_bytes(32, 'big')
        data_to_hash += self.public_key[1].to_bytes(32, 'big')
        
        return get_hash(data_to_hash)

    def sign(self, message: bytes, user_id: str = "1234567812345678") -> Tuple[int, int]:
        """
        SM2 签名
        返回 (r, s)
        """
        if not self.private_key:
            raise ValueError("Private key is not available for signing.")
            
        z = self._get_z(user_id)
        m_prime = z + message
        e = int.from_bytes(get_hash(m_prime), 'big')
        
        while True:
            k = random.randrange(1, N)
            x1, y1 = scalar_mult(k, self.G)
            
            r = (e + x1) % N
            if r == 0 or r + k == N:
                continue
            
            # s = ( (1+d)^-1 * (k - r*d) ) mod N
            d = self.private_key
            s1 = inv(1 + d, N)
            s2 = (k - r * d) % N
            s = (s1 * s2) % N
            
            if s != 0:
                break
                
        return r, s

    def verify(self, message: bytes, signature: Tuple[int, int], user_id: str = "1234567812345678") -> bool:
        """SM2 验签"""
        r, s = signature
        if not (1 <= r < N and 1 <= s < N):
            return False

        z = self._get_z(user_id)
        m_prime = z + message
        e = int.from_bytes(get_hash(m_prime), 'big')

        # t = (r + s) mod N
        t = (r + s) % N
        if t == 0:
            return False
        
        # P = s*G + t*Pk
        p1 = scalar_mult(s, self.G)
        p2 = scalar_mult(t, self.public_key)
        x, y = point_add(p1, p2)
        
        # R = (e + x) mod N
        R = (e + x) % N
        return R == r

    def encrypt(self, plain_bytes: bytes) -> bytes:
        """SM2 加密"""
        while True:
            k = random.randrange(1, N)
            c1_point = scalar_mult(k, self.G)
            x1, y1 = c1_point
            
            # C1 = x1 || y1 (64 bytes)
            c1 = x1.to_bytes(32, 'big') + y1.to_bytes(32, 'big')
            
            # (x2, y2) = k * Pk
            x2, y2 = scalar_mult(k, self.public_key)
            
            # t = KDF(x2 || y2, klen)
            # 基础KDF实现，仅用一次哈希
            kdf_input = x2.to_bytes(32, 'big') + y2.to_bytes(32, 'big')
            t = get_hash(kdf_input)

            # C2 = M xor t
            # 确保t足够长
            c2 = bytes(p_byte ^ t_byte for p_byte, t_byte in zip(plain_bytes, t))
            
            # C3 = H(x2 || M || y2)
            c3_input = x2.to_bytes(32, 'big') + plain_bytes + y2.to_bytes(32, 'big')
            c3 = get_hash(c3_input)
            
            # 标准输出是 C1 || C3 || C2
            return c1 + c3 + c2


    def decrypt(self, cipher_bytes: bytes) -> bytes:
        """SM2 解密"""
        if not self.private_key:
            raise ValueError("Private key is not available for decryption.")
        
        c1_len = 64
        c3_len = 32
        
        c1 = cipher_bytes[:c1_len]
        c3 = cipher_bytes[c1_len : c1_len + c3_len]
        c2 = cipher_bytes[c1_len + c3_len:]
        
        x1 = int.from_bytes(c1[:32], 'big')
        y1 = int.from_bytes(c1[32:], 'big')
        c1_point = (x1, y1)
        
        if not is_on_curve(c1_point):
            raise ValueError("C1 is not a valid point on the curve.")
        
        # (x2, y2) = d * C1
        x2, y2 = scalar_mult(self.private_key, c1_point)
        
        # t = KDF(x2 || y2, klen)
        kdf_input = x2.to_bytes(32, 'big') + y2.to_bytes(32, 'big')
        t = get_hash(kdf_input)
        
        # M' = C2 xor t
        m_prime = bytes(c_byte ^ t_byte for c_byte, t_byte in zip(c2, t))
        
        # 校验 C3' = H(x2 || M' || y2)
        c3_prime_input = x2.to_bytes(32, 'big') + m_prime + y2.to_bytes(32, 'big')
        c3_prime = get_hash(c3_prime_input)
        
        if c3_prime != c3:
            raise ValueError("Decryption failed. Hash check invalid.")
            
        return m_prime


if __name__ == '__main__':
    # 生成密钥对
    sm2_key = SM2Key()
    print(f"私钥: {hex(sm2_key.private_key)}")
    print(f"公钥Px: {hex(sm2_key.public_key[0])}")
    print(f"公钥Py: {hex(sm2_key.public_key[1])}")

    # 签名
    print("===签名验签===")
    message = b"plaintext"

    print(f"待签名消息: {message.decode()}")
    start= time.time()
    signature = sm2_key.sign(message)
    end = time.time()
    print(f"签名耗时: {end - start:.6f} 秒")
    print(f"签名: {hex(signature[0])}, {hex(signature[1])}")
    verifier = SM2Key(public_key=sm2_key.public_key)
    is_verified = verifier.verify(message, signature)
    print(f"验签结果: {'成功' if is_verified else '失败'}")

    # 加密
    print("===加解密===")
    print(f"待加密明文: {message.decode()}")
    
    # 使用公钥加密
    encryptor = SM2Key(public_key=sm2_key.public_key)
    start = time.time()
    cipher_text = encryptor.encrypt(message)
    end = time.time()
    print(f"加密耗时: {end - start:.6f} 秒")
    print(f"密文: {cipher_text.hex()}")

    # 使用私钥解密
    decrypted_text = sm2_key.decrypt(cipher_text)
    print(f"解密后明文: {decrypted_text.decode()}")