import random
from hashlib import sha256
from typing import List, Tuple, Dict, Any
from phe import paillier

def H(val: str, p: int) -> int:

    h = sha256(val.encode()).digest()
    return int.from_bytes(h, 'big') % p

class Party1:

    def __init__(self, identifiers: List[str], p: int):
        self.V = set(identifiers)
        self.p = p
        self.k1 = random.randint(2, self.p - 2)
        self.paillier_pk = None

    def set_paillier_public_key(self, public_key: paillier.PaillierPublicKey):
        self.paillier_pk = public_key

    def round1_output(self) -> List[int]:
        blinded_data = [pow(H(v, self.p), self.k1, self.p) for v in self.V]
        random.shuffle(blinded_data)
        return blinded_data

    def round3_output(self, p2_response: Dict[str, Any]) -> paillier.EncryptedNumber:
        Z = p2_response['Z']
        ciphertext_set = p2_response['ciphertext_set']

        #计算H(w_j)^{k1*k2} 用于匹配
        H_wj_k1k2 = {pow(h, self.k1, self.p): ct for h, ct in ciphertext_set}

        #找出Z中与H_wj_k1k2匹配的值
        intersection_ciphertexts = [
            ct for h_k1k2, ct in H_wj_k1k2.items() if h_k1k2 in Z
        ]
        
        if not intersection_ciphertexts:
            return self.paillier_pk.encrypt(0)


        # 同态加法
        encrypted_sum = intersection_ciphertexts[0]
        for i in range(1, len(intersection_ciphertexts)):
            encrypted_sum += intersection_ciphertexts[i]
        return encrypted_sum


class Party2:

    def __init__(self, data: List[Tuple[str, int]], p: int):
        self.W = dict(data)
        self.p = p
        self.k2 = random.randint(2, self.p - 2)
        self.paillier_pk, self.paillier_sk = paillier.generate_paillier_keypair(n_length=1024)

    def round2_output(self, p1_data: List[int]) -> Dict[str, Any]:
        #Z = { (H(v)^k1)^k2 }
        Z = {pow(h_v_k1, self.k2, self.p) for h_v_k1 in p1_data}

        # H(w)^k2 和 AEnc(t)
        ciphertext_set = []
        for w, t in self.W.items():
            h_w_k2 = pow(H(w, self.p), self.k2, self.p)
            encrypted_t = self.paillier_pk.encrypt(t)
            ciphertext_set.append((h_w_k2, encrypted_t))
        
        random.shuffle(ciphertext_set)
        
        return {
            'Z': Z,
            'ciphertext_set': ciphertext_set
        }

    def final_decryption(self, encrypted_sum: paillier.EncryptedNumber) -> int:
        decrypted_sum = self.paillier_sk.decrypt(encrypted_sum)
        return decrypted_sum



def run_protocol():
    # 公共参数p
    p = 115792089237316195423570985008687907853269984665640564039457584007913129639747

    # P1：待检测账号
    p1_data = ["2003", "202200460117", "123456", "sdu"]

    # P2：泄露库，账号 + 风险值
    p2_data = [("cst", 3), ("123456", 85), ("1126", 22), ("sdu", 150)]
    

    print(f"P1 的输入: {p1_data}")
    print(f"P2 的输入: {p2_data}")

    p1 = Party1(p1_data, p)
    p2 = Party2(p2_data, p)
    
    # P2 将其 Paillier 公钥发送给 P1
    p1.set_paillier_public_key(p2.paillier_pk)

    p1_output_r1 = p1.round1_output()
    p2_output_r2 = p2.round2_output(p1_output_r1)
    p1_output_r3 = p1.round3_output(p2_output_r2)
    final_sum = p2.final_decryption(p1_output_r3)


    print(f"协议完成，计算出交集风险总和为: {final_sum}\n")

    #本地验证
    print("本地验证：")
    intersection = set(p1_data).intersection(set(dict(p2_data).keys()))
    expected_sum = sum(dict(p2_data)[item] for item in intersection)
    print(f"交集为:{intersection}")
    print(f"风险值总和为:{expected_sum}\n")
    
    assert final_sum == expected_sum
    print("结果验证成功")

if __name__ == "__main__":
    run_protocol()
