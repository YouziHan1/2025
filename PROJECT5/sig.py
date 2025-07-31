import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def generate_satoshi_style_keypair() -> (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey):
    # 使用 secp256k1 曲线生成私钥
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    return private_key, public_key

def hash_message_for_signing(message: bytes) -> bytes:

    sha256_once = hashlib.sha256(message).digest()
    sha256_twice = hashlib.sha256(sha256_once).digest()
    return sha256_twice

def sign_message(private_key: ec.EllipticCurvePrivateKey, message_hash: bytes) -> bytes:

    signature = private_key.sign(
        message_hash,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    return signature

def verify_signature(public_key: ec.EllipticCurvePublicKey, signature: bytes, message_hash: bytes) -> bool:
    """
    使用公钥验证签名是否有效。
    """
    try:
        public_key.verify(
            signature,
            message_hash,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        return True
    except InvalidSignature:
        return False

if __name__ == '__main__':
    print("===模仿中本聪数字签名过程===")

    satoshi_imitation_private_key, satoshi_imitation_public_key = generate_satoshi_style_keypair()
    
    private_key_hex = hex(satoshi_imitation_private_key.private_numbers().private_value)
    public_key_hex = satoshi_imitation_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    ).hex()
    
    print(f"私钥: {private_key_hex}")
    print(f"公钥: {public_key_hex}")

    message_string = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    message_bytes = message_string.encode('utf-8')
    
    message_hash = hash_message_for_signing(message_bytes)
    
    print(f"原始消息: '{message_string}'")
    print(f"消息哈希: {message_hash.hex()}")

    # 私钥签名
    print("===签名===")
    signature = sign_message(satoshi_imitation_private_key, message_hash)
    print(f"数字签名:{signature.hex()}")
    
    # 公钥验证
    is_valid = verify_signature(satoshi_imitation_public_key, signature, message_hash)
    
    if is_valid:
        print("验证成功")
    else:
        print("验证失败")
        
    #篡改签名
    print("===篡改签名验证===")
    tampered_message_bytes = b"This message has been tampered with!"
    tampered_message_hash = hash_message_for_signing(tampered_message_bytes)
    
    print(f"篡改后的消息哈希: {tampered_message_hash.hex()}")
    is_tampered_valid = verify_signature(satoshi_imitation_public_key, signature, tampered_message_hash)

    if not is_tampered_valid:
        print("验证失败！签名无法匹配被篡改的消息")
    else:
        print("验证成功")