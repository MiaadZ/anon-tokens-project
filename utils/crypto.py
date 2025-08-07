import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- RSA Blind Signature Utilities ---
def blind_message(message: bytes, pubkey: RSA.RsaKey):
    e, n = pubkey.e, pubkey.n
    r = int.from_bytes(get_random_bytes(256), 'big') % n
    m = int.from_bytes(message, 'big')
    blinded = (m * pow(r, e, n)) % n
    return blinded, r

def sign_blinded(blinded: int, privkey: RSA.RsaKey):
    return pow(blinded, privkey.d, privkey.n)

def unblind_signature(s_blinded: int, r: int, pubkey: RSA.RsaKey):
    n = pubkey.n
    r_inv = pow(r, -1, n)
    return (s_blinded * r_inv) % n

# --- Metadata Encryption Utilities ---

def encrypt_metadata(metadata: dict, key: bytes = None) -> dict:
    if key is None:
        key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM)
    data = str(metadata).encode()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        'key': key,
        'nonce': cipher.nonce,
        'ciphertext': ciphertext,
        'tag': tag
    }

def decrypt_metadata(enc_obj: dict) -> dict:
    cipher = AES.new(enc_obj['key'], AES.MODE_GCM, nonce=enc_obj['nonce'])
    data = cipher.decrypt_and_verify(enc_obj['ciphertext'], enc_obj['tag'])
    return eval(data.decode())
