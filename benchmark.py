# benchmark.py
import timeit
from keys import pubkey, privkey
from utils.crypto import blind_message, sign_blinded, unblind_signature, encrypt_metadata, decrypt_metadata

# Prepare a sample message and metadata
MESSAGE  = b'user-token-123'
METADATA = {'type_bit': 1, 'timestamp': '2025-08-07'}

# 1. Blinding
def bench_blind():
    blind_message(MESSAGE, pubkey)

# 2. Blind‐signature generation (on a single blinded value)
blinded, _ = blind_message(MESSAGE, pubkey)
def bench_sign():
    sign_blinded(blinded, privkey)

# 3. Unblinding (on a fresh signed blind)
s_blinded = sign_blinded(blinded, privkey)
def bench_unblind():
    _, r = blind_message(MESSAGE, pubkey)
    unblind_signature(s_blinded, r, pubkey)

# 4. Raw verification
# First, get a valid signature
blinded, r = blind_message(MESSAGE, pubkey)
s_blinded = sign_blinded(blinded, privkey)
sig      = unblind_signature(s_blinded, r, pubkey)
def bench_verify():
    m_int   = int.from_bytes(MESSAGE, 'big')
    pow(sig, pubkey.e, pubkey.n) == m_int

# 5. Metadata encryption
def bench_encrypt():
    encrypt_metadata(METADATA)

# 6. Metadata decryption
enc = encrypt_metadata(METADATA)
def bench_decrypt():
    decrypt_metadata(enc)

# Run benchmarks
if __name__ == "__main__":
    iterations = 100
    for name, fn in [
        ("blinding", bench_blind),
        ("signing", bench_sign),
        ("unblinding", bench_unblind),
        ("verification", bench_verify),
        ("enc. metadata", bench_encrypt),
        ("dec. metadata", bench_decrypt),
    ]:
        t = timeit.timeit(fn, number=iterations)
        print(f"{name:15s}: {t/iterations*1e3:.3f} ms/op")
