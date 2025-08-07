from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from issuer import pubkey
from utils.crypto import decrypt_metadata


def verify_token(message: bytes, signature: int, enc_meta: dict, audit=False) -> bool:
    """
    Verify token signature; optionally decrypt metadata if audit=True.
    Returns True if valid, False otherwise.
    """
    h = SHA256.new(message)
    try:
        sig_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, 'big')
        pkcs1_15.new(pubkey).verify(h, sig_bytes)
        print('Signature valid')
    except (ValueError, TypeError):
        print('Invalid signature')
        return False

    if audit:
        metadata = decrypt_metadata(enc_meta)
        print('Decrypted Metadata:', metadata)
    return True


if __name__ == '__main__':
    msg, sig, meta = obtain_token(b'user-token-123', {'type_bit': 1, 'timestamp': '2025-08-07'})
    verify_token(msg, sig, meta, audit=True)