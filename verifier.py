from utils.crypto import decrypt_metadata
from user import obtain_token
from issuer import pubkey


def verify_token_raw(message: bytes, signature: int, enc_meta: dict, audit=False) -> bool:
    """
    Verify raw RSA signature by checking s^e mod n == m.
    Optionally decrypt metadata if audit=True.
    Returns True if valid, False otherwise.
    """
    # Convert message to integer
    m = int.from_bytes(message, 'big')
    # Verify signature
    s_pow = pow(signature, pubkey.e, pubkey.n)
    if s_pow != m:
        print('Invalid signature')
        return False
    print('Signature valid')

    if audit:
        metadata = decrypt_metadata(enc_meta)
        print('Decrypted Metadata:', metadata)
    return True


if __name__ == '__main__':
    msg, sig, meta = obtain_token(b'user-token-123', {'type_bit': 1, 'timestamp': '2025-08-07'})
    verify_token_raw(msg, sig, meta, audit=True)