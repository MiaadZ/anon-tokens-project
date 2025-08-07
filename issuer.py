from utils.crypto import generate_rsa_keypair, blind_message, sign_blinded, encrypt_metadata

# Generate issuer keypair
privkey, pubkey = generate_rsa_keypair()


def issue_token(raw_message: bytes, metadata: dict):
    """
    Issue a blind-signed token with encrypted metadata.
    Returns (s_blinded, enc_meta), user retains blinding factor.
    """
    blinded, r = blind_message(raw_message, pubkey)
    s_blinded = sign_blinded(blinded, privkey)
    enc_meta = encrypt_metadata(metadata)
    return s_blinded, enc_meta


if __name__ == '__main__':
    message = b'user-token-123'
    metadata = {'type_bit': 1, 'timestamp': '2025-08-07'}
    s_blinded, enc_meta = issue_token(message, metadata)
    print('Blinded Signature:', s_blinded)
    print('Encrypted Metadata:', enc_meta)