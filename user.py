from utils.crypto import blind_message, unblind_signature
from issuer import issue_token, pubkey


def obtain_token(message: bytes, metadata: dict):
    """
    Simulate user obtaining a blind-signed token with encrypted metadata.
    Returns (message, signature, enc_meta).
    """
    blinded, r = blind_message(message, pubkey)
    s_blinded, enc_meta = issue_token(message, metadata)
    signature = unblind_signature(s_blinded, r, pubkey)
    return message, signature, enc_meta


if __name__ == '__main__':
    msg, sig, meta = obtain_token(b'user-token-123', {'type_bit': 1, 'timestamp': '2025-08-07'})
    print('Token:', {'message': msg, 'signature': sig, 'metadata': meta})