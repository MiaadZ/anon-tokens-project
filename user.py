from keys import pubkey
from utils.crypto import blind_message, unblind_signature
from issuer      import issue_blinded_token

def obtain_token(message: bytes, metadata: dict):
    """
    1) Blind message (once)
    2) Send blinded to issuer.issue_blinded_token()
    3) Unblind the returned signature
    """
    # Step A: Blind
    blinded, r = blind_message(message, pubkey)

    # Step B: Issuer signs that same blinded
    s_blinded, enc_meta = issue_blinded_token(blinded, metadata)

    # Step C: Unblind to get signature on original message
    signature = unblind_signature(s_blinded, r, pubkey)
    return message, signature, enc_meta

if __name__ == '__main__':
    msg, sig, meta = obtain_token(
        b'user-token-123',
        {'type_bit': 1, 'timestamp': '2025-08-07'}
    )
    print('Token:', {'message': msg, 'signature': sig, 'metadata': meta})
