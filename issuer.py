from keys import privkey
from utils.crypto import sign_blinded, encrypt_metadata

def issue_blinded_token(blinded: int, metadata: dict):
    """
    Sign the blinded integer and attach encrypted metadata.
    Returns (s_blinded, enc_meta).
    """
    s_blinded = sign_blinded(blinded, privkey)
    enc_meta   = encrypt_metadata(metadata)
    return s_blinded, enc_meta

if __name__ == '__main__':
    # Demo—won’t be used for protocol flow
    print("Run `user.py` then `verifier.py` for full flow.")
