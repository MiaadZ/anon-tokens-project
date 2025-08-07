from Crypto.PublicKey import RSA
from pathlib import Path

PRIV_PATH = Path("issuer_priv.pem")
PUB_PATH  = Path("issuer_pub.pem")

def load_or_create_keys(key_size=2048):
    if PRIV_PATH.exists() and PUB_PATH.exists():
        privkey = RSA.import_key(PRIV_PATH.read_bytes())
        pubkey  = RSA.import_key(PUB_PATH.read_bytes())
    else:
        key = RSA.generate(key_size)
        privkey = key
        pubkey  = key.publickey()
        PRIV_PATH.write_bytes(privkey.export_key())
        PUB_PATH.write_bytes(pubkey.export_key())
    return privkey, pubkey

# Load at import time
privkey, pubkey = load_or_create_keys()