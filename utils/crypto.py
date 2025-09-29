import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Key Loading and Generation
def get_rsa_key(key_file):
    """Loads an RSA key from a file or generates a new one if it doesn't exist."""
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = RSA.import_key(f.read())
    else:
        key = RSA.generate(2048)
        with open(key_file, "wb") as f:
            f.write(key.export_key("PEM"))
    return key

# Hashing Utility
def hash_message(message: bytes) -> str:
    """Hashes a message using SHA-256 and returns the hex digest."""
    return hashlib.sha256(message).hexdigest()

# --- RSA Blind Signature Utilities ---

def blind_message(message: bytes, pubkey: RSA.RsaKey):
    """Blinds a message with a random factor 'r'."""
    e, n = pubkey.e, pubkey.n
    # Use a secure random number for the blinding factor
    r_bytes = get_random_bytes(256)
    r = int.from_bytes(r_bytes, 'big')
    # Ensure r is in the multiplicative group modulo n
    r = pow(r, 1, n)
    
    m = int.from_bytes(message, 'big')
    blinded_m = (m * pow(r, e, n)) % n
    return blinded_m, r

def raw_blind_sign(privkey: RSA.RsaKey, blinded_m: int) -> int:
    """Signs a blinded message. (Renamed from sign_blinded for clarity)."""
    return pow(blinded_m, privkey.d, privkey.n)

def unblind_signature(s_blinded: int, r: int, pubkey: RSA.RsaKey) -> int:
    """Unblinds a signature using the original random factor 'r'."""
    n = pubkey.n
    # Compute the modular multiplicative inverse of r
    r_inv = pow(r, -1, n)
    return (s_blinded * r_inv) % n

# --- Metadata Encryption Utilities ---

def encrypt_metadata(metadata: dict) -> dict:
    """Encrypts a metadata dictionary using AES-GCM with a random key."""
    key = get_random_bytes(16) # Generate a fresh key for each encryption
    cipher = AES.new(key, AES.MODE_GCM)
    # Convert dict to string, then bytes for encryption
    metadata_bytes = str(metadata).encode('utf-8')
    ciphertext, tag = cipher.encrypt_and_digest(metadata_bytes)
    return {
        'key': key,
        'nonce': cipher.nonce,
        'ciphertext': ciphertext,
        'tag': tag
    }

def decrypt_metadata(key: bytes, enc_meta: dict) -> dict:
    """
    Decrypts a metadata object using the secret key, nonce, and tag.
    Note: The key must be provided separately.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=enc_meta['nonce'])
    decrypted_bytes = cipher.decrypt_and_verify(enc_meta['ciphertext'], enc_meta['tag'])
    # Convert bytes back to string, then evaluate to get the dictionary
    return eval(decrypted_bytes.decode('utf-8'))