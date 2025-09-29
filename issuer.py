import os
from Crypto.PublicKey import RSA
from utils.crypto import (
    get_rsa_key,
    raw_blind_sign,
    encrypt_metadata,
    hash_message,
)

KEYS_DIR = "keys"
ISSUER_KEY_FILE = os.path.join(KEYS_DIR, "issuer_key.pem")

# Simple in-memory key store for the auditor
# In a real system, this would be a secure database.
AUDITOR_KEY_STORE = {}

class Issuer:
    def __init__(self):
        """Initializes the issuer by loading or generating an RSA keypair."""
        if not os.path.exists(KEYS_DIR):
            os.makedirs(KEYS_DIR)
        self.key = get_rsa_key(ISSUER_KEY_FILE)
        self.public_key = self.key.publickey()

    # Function now requires the original_message
    def issue_blinded_token(self, blinded_message, original_message, metadata):
        """
        Signs a blinded message and attaches encrypted metadata containing a hash
        of the original message to prevent forgery.
        """
        # 1. Sign the blinded message
        blinded_sig = raw_blind_sign(self.key, blinded_message)

        # Add hash of the original message to metadata
        # This creates a cryptographic link between the token and the metadata.
        metadata_to_encrypt = metadata.copy()
        metadata_to_encrypt['token_hash'] = hash_message(original_message)
        
        # 2. Encrypt the enhanced metadata
        enc_meta_full = encrypt_metadata(metadata_to_encrypt)

        # 3. Sanitize the encrypted metadata for the user (removes the key)
        enc_meta_for_user = {
            "ciphertext": enc_meta_full["ciphertext"],
            "nonce": enc_meta_full["nonce"],
            "tag": enc_meta_full["tag"],
        }
        
        # Store the key for the auditor
        # We use the ciphertext as a unique ID to store the key.
        key_id = enc_meta_for_user["ciphertext"].hex()
        AUDITOR_KEY_STORE[key_id] = enc_meta_full['key']

        # 4. Return the signature and the sanitized encrypted metadata
        return {
            "blinded_sig": blinded_sig,
            "enc_meta": enc_meta_for_user,
        }

if __name__ == "__main__":
    # Example usage (for testing)
    issuer = Issuer()
    print("Issuer initialized.")
    print(f"Issuer public key (n): {issuer.public_key.n}")
    print(f"Issuer public key (e): {issuer.public_key.e}")