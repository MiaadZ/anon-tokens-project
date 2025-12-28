from Crypto.Random import get_random_bytes
from issuer import Issuer, AUDITOR_KEY_STORE
from user import User
from utils.crypto import hash_message, decrypt_metadata

class Verifier:
    def __init__(self, issuer_pubkey):
        """Initializes the verifier with the issuer's public key."""
        self.issuer_pubkey = issuer_pubkey

    def verify_signature(self, message, signature):
        """Verifies the RSA signature on a message."""
        n = self.issuer_pubkey.n
        e = self.issuer_pubkey.e
        
        m_int = int.from_bytes(message, 'big')
        sig_check = pow(signature, e, n)
        
        return m_int == sig_check

    # The complete audit logic
    def verify_and_audit_metadata(self, message, signature, enc_meta):
        """
        Verifies a token's signature AND audits its metadata for validity and integrity.
        This function simulates the role of a trusted auditor.
        """
        # Step 1: Verify the token's signature first
        if not self.verify_signature(message, signature):
            print("Audit failed: Invalid signature.")
            return False
        
        print("Signature is valid.")

        try:
            # Step 2: Retrieve the secret key for this metadata
            # We use the ciphertext's hex representation as the ID to find the key.
            key_id = enc_meta["ciphertext"].hex()
            secret_key = AUDITOR_KEY_STORE.get(key_id)
            if secret_key is None:
                print("Audit failed: No decryption key found for this metadata.")
                return False

            # Step 3: Decrypt the metadata using the secret key
            decrypted_meta = decrypt_metadata(secret_key, enc_meta)
            print(f"Decrypted metadata: {decrypted_meta}")

            # Step 4: Verify the integrity link
            # Check if the 'token_hash' inside the metadata matches the actual message.
            if 'token_hash' not in decrypted_meta:
                print("Audit failed: 'token_hash' not found in metadata.")
                return False
                
            hash_from_meta = decrypted_meta['token_hash']
            expected_hash = hash_message(message)

            if hash_from_meta != expected_hash:
                print(f"Audit failed: Hash mismatch! (Expected: {expected_hash}, Got: {hash_from_meta})")
                return False
            
            print("Metadata hash link is valid.")
            return True

        except Exception as e:
            print(f"Audit failed: An error occurred during decryption or verification. {e}")
            return False

# End-to-end test in a main block
if __name__ == "__main__":
    print("--- Setting up simulation ---")
    issuer = Issuer()
    user = User(issuer.public_key)
    verifier = Verifier(issuer.public_key)

    print("\n--- User obtains a token ---")
    # The user has a message (e.g., a random nonce for unlinkability)
    token_message = get_random_bytes(32)
    # The issuer wants to attach some private metadata
    private_metadata = {'user_type': 'premium', 'risk_score': 15}
    
    print(f"Original message: {token_message.hex()}")
    print(f"Private metadata to attach: {private_metadata}")
    
    token = user.obtain_token(issuer, token_message, private_metadata)
    print("Token successfully obtained by user.")

    print("\n--- Verifier audits the token and its metadata ---")
    is_valid = verifier.verify_and_audit_metadata(
        token["message"],
        token["signature"],
        token["enc_meta"]
    )

    print("\n--- FINAL AUDIT RESULT ---")
    if is_valid:
        print("SUCCESS: Token signature is valid AND metadata is authentic and linked correctly.")
    else:
        print("FAILURE: Token or metadata is invalid.")
