from utils.crypto import blind_message, unblind_signature

class User:
    def __init__(self, issuer_pubkey):
        """Initializes the user with the issuer's public key."""
        self.issuer_pubkey = issuer_pubkey
        self.blinding_factor = None
        self.original_message = None

    def obtain_token(self, issuer, message, metadata):
        """
        Blinds a message, sends it to the issuer, and receives a token
        with encrypted metadata.
        """
        self.original_message = message
        
        # 1. Blind the message
        blinded_m, self.blinding_factor = blind_message(message, self.issuer_pubkey)

        # 2. Pass the necessary data to the issuer object's method
        # The issuer object is passed in as an argument, so no import is needed.
        response = issuer.issue_blinded_token(blinded_m, message, metadata)

        blinded_sig = response["blinded_sig"]
        enc_meta = response["enc_meta"]
        
        # 3. Unblind the signature
        signature = unblind_signature(blinded_sig, self.blinding_factor, self.issuer_pubkey)

        # 4. The final token is the (message, signature) pair, plus the metadata
        return {
            "message": self.original_message,
            "signature": signature,
            "enc_meta": enc_meta,
        }