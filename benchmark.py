import timeit
from Crypto.Random import get_random_bytes

# Import the components from our final code structure
from issuer import Issuer
from user import User
from verifier import Verifier
from utils.crypto import (
    encrypt_metadata,
    decrypt_metadata,
    blind_message,
    raw_blind_sign,
    unblind_signature,
)

# --- SETUP ---
# Create instances of all participants
issuer = Issuer()
user = User(issuer.public_key)
verifier = Verifier(issuer.public_key)

# Prepare the data needed for one full token issuance cycle
message = get_random_bytes(32)
metadata = {'user_type': 'premium', 'risk_score': 15}

# Perform one full run to get all the necessary intermediate values
blinded_m, r = blind_message(message, user.issuer_pubkey)
blinded_sig = raw_blind_sign(issuer.key, blinded_m)
signature = unblind_signature(blinded_sig, r, user.issuer_pubkey)
enc_meta_full = encrypt_metadata(metadata)
# The key is needed for the decryption benchmark
secret_key = enc_meta_full['key'] 
enc_meta_for_user = {
    "ciphertext": enc_meta_full["ciphertext"],
    "nonce": enc_meta_full["nonce"],
    "tag": enc_meta_full["tag"],
}

# --- BENCHMARKING ---
# Number of repetitions for each measurement
N_RUNS = 100

# Use timeit to measure the execution time of each function
# We use lambdas to call functions with the prepared arguments
blinding_time = timeit.timeit(lambda: blind_message(message, user.issuer_pubkey), number=N_RUNS)
signing_time = timeit.timeit(lambda: raw_blind_sign(issuer.key, blinded_m), number=N_RUNS)
unblinding_time = timeit.timeit(lambda: unblind_signature(blinded_sig, r, user.issuer_pubkey), number=N_RUNS)
verification_time = timeit.timeit(lambda: verifier.verify_signature(message, signature), number=N_RUNS)
encryption_time = timeit.timeit(lambda: encrypt_metadata(metadata), number=N_RUNS)
decryption_time = timeit.timeit(lambda: decrypt_metadata(secret_key, enc_meta_for_user), number=N_RUNS)

# --- RESULTS ---
print("--- Benchmark Results ---")
print(f"Average over {N_RUNS} runs (2048-bit RSA)\n")
print(f"{'Operation':<20} | {'Time per op (ms)':>20}")
print("-" * 44)
# Convert total time to average time per operation in milliseconds
print(f"{'Blinding':<20} | {blinding_time / N_RUNS * 1000:>20.3f}")
print(f"{'Signing':<20} | {signing_time / N_RUNS * 1000:>20.3f}")
print(f"{'Unblinding':<20} | {unblinding_time / N_RUNS * 1000:>20.3f}")
print(f"{'Verification':<20} | {verification_time / N_RUNS * 1000:>20.3f}")
print(f"{'Encrypt Metadata':<20} | {encryption_time / N_RUNS * 1000:>20.3f}")
print(f"{'Decrypt Metadata':<20} | {decryption_time / N_RUNS * 1000:>20.3f}")