# Anonymous Tokens with Private Metadata Bit

A prototype implementation of blind‐signature–based anonymous tokens enhanced with an encrypted metadata bit.  
This repo contains:
- `utils/crypto.py` — blind‐signature & AES-GCM metadata encryption primitives  
- `issuer.py`         — token issuance (blind-sign + metadata encryption)  
- `user.py`           — client flow (blind, unblind + redeem)  
- `verifier.py`       — verification & optional metadata audit  
- `benchmark.py`      — micro-benchmarks for each crypto operation  

## 📂 Directory Structure
anon-tokens-project/  
├── README.md  
├── issuer.py  
├── user.py  
├── verifier.py  
├── benchmark.py  
├── keys.py  
└── utils/  
└── crypto.py  


## 🚀 Quickstart

1. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate      # Windows: venv\Scripts\activate
   pip install --upgrade pip
   pip install pycryptodome

2. Run the full flow:
    ```python
    python user.py       # issues & redeems a token
    python verifier.py   # verifies signature & decrypts metadata

3. Benchmark performance:
    ```python
    python benchmark.py

## 📖 Code Overview
utils/crypto.py

    blind_message(msg, pubkey) → (blinded, r)
    sign_blinded(blinded, privkey) → s_blinded
    unblind_signature(s_blinded, r, pubkey) → signature
    encrypt_metadata(dict) → enc_obj
    decrypt_metadata(enc_obj) → metadata

issuer.py

    Imports persistent RSA keys from keys.py
    Exposes issue_blinded_token(blinded, metadata)
    Simulates an issuer signing the blinded value and encrypting metadata

user.py

    Blinds a message, sends the blinded value to issuer, unblinds the signed result
    Returns (message, signature, enc_meta)

verifier.py

    Checks raw RSA signature: sig^e mod n == int(message)
    Optionally decrypts metadata for audit

benchmark.py

    Measures average runtime (ms/op) for:
        blinding, signing, unblinding, verification, metadata encryption & decryption

## 🛠 Tools & Libraries Used
| Tool / Library                                      | Purpose                                          |
| --------------------------------------------------- | ------------------------------------------------ |
| Python 3.8+                                         | Implementation language                          |
| [PyCryptodome](https://pycryptodome.readthedocs.io) | RSA, AES-GCM, randomness primitives              |
| `timeit` (stdlib)                                   | Micro-benchmark harness                          |
| Generative AI (ChatGPT)                             | Rapid scaffolding of code, LaTeX & documentation |

## 📄 License & Citation
Feel free to fork and build upon this prototype. If you reference this work, please cite as “Anonymous Tokens with Private Metadata Bit, RPTU project.”