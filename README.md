# Crypto Suite (AES-256-GCM, RSA-3072, SHA-256)

Arrowstack Cyber Security Internship, Task 1. A Python CLI for encryption and hashing.

## Features
- AES-256-GCM file encryption (key derived from password using scrypt)
- RSA-3072 OAEP key generation, encryption, decryption (private key password-protected)
- SHA-256 file hashing (verified against `sha256sum`)
- Wrong password or tampered file is detected and rejected

## Setup
    python3 -m venv venv && source venv/bin/activate
    pip install cryptography

## Usage
    python3 crypto_suite.py hash FILE
    python3 crypto_suite.py aes-encrypt IN OUT
    python3 crypto_suite.py aes-decrypt IN OUT
    python3 crypto_suite.py rsa-keygen PREFIX
    python3 crypto_suite.py rsa-encrypt PUBKEY IN OUT
    python3 crypto_suite.py rsa-decrypt PRIVKEY IN OUT

## Testing
    python3 -m unittest -v

## Limitations
- RSA encrypts only small data (under 300 bytes); use AES for files.
- Files are read fully into memory.
- Educational project, not audited for production use.

## Test Results
- Unit tests: 3 of 3 passed (AES round-trip, AES wrong password rejected, RSA round-trip). Output: `evidence/unittest_output.txt`
- SHA-256 validation: this tool's output matches `sha256sum` exactly. Output: `evidence/hash_check.txt`
- Manual check: decrypting with a wrong password prints "FAILED: wrong password or file was tampered"
