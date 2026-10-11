#!/usr/bin/env python3
"""Crypto Suite: AES-256-GCM, RSA-OAEP, SHA-256"""
import argparse, getpass, hashlib, os, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None)

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)

def derive_key(password, salt):
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())

def aes_encrypt(inp, out):
    pw = getpass.getpass("Password: ")
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(derive_key(pw, salt)).encrypt(nonce, read_file(inp), None)
    write_file(out, salt + nonce + ct)
    print(f"Encrypted -> {out}")

def aes_decrypt(inp, out):
    pw = getpass.getpass("Password: ")
    blob = read_file(inp)
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    try:
        pt = AESGCM(derive_key(pw, salt)).decrypt(nonce, ct, None)
    except Exception:
        sys.exit("FAILED: wrong password or file was tampered")
    write_file(out, pt)
    print(f"Decrypted -> {out}")

def rsa_keygen(prefix):
    pw = getpass.getpass("Private key password: ")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    priv_path, pub_path = f"{prefix}_private.pem", f"{prefix}_public.pem"
    write_file(priv_path, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(pw.encode())))
    os.chmod(priv_path, 0o600)  # only the owner can read the private key
    write_file(pub_path, key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Keys saved: {priv_path}, {pub_path}")

def rsa_encrypt(pub, inp, out):
    key = serialization.load_pem_public_key(read_file(pub))
    data = read_file(inp)
    if len(data) > 300:
        sys.exit("RSA can only encrypt small data (<300 bytes). Use AES for files.")
    write_file(out, key.encrypt(data, OAEP))
    print(f"Encrypted -> {out}")

def rsa_decrypt(priv, inp, out):
    pw = getpass.getpass("Private key password: ")
    key = serialization.load_pem_private_key(read_file(priv), pw.encode())
    try:
        pt = key.decrypt(read_file(inp), OAEP)
    except Exception:
        sys.exit("FAILED: wrong key or corrupted data")
    write_file(out, pt)
    print(f"Decrypted -> {out}")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    print(f"{h.hexdigest()}  {path}")

def main():
    p = argparse.ArgumentParser(description="AES-256-GCM / RSA-OAEP / SHA-256 tool")
    s = p.add_subparsers(dest="cmd", required=True)
    for name in ("aes-encrypt", "aes-decrypt"):
        x = s.add_parser(name); x.add_argument("infile"); x.add_argument("outfile")
    x = s.add_parser("rsa-keygen"); x.add_argument("prefix")
    x = s.add_parser("rsa-encrypt")
    x.add_argument("pubkey"); x.add_argument("infile"); x.add_argument("outfile")
    x = s.add_parser("rsa-decrypt")
    x.add_argument("privkey"); x.add_argument("infile"); x.add_argument("outfile")
    x = s.add_parser("hash"); x.add_argument("infile")
    a = p.parse_args()
    {"aes-encrypt": lambda: aes_encrypt(a.infile, a.outfile),
     "aes-decrypt": lambda: aes_decrypt(a.infile, a.outfile),
     "rsa-keygen": lambda: rsa_keygen(a.prefix),
     "rsa-encrypt": lambda: rsa_encrypt(a.pubkey, a.infile, a.outfile),
     "rsa-decrypt": lambda: rsa_decrypt(a.privkey, a.infile, a.outfile),
     "hash": lambda: sha256_file(a.infile)}[a.cmd]()

if __name__ == "__main__":
    main()
