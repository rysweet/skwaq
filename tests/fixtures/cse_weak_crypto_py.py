"""CWE-327/CWE-328: Use of Weak Cryptographic Algorithm in Python
Uses MD5, SHA1, DES, and weak random for security purposes."""

import hashlib
import random
import string
import sys


def hash_password(password):
    """Weak: uses MD5 for password hashing."""
    return hashlib.md5(password.encode()).hexdigest()


def generate_token(length=32):
    """Weak: uses random (not secrets) for security token."""
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def sign_message(message, key):
    """Weak: uses SHA1 for HMAC-like signature."""
    return hashlib.sha1((key + message).encode()).hexdigest()


def verify_integrity(data, expected_hash):
    """Weak: uses MD5 for integrity checking."""
    actual = hashlib.md5(data.encode()).hexdigest()
    return actual == expected_hash


def encrypt_xor(plaintext, key):
    """Weak: XOR 'encryption'."""
    key_bytes = key.encode()
    result = bytearray()
    for i, ch in enumerate(plaintext.encode()):
        result.append(ch ^ key_bytes[i % len(key_bytes)])
    return result.hex()


def main():
    if len(sys.argv) < 2:
        return
    pw = sys.argv[1]
    print(f"MD5 hash: {hash_password(pw)}")
    print(f"Token: {generate_token()}")
    print(f"Signature: {sign_message(pw, 'secret')}")


if __name__ == "__main__":
    main()
