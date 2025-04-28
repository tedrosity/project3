import base64
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def base64url_uint(val):
    b = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('utf-8')

def serialize_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(pem_bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)

def get_aes_key():
    key = os.getenv("NOT_MY_KEY")
    if not key:
        raise ValueError("Environment variable NOT_MY_KEY not set.")
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 32:
        key_bytes = key_bytes.ljust(32, b'\0')
    elif len(key_bytes) > 32:
        key_bytes = key_bytes[:32]
    return key_bytes

def encrypt_data(plaintext: bytes) -> bytes:
    key = get_aes_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_data(data: bytes) -> bytes:
    key = get_aes_key()
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
