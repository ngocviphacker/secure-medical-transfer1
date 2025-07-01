import os, base64, json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from hashlib import sha256, sha512
from datetime import datetime


### --- KHÓA RSA --- ###
def load_key(path, is_private=True):
    with open(path, "rb") as key_file:
        key_data = key_file.read()
    return serialization.load_pem_private_key(key_data, password=None) if is_private else \
           serialization.load_pem_public_key(key_data)


### --- HASH --- ###
def hash_password(password: str) -> str:
    return sha256(password.encode()).hexdigest()

def hash_integrity(iv: bytes, cipher: bytes) -> str:
    return sha512(iv + cipher).hexdigest()


### --- KÝ SỐ --- ###
def sign_metadata(private_key, metadata: dict) -> bytes:
    data = f"{metadata['filename']}|{metadata['timestamp']}|{metadata['patient_id']}".encode()
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA512()
    )
    return signature

def verify_signature(public_key, metadata: dict, signature: bytes) -> bool:
    data = f"{metadata['filename']}|{metadata['timestamp']}|{metadata['patient_id']}".encode()
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA512()
        )
        return True
    except InvalidSignature:
        return False


### --- MÃ HÓA / GIẢI MÃ AES-CBC --- ###
def aes_encrypt(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded = data + b' ' * (16 - len(data) % 16)  # Padding đơn giản
    ct = encryptor.update(padded) + encryptor.finalize()
    return iv, ct

def aes_decrypt(iv: bytes, cipher_text: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plain_padded = decryptor.update(cipher_text) + decryptor.finalize()
    return plain_padded.rstrip(b' ')


### --- TRAO KHÓA RSA-OAEP --- ###
def encrypt_session_key(public_key, session_key: bytes) -> bytes:
    return public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )

def decrypt_session_key(private_key, encrypted_key: bytes) -> bytes:
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )


### --- TẠO METADATA --- ###
def create_metadata(filename, patient_id):
    return {
        "filename": filename,
        "timestamp": datetime.utcnow().isoformat(),
        "patient_id": patient_id
    }

