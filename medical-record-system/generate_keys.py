from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

os.makedirs('keys', exist_ok=True)

def save_key(path, key, is_private):
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(path, 'wb') as f:
        f.write(pem)

# Tạo khóa cho người gửi
sender_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
save_key('keys/sender_private.pem', sender_private, True)
save_key('keys/sender_public.pem', sender_private.public_key(), False)

# Tạo khóa cho người nhận
receiver_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
save_key('keys/receiver_private.pem', receiver_private, True)
save_key('keys/receiver_public.pem', receiver_private.public_key(), False)
