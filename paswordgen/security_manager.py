from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64


class SecurityManager:

    def __init__(self, master_password: str):
        self.salt = b'a_fixed_salt_for_testing'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.fernet = Fernet(key)

    def encrypt_password(self, password: str) -> bytes:
        return self.fernet.encrypt(password.encode())

    def decrypt_password(self, encrypted_data: bytes) -> str:
        return self.fernet.decrypt(encrypted_data).decode()
