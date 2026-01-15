from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import hashlib
from typing import Optional

class CryptoEngine:
    def __init__(self, password: str, salt: Optional[bytes] = None):
        """
        Initializes the cryptographic engine using Key Stretching and Salting.
        CV CLAIM: 'Implemented per-encryption random salting with PBKDF2 Key Stretching'
        """
        # Generate a new 16-byte random SALT if one isn't provided.
        # This ensures identical files produce different ciphertexts.
        self.salt: bytes = salt if salt else get_random_bytes(16)
            
        # Derive a 32-byte AES key using PBKDF2 (100k iterations).
        self.key: bytes = PBKDF2(password, self.salt, dkLen=32, count=100000)

    def encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypts data using AES-GCM (Galois/Counter Mode).
        Returns: Salt + Nonce + Tag + Ciphertext
        """
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        return self.salt + cipher.nonce + tag + ciphertext

    @staticmethod
    def decrypt_payload(password: str, encrypted_payload: bytes) -> bytes:
        """
        Extracts salt, re-derives key, and decrypts.
        """
        # Extract metadata
        salt_from_payload: bytes = encrypted_payload[:16]
        nonce: bytes = encrypted_payload[16:32]
        tag: bytes = encrypted_payload[32:48]
        ciphertext: bytes = encrypted_payload[48:]
        
        # Re-derive the key using the extracted salt
        engine = CryptoEngine(password, salt=salt_from_payload)
        
        cipher = AES.new(engine.key, AES.MODE_GCM, nonce=nonce)
        
        # Verify Tag & Decrypt (Fails if tampered)
        return cipher.decrypt_and_verify(ciphertext, tag)