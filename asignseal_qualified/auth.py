# asign_seal_qualified/auth.py
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
import base64

class AuthCredentials:
    def __init__(self, p12_path=None, password=None):
        self.p12_path = p12_path or os.getenv('ATRUST_P12')
        self.password = password or os.getenv('ATRUST_P12_PASSWORD')

        if not self.p12_path or not self.password:
            raise ValueError("P12 path and password required")

        self._load_credentials()

    def _load_credentials(self):
        with open(self.p12_path, 'rb') as f:
            p12_data = f.read()

        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data,
            self.password.encode()
        )

        self.private_key = private_key
        self.certificate = certificate

    def sign_hash(self, hash_data):
        """Signiert einen Hash mit dem privaten Schlüssel"""
        signature = self.private_key.sign(
            hash_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def get_certificate_der(self):
        """Gibt das Zertifikat im DER-Format zurück"""
        return base64.b64encode(self.certificate.public_bytes(serialization.Encoding.DER)).decode()
