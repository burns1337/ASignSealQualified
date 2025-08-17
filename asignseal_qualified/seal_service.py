# asign_seal_qualified/seal_service.py
from .api_client import ApiClient
import base64


class SealSignatureService:
    def __init__(self, base_url: str, auth_credentials):
        self.base_url = base_url
        self.client = ApiClient(base_url, auth_credentials)

    def create_signature(self, pdf_hash: bytes, signature_params: dict) -> dict:
        """Erstellt eine qualifizierte elektronische Signatur"""
        payload = {
            'hashValue': base64.b64encode(pdf_hash).decode(),
            'hashAlgorithm': 'SHA256',
            'signatureField': signature_params.get('field', 'Signature1'),
            'reason': signature_params.get('reason', 'Qualified electronic seal'),
            'location': signature_params.get('location', ''),
            'sessionId': signature_params.get('sid')
        }

        return self.client.post('/api/v1/seal/sign', payload)

    def get_seal_certificate(self) -> dict:
        """Holt das Seal-Zertifikat"""
        return self.client.get('/api/v1/seal/certificate')