# asign_seal_qualified/api_client.py
import requests
import hashlib
import base64
from typing import Dict, Any


class ApiClient:
    def __init__(self, base_url: str, auth_credentials):
        self.base_url = base_url.rstrip('/')
        self.auth_creds = auth_credentials
        self.session = requests.Session()

    def _authenticate_request(self, method: str, path: str, body: bytes = b'') -> Dict[str, str]:
        """Erstellt Authentifizierungs-Header für die Anfrage"""
        # Hash der Anfrage erstellen
        request_data = f"{method.upper()}{path}".encode() + body
        request_hash = hashlib.sha256(request_data).digest()

        # Hash signieren
        signature = self.auth_creds.sign_hash(request_hash)

        return {
            'X-ATrust-AuthCert': self.auth_creds.get_certificate_der(),
            'X-ATrust-Signature': signature,
            'Content-Type': 'application/json'
        }

    def post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """POST-Anfrage mit Authentifizierung"""
        url = f"{self.base_url}{endpoint}"
        body = requests.models.RequestEncodingMixin._encode_params(json_data)
        headers = self._authenticate_request('POST', endpoint, body)

        response = self.session.post(url, json=json_data, headers=headers)
        response.raise_for_status()
        return response.json()

    def get(self, endpoint: str) -> Dict[str, Any]:
        """GET-Anfrage mit Authentifizierung"""
        url = f"{self.base_url}{endpoint}"
        headers = self._authenticate_request('GET', endpoint)

        response = self.session.get(url, headers=headers)
        response.raise_for_status()
        return response.json()