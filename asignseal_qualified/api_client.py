from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional, List
from urllib.parse import quote

import requests

from .crypto import b64, sha256, sign_with_auth_key, get_cert_serial_decimal, load_auth_p12
from .models import SignatureResponse, BatchHashData, BatchSignatureData, ApiError, AuthCredentials


@dataclass
class SealSignatureService:
    base_url: str

    def _url(self, path: str) -> str:
        return f"{self.base_url.rstrip('/')}{path}"

    def get_seal_certificate(self, auth_serial: str, sid: Optional[str] = None) -> bytes:
        sid = sid or "dummy"
        url = self._url(f"/Certificate/{quote(auth_serial)}/{quote(sid)}")
        r = requests.get(url, timeout=15)
        if r.status_code != 200:
            raise ApiError(r.status_code, r.text)
        return r.content

    def sign_hash(self, auth_serial: str, hash_bytes: bytes, auth_signature_bytes: bytes, sid: Optional[str] = None) -> bytes:
        sid = sid or "dummy"
        url = self._url(f"/Sign/{quote(sid)}")
        payload = {
            "AuthSerial": auth_serial,
            "Hash": b64(hash_bytes),
            "HashSignature": b64(auth_signature_bytes),
            "HashSignatureMechanism": "SHA256withRSA",
        }
        r = requests.post(url, data=json.dumps(payload), headers={"Content-Type": "application/json"}, timeout=20)
        if r.status_code != 200:
            raise ApiError(r.status_code, r.text)
        obj = r.json()
        sig_b64 = obj.get("Signature")
        if not sig_b64:
            raise ApiError(r.status_code, "Missing Signature in response")
        import base64
        return base64.b64decode(sig_b64)


class ApiClient:
    def __init__(self, service: SealSignatureService, creds: AuthCredentials):
        self.service = service
        self._km = load_auth_p12(creds.p12_path, creds.password)
        self.auth_serial = get_cert_serial_decimal(self._km.certificate)

    def fetch_seal_certificate(self, sid: Optional[str] = None) -> bytes:
        return self.service.get_seal_certificate(self.auth_serial, sid)

    def sign_arbitrary_hash(self, hash_bytes: bytes, sid: Optional[str] = None) -> bytes:
        # Client must authenticate by signing the hash with the auth private key
        auth_sig = sign_with_auth_key(self._km.private_key, hash_bytes)
        return self.service.sign_hash(self.auth_serial, hash_bytes, auth_sig, sid)
