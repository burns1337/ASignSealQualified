from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List


@dataclass
class AuthCredentials:
    p12_path: str
    password: str


@dataclass
class SignatureRequest:
    auth_serial: str
    hash_b64: str
    hash_signature_b64: str
    hash_signature_mechanism: str = "SHA256withRSA"


@dataclass
class SignatureResponse:
    signature_b64: str


@dataclass
class BatchHashData:
    id: int
    hash_b64: str


@dataclass
class BatchSignatureData:
    id: int
    signature_b64: str


@dataclass
class ApiError(Exception):
    status_code: int
    message: str

    def __str__(self) -> str:  # pragma: no cover
        return f"A-Trust API error {self.status_code}: {self.message}"