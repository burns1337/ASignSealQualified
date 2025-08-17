from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.x509 import Certificate


@dataclass
class AuthKeyMaterial:
    private_key: object
    certificate: Certificate


def load_auth_p12(path: str, password: str) -> AuthKeyMaterial:
    if password is None:
        raise ValueError("Password must not be None")
    with open(path, "rb") as f:
        data = f.read()
    private_key, cert, _addl = load_key_and_certificates(data, password.encode("utf-8"))
    if private_key is None or cert is None:
        raise ValueError("Failed to load private key or certificate from P12")
    return AuthKeyMaterial(private_key=private_key, certificate=cert)


def get_cert_serial_decimal(cert: Certificate) -> str:
    # C# demo uses decimal serial
    return str(cert.serial_number)


def sign_with_auth_key(private_key, data: bytes) -> bytes:
    # Corresponds to SHA256withRSA in the C# sample
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signature


def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))
