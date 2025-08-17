from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Optional

from cryptography.x509 import load_der_x509_certificate

from .api_client import ApiClient, SealSignatureService
from .models import AuthCredentials
from .crypto import sha256


# We leverage pyHanko for clean PDF signing with external signature providers.
# The ExternalSigner below asks the remote A-Trust service to sign the CMS
# SignedAttributes digest, and pyHanko takes care of embedding the CMS into the PDF.
try:
    from pyhanko.sign.general import ExternalSigner
    from pyhanko.sign.general import SimpleCertificateStore
    from pyhanko.sign.signers.pdf_signer import PdfSigner
    from pyhanko.sign.fields import SigFieldSpec
    from pyhanko.sign.general import SignatureResult
    from pyhanko.sign.general import ExternalSignature
    from pyhanko.sign.general import KeyUsageConstraints
except Exception as e:  # pragma: no cover
    ExternalSigner = object  # type: ignore
    PdfSigner = None  # type: ignore
    SimpleCertificateStore = None  # type: ignore
    SigFieldSpec = None  # type: ignore
    SignatureResult = None  # type: ignore
    ExternalSignature = None  # type: ignore
    KeyUsageConstraints = None  # type: ignore


@dataclass
class _ATrustExternalSigner(ExternalSigner):  # type: ignore[misc]
    api: ApiClient
    sid: Optional[str] = None

    def sign_raw(self, data: bytes, digest_algorithm: str) -> "SignatureResult":  # type: ignore[override]
        # pyHanko will provide the DER-encoded SignedAttributes as data.
        # We must provide an RSA PKCS#1 v1.5 signature over hash(data) with the
        # remote seal key. First we compute SHA-256 over data, then have A-Trust
        # sign that hash. Note: digest_algorithm is expected to be 'sha256'.
        if digest_algorithm.lower() not in ("sha256", "sha-256"):
            raise ValueError("Only sha256 is supported by A-Trust example client")
        digest = sha256(data)
        signature = self.api.sign_arbitrary_hash(digest, sid=self.sid)
        # Wrap as ExternalSignature for pyHanko
        return ExternalSignature(raw_sig=signature, md_algorithm=digest_algorithm)

    @property
    def signing_cert(self):  # type: ignore[override]
        # Retrieve the remote seal certificate and return as cryptography cert
        cert_der = self.api.fetch_seal_certificate(sid=self.sid)
        return load_der_x509_certificate(cert_der)

    @property
    def cert_registry(self):  # type: ignore[override]
        # For simplicity, only provide the end-entity cert to pyHanko's store.
        # A-Trust may provide chain via AIA; validation can be configured by users.
        store = SimpleCertificateStore()
        store.register(self.signing_cert)
        return store


@dataclass
class PdfSealSigner:
    base_url: str
    creds: AuthCredentials
    sid: Optional[str] = None

    def sign_pdf(self, input_pdf_path: str, output_pdf_path: str, field_name: Optional[str] = None,
                 reason: Optional[str] = None, location: Optional[str] = None):
        if PdfSigner is None:
            raise RuntimeError("pyHanko is required for PDF signing. Please install dependencies from requirements.txt")
        service = SealSignatureService(self.base_url)
        api = ApiClient(service, self.creds)
        signer = _ATrustExternalSigner(api=api, sid=self.sid)

        # Configure PDF signer
        sig_spec = SigFieldSpec(field_name or "Signature1")
        signer_kwargs = {}
        if reason:
            signer_kwargs["reason"] = reason
        if location:
            signer_kwargs["location"] = location

        pdf_signer = PdfSigner(sig_field_spec=sig_spec)
        with open(input_pdf_path, 'rb') as inf, open(output_pdf_path, 'wb') as outf:
            pdf_signer.sign_pdf(inf, signer=signer, output=outf, **signer_kwargs)
