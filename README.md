# a.sign seal qualified

**a.sign seal qualified** is a qualified electronic seal in accordance with the eIDAS regulation (https://eur-lex.europa.eu/eli/reg/2014/910/oj, Section 5, Article 38, Qualified certificates for electronic seals)

**a.sign seal qualified** is a remote signature, therefore the seal private key is stored in a hardware security module in the A-Trust data center.

User Manual: [User_Manual_a.sign_Seal_qualified](User_Manual_a.sign_Seal_qualified.pdf)

## Python client (CLI) to sign PDFs

This repository now includes a clean, secure and modular Python client that can sign PDFs with A-Trust a.sign seal qualified.

### Install

- Python 3.10+
- Install dependencies:

```
pip install -r requirements.txt
```

### Usage

```
python -m asignseal_qualified.cli input.pdf output.pdf --api-url https://<your-asignseal-endpoint> \
  --p12 /path/to/authentication_certificate.p12
```

Options:
- --api-url: Base URL of the A-Trust API
- --p12 / --password: Authentication certificate (P12) and password. You can set env vars ATRUST_P12 and ATRUST_P12_PASSWORD.
- --sid: Optional session identifier (env: ATRUST_SID)
- --field: Signature field name (default: Signature1)
- --reason / --location: Signature metadata

Example with environment variables:

```
export ATRUST_P12=test_credentials/authentication_certificate.p12
export ATRUST_P12_PASSWORD=secret
python -m asignseal_qualified.cli docs/sample.pdf docs/sample.signed.pdf --api-url https://example.com
```

Security notes:
- Never commit P12 files or passwords to version control. Use environment variables or secure secret stores.
- The authentication key is only used locally to sign the request hash, not the document.
- The seal private key remains in A-Trust HSM and is never exposed.

### Library

You can also use the API programmatically:

```python
from asignseal_qualified import ApiClient, SealSignatureService, AuthCredentials, PdfSealSigner

service = SealSignatureService(base_url="https://example.com")
creds = AuthCredentials(p12_path="test_credentials/authentication_certificate.p12", password="secret")

# PDF signing
PdfSealSigner(base_url=service.base_url, creds=creds).sign_pdf("in.pdf", "out.pdf")
```
