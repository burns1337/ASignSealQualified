from __future__ import annotations

import argparse
import getpass
import os
from typing import Optional

from .api_client import SealSignatureService
from .models import AuthCredentials
from .pdf_signer import PdfSealSigner


def _env_default(name: str, default: Optional[str] = None) -> Optional[str]:
    return os.environ.get(name, default)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Sign PDFs using A-Trust ASignSealQualified remote seals")
    p.add_argument("input", help="Input PDF path")
    p.add_argument("output", help="Output signed PDF path")
    p.add_argument("--api-url", required=True, help="Base URL of the A-Trust qualified seal API")
    p.add_argument("--p12", dest="p12_path", default=_env_default("ATRUST_P12"), help="Path to authentication .p12 file (env: ATRUST_P12)")
    p.add_argument("--password", dest="password", default=_env_default("ATRUST_P12_PASSWORD"), help="Password for the .p12 (env: ATRUST_P12_PASSWORD). If omitted, you will be prompted securely.")
    p.add_argument("--sid", dest="sid", default=_env_default("ATRUST_SID"), help="Optional session identifier")
    p.add_argument("--field", dest="field_name", default=None, help="Signature field name to create/use (default: Signature1)")
    p.add_argument("--reason", dest="reason", default=None, help="Reason for signing")
    p.add_argument("--location", dest="location", default=None, help="Location for signing")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.p12_path:
        parser.error("Missing --p12 (or ATRUST_P12 env var)")
    password = args.password or getpass.getpass("P12 password: ")

    creds = AuthCredentials(p12_path=args.p12_path, password=password)

    signer = PdfSealSigner(base_url=args.api_url, creds=creds, sid=args.sid)
    signer.sign_pdf(
        input_pdf_path=args.input,
        output_pdf_path=args.output,
        field_name=args.field_name,
        reason=args.reason,
        location=args.location,
    )
    print(f"Signed PDF written to {args.output}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
