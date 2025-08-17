

"""
ASignSealQualified - Python CLI to sign PDFs using A-Trust a.sign seal qualified

Usage example:
  python -m asignseal_qualified.cli input.pdf output.pdf --api-url https://example.com --p12 test_credentials/authentication_certificate.p12

For more options, run:
  python -m asignseal_qualified.cli --help
"""

from asignseal_qualified.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

