# asignseal_qualified/cli.py
import argparse
import os
from .auth import AuthCredentials
from .pdf_signer import PdfSealSigner

def main():
    parser = argparse.ArgumentParser(description='Sign PDFs with A-Trust a.sign seal qualified')
    parser.add_argument('input_pdf', help='Input PDF file')
    parser.add_argument('output_pdf', help='Output PDF file')
    parser.add_argument('--api-url', required=True, help='A-Trust API base URL')
    parser.add_argument('--p12', help='P12 certificate path (or set ATRUST_P12)')
    parser.add_argument('--password', help='P12 password (or set ATRUST_P12_PASSWORD)')
    parser.add_argument('--sid', help='Session ID (or set ATRUST_SID)')
    parser.add_argument('--field', default='Signature1', help='Signature field name')
    parser.add_argument('--reason', default='Qualified electronic seal', help='Signature reason')
    parser.add_argument('--location', default='', help='Signature location')

    args = parser.parse_args()

    try:
        # Authentifizierung laden
        creds = AuthCredentials(args.p12, args.password)

        # PDF signieren
        signer = PdfSealSigner(args.api_url, creds)
        signer.sign_pdf(
            args.input_pdf,
            args.output_pdf,
            field=args.field,
            reason=args.reason,
            location=args.location,
            sid=args.sid or os.getenv('ATRUST_SID')
        )

        print(f"PDF erfolgreich signiert: {args.output_pdf}")

    except Exception as e:
        print(f"Fehler beim Signieren: {e}")
        return 1

    return 0

if __name__ == '__main__':
    exit(main())