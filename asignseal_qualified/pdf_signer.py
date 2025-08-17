# asign_seal_qualified/pdf_signer.py
import hashlib
from PyPDF2 import PdfReader, PdfWriter
import base64
from .seal_service import SealSignatureService


class PdfSealSigner:
    def __init__(self, base_url: str, auth_credentials):
        self.service = SealSignatureService(base_url, auth_credentials)

    def sign_pdf(self, input_path: str, output_path: str, **signature_params):
        """Signiert ein PDF mit a.sign seal qualified"""
        # PDF lesen und Hash erstellen
        with open(input_path, 'rb') as f:
            pdf_data = f.read()

        pdf_hash = hashlib.sha256(pdf_data).digest()

        # Signatur erstellen
        signature_result = self.service.create_signature(pdf_hash, signature_params)

        # PDF mit Signatur modifizieren
        self._apply_signature_to_pdf(input_path, output_path, signature_result)

    def _apply_signature_to_pdf(self, input_path: str, output_path: str, signature_data: dict):
        """Wendet die Signatur auf das PDF an"""
        reader = PdfReader(input_path)
        writer = PdfWriter()

        # Alle Seiten kopieren
        for page in reader.pages:
            writer.add_page(page)

        # Signatur-Metadaten hinzufügen
        if 'signature' in signature_data:
            # Signatur in PDF einbetten (vereinfachte Implementierung)
            writer.add_metadata({
                '/ATrust_Signature': signature_data['signature'],
                '/Signature_Field': signature_data.get('field', 'Signature1')
            })

        # Signiertes PDF speichern
        with open(output_path, 'wb') as f:
            writer.write(f)