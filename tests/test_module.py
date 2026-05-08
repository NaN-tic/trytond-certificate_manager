# This file is part certificate_manager module for Tryton.
# The COPYRIGHT file at the top level of this repository contains
# the full copyright notices and license terms.
from datetime import datetime, timedelta, UTC

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from trytond.modules.certificate_manager.load_sat_efirma import (
    convert_sat_efirma_to_pem)
from trytond.exceptions import UserError
from trytond.tests.test_tryton import ModuleTestCase, with_transaction


class CertificateManagerTestCase(ModuleTestCase):
    'Test Certificate Manager module'
    module = 'certificate_manager'
    extras = ['company']

    @with_transaction()
    def test_convert_sat_efirma_to_pem(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        password = 'secret123'
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, 'SAT TEST')]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, 'SAT TEST')]))
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
            .sign(key, hashes.SHA256()))
        cer_der = certificate.public_bytes(serialization.Encoding.DER)
        key_der = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password.encode()))

        pem_certificate, pem_key = convert_sat_efirma_to_pem(
            cer_der, key_der, password)

        self.assertTrue(
            pem_certificate.startswith(b'-----BEGIN CERTIFICATE-----'))
        self.assertTrue(
            pem_key.startswith(b'-----BEGIN PRIVATE KEY-----'))

    @with_transaction()
    def test_convert_sat_efirma_to_pem_mismatch(self):
        key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        password = 'secret123'
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, 'SAT TEST')]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, 'SAT TEST')]))
            .public_key(key1.public_key())
            .serial_number(1)
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1))
            .sign(key1, hashes.SHA256()))
        cer_der = certificate.public_bytes(serialization.Encoding.DER)
        key_der = key2.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password.encode()))

        with self.assertRaises(UserError):
            convert_sat_efirma_to_pem(cer_der, key_der, password)

del ModuleTestCase
