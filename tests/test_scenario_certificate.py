import datetime
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from proteus import Model
from trytond.tests.test_tryton import drop_db
from trytond.tests.tools import activate_modules


class TestCertificate(unittest.TestCase):

    def setUp(self):
        drop_db()
        super().setUp()

    def tearDown(self):
        drop_db()
        super().tearDown()

    def test(self):
        config = activate_modules('certificate_manager')
        Certificate = Model.get('certificate')
        record = Certificate(name='Certificate')
        record.save()
        self.assertIsNone(record.metadata)
        self.assertIsNone(record.expiration_date)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificate = (x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, 'Test Subject')]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, 'Test Issuer')]))
            .public_key(key.public_key())
            .serial_number(12345)
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2030, 12, 31, 23, 59))
            .sign(key, hashes.SHA256()))
        record.pem_certificate = certificate.public_bytes(
            serialization.Encoding.PEM)
        record.save()
        self.assertEqual(record.expiration_date, datetime.date(2030, 12, 31))
        for value in ('CN=Test Subject', 'CN=Test Issuer', '12345',
                '2020-01-01T00:00:00+00:00', '2030-12-31T23:59:00+00:00',
                certificate.fingerprint(hashes.SHA256()).hex(':')):
            self.assertIn(value, record.metadata)

        context = dict(config.context, **{'certificate.pem_certificate': 'size'})
        values, = Certificate._proxy.read([record.id],
            ['pem_certificate', 'metadata', 'expiration_date'], context)
        self.assertEqual(values['pem_certificate'], len(record.pem_certificate))
        self.assertEqual(values['metadata'], record.metadata)
        self.assertEqual(values['expiration_date'], record.expiration_date)

        record.pem_certificate = b'Invalid certificate'
        record.save()
        self.assertEqual(record.metadata, 'Invalid PEM certificate.')
        self.assertIsNone(record.expiration_date)

        record.pem_certificate = None
        record.save()
        self.assertIsNone(record.metadata)
        self.assertIsNone(record.expiration_date)
