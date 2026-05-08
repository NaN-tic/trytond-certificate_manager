# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
import subprocess
import tempfile
from logging import getLogger
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate

from trytond.pool import Pool
from trytond.model import ModelView
from trytond.model import fields
from trytond.wizard import Wizard
from trytond.wizard import StateView
from trytond.wizard import StateTransition
from trytond.wizard import Button
from trytond.i18n import gettext
from trytond.exceptions import UserError

__all__ = [
    'LoadSATEFirma',
    'LoadSATEFirmaStart',
    'convert_sat_efirma_to_pem',
]
_logger = getLogger(__name__)


def _run_openssl(command, error_message):
    try:
        subprocess.run(
            command, check=True, capture_output=True, text=True, timeout=30)
    except FileNotFoundError as exception:
        raise UserError(gettext(
            'certificate_manager.msg_openssl_not_found')) from exception
    except subprocess.CalledProcessError as exception:
        raise UserError(gettext(error_message)) from exception


def convert_sat_efirma_to_pem(certificate_der, private_key_der, password):
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        certificate_path = directory / 'certificate.cer'
        key_path = directory / 'private.key'
        password_path = directory / 'password.txt'
        pem_certificate_path = directory / 'certificate.pem'
        pem_key_path = directory / 'private.pem'

        certificate_path.write_bytes(certificate_der)
        key_path.write_bytes(private_key_der)
        password_path.write_text(password)

        _run_openssl([
                'openssl', 'x509',
                '-inform', 'DER',
                '-in', str(certificate_path),
                '-out', str(pem_certificate_path),
                ], 'certificate_manager.msg_error_loading_sat_certificate')
        _run_openssl([
                'openssl', 'pkcs8',
                '-inform', 'DER',
                '-in', str(key_path),
                '-passin', 'file:%s' % password_path,
                '-out', str(pem_key_path),
                ], 'certificate_manager.msg_error_loading_sat_private_key')
        pem_certificate = pem_certificate_path.read_bytes()
        pem_key = pem_key_path.read_bytes()
        validate_sat_efirma(pem_certificate, pem_key)
        return pem_certificate, pem_key


def validate_sat_efirma(pem_certificate, pem_key):
    certificate = load_pem_x509_certificate(pem_certificate)
    private_key = load_pem_private_key(pem_key, None)
    if private_key.public_key().public_numbers() != (
            certificate.public_key().public_numbers()):
        raise UserError(gettext(
            'certificate_manager.msg_sat_certificate_key_mismatch'))
    return certificate


class LoadSATEFirmaStart(ModelView):
    "Load SAT e.firma Start"
    __name__ = "certificate.load_sat_efirma.start"

    cer = fields.Binary('CER File', required=True)
    key = fields.Binary('KEY File', required=True)
    password = fields.Char('Password', required=True, strip=False)


class LoadSATEFirma(Wizard):
    "Load SAT e.firma"
    __name__ = "certificate.load_sat_efirma"
    start = StateView(
        'certificate.load_sat_efirma.start',
        'certificate_manager.certificate_load_sat_efirma_start_view', [
            Button('Cancel', 'end', 'tryton-cancel'),
            Button('Load', 'load', 'tryton-ok', default=True),
        ])
    load = StateTransition()

    def transition_load(self):
        Certificate = Pool().get('certificate')

        certificate, private_key = convert_sat_efirma_to_pem(
            self.start.cer, self.start.key, self.start.password)
        Certificate.write(self.records, {
            'pem_certificate': certificate,
            'private_key': private_key,
        })
        certificates = ",".join([record.name for record in self.records])
        _logger.info('Correctly loaded SAT e.firma certificates %s',
            certificates)
        return 'end'
