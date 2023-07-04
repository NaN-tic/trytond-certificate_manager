# The COPYRIGHT file at the top level of this repository contains the full
# copyright notices and license terms.
from io import BytesIO
from logging import getLogger

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.exceptions import UnsupportedAlgorithm

from trytond.transaction import Transaction
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
    'LoadPKCS12',
    'LoadPKCS12Start',
]
_logger = getLogger(__name__)


class LoadPKCS12Start(ModelView):
    "Load PKCS12 Start"
    __name__ = "certificate.load_pkcs12.start"

    pfx = fields.Binary('PFX File', required=True)
    password = fields.Char('Password', required=True)


class LoadPKCS12(Wizard):
    "Load PKCS12"
    __name__ = "certificate.load_pkcs12"
    start = StateView(
        'certificate.load_pkcs12.start',
        'certificate_manager.certificate_load_pkcs12_start_view', [
            Button('Cancel', 'end', 'tryton-cancel'),
            Button('Load', 'load', 'tryton-ok', default=True),
        ])
    load = StateTransition()

    def transition_load(self):
        Certificate = Pool().get('certificate')

        with BytesIO(self.start.pfx) as pfx:
            try:
                (
                    private_key,
                    certificate,
                    additional_certificates,
                ) = pkcs12.load_key_and_certificates(
                    pfx.read(), self.start.password.encode()
                )
                key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                crt = certificate.public_bytes(serialization.Encoding.PEM)
                Certificate.write(self.records, {
                    'pem_certificate': crt,
                    'private_key': key,
                })
                certificates = ",".join([r.name for r in self.records])
                _logger.info(
                    'Correctly loaded SSL credentials certificates %s',
                    certificates)
            except (ValueError, TypeError, UnsupportedAlgorithm) as e:
                _logger.debug('Cryptographic error loading pkcs12: %s', e)
                errors = e.args[0]
                if isinstance(errors, list):
                    message = ', '.join(error[2] for error in errors)
                elif isinstance(errors, str):
                    message = errors
                else:
                    message = ''
                raise UserError(gettext('certificate_manager.msg_error_loading_pkcs12',
                        message=message))
        return 'end'
