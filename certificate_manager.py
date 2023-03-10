# The COPYRIGHT file at the top level of this repository contains
# the full copyright notices and license terms.
from logging import getLogger
from contextlib import contextmanager
from tempfile import NamedTemporaryFile

from cryptography.fernet import Fernet

from trytond.config import config
from trytond.model import DeactivableMixin, ModelView, ModelSQL, fields
from trytond.transaction import Transaction
from trytond.i18n import gettext
from trytond.exceptions import UserError

_logger = getLogger(__name__)


class CertificateManager(DeactivableMixin, ModelSQL, ModelView):
    'Certificate Manager'
    __name__ = 'certificate.manager'
    name = fields.Char('Name',required=True)
    pem_certificate = fields.Binary('PEM Certificate',required=True)
    encrypted_private_key = fields.Binary('Encrypted Private Key')
    private_key = fields.Function(fields.Binary('Private Key'),
        'get_private_key', 'set_private_key')

    @classmethod
    def get_private_key(cls, certificates, name=None):
        converter = bytes
        default = None
        format_ = Transaction().context.get('%s.%s' % (cls.__name__, name))
        if format_ == 'size':
            converter = len
            default = 0

        pkeys = []
        for certificate in certificates:
            key = certificate._get_private_key(name)
            if not key:
                continue
            pkeys.append(key)

        if not pkeys:
            return {certificate.id:None for x in certificates}

        return {
            certificate.id: converter(pkey) if pkey else default
            for (certificate, pkey) in zip(certificates, pkeys)
        }

    def _get_private_key(self, name=None):
        if not self.encrypted_private_key:
            return None
        fernet = self.get_fernet_key()
        if not fernet:
            return
        decrypted_key = fernet.decrypt(bytes(self.encrypted_private_key))
        return decrypted_key

    @classmethod
    def set_private_key(cls, certificates, name, value):
        encrypted_key = None
        if value:
            fernet = cls.get_fernet_key()
            if not fernet:
                return
            encrypted_key = fernet.encrypt(bytes(value))
        cls.write(certificates, {'encrypted_private_key': encrypted_key})

    @classmethod
    def get_fernet_key(cls):
        fernet_key = config.get('cryptography', 'fernet_key')
        if not fernet_key:
            _logger.error('Missing Fernet key configuration')
        else:
            return Fernet(fernet_key)

    @contextmanager
    def tmp_ssl_credentials(self):
        if not self.pem_certificate or not self.private_key:
            raise UserError(gettext('certificate_manager.msg_missing_pem_cert'))
        with NamedTemporaryFile(suffix='.crt') as crt:
            with NamedTemporaryFile(suffix='.pem') as key:
                crt.write(self.pem_certificate)
                key.write(self.private_key)
                crt.flush()
                key.flush()
                yield (crt.name, key.name)
