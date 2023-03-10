# This file is part of Tryton.  The COPYRIGHT file at the top level of
# this repository contains the full copyright notices and license terms.
from trytond.model import fields
from trytond.pool import PoolMeta
from trytond.transaction import Transaction


class CertificateManager(metaclass=PoolMeta):
    __name__ = 'certificate.manager'
    company = fields.Many2One(
        'company.company', "Company",
        help="Restricts the certificate usage to the company.")

    @classmethod
    def __setup__(cls):
        super(CertificateManager, cls).__setup__()
        cls._order.insert(0, ('company', 'ASC'))

    @staticmethod
    def default_company():
        return Transaction().context.get('company')
