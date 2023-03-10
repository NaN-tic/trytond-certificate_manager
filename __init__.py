# This file is part certificate_manager module for Tryton.
# The COPYRIGHT file at the top level of this repository contains
# the full copyright notices and license terms.
from trytond.pool import Pool
from . import certificate_manager
from . import company

def register():
    Pool.register(
        certificate_manager.CertificateManager,
        module='certificate_manager', type_='model')
    Pool.register(
        company.CertificateManager,
        module='certificate_manager', type_='model',
        depends=['company'])
