# This file is part certificate_manager module for Tryton.
# The COPYRIGHT file at the top level of this repository contains
# the full copyright notices and license terms.
from trytond.pool import Pool
from . import certificate_manager
from . import company
from . import load_pkcs12
from . import load_sat_efirma

def register():
    Pool.register(
        certificate_manager.Certificate,
        load_pkcs12.LoadPKCS12Start,
        load_sat_efirma.LoadSATEFirmaStart,
        module='certificate_manager', type_='model')
    Pool.register(
        company.Certificate,
        module='certificate_manager', type_='model',
        depends=['company'])
    Pool.register(
        load_pkcs12.LoadPKCS12,
        load_sat_efirma.LoadSATEFirma,
        module='certificate_manager', type_='wizard')
