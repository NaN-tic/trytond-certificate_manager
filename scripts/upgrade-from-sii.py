#!/usr/bin/env python
import sys

dbname = sys.argv[1]
if len(argv) > 2:
    config_file = sys.argv[2]
    from trytond.config import config as CONFIG
    CONFIG.update_etc(config_file)

from trytond.pool import Pool
from trytond.transaction import Transaction
import logging

Pool.start()
pool = Pool(dbname)
pool.init()

context = {}

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

with Transaction().start(dbname, 1, context=context):
    Company = pool.get('company.company')
    Certificate = pool.get('certificate')

    table = Company.__table_handler__('company')

    if table.column_exist('pem_certificate'):
        cursor = Transaction().connection.cursor()

        query = "select id, pem_certificate, encrypted_private_key from company_company where pem_certificate is not null"
        cursor.execute(query)

        for _id, pem_certificate, encrypted_private_key in cursor.fetchall():

            with Transaction().set_context(company=_id):
                company = Company(_id)

                certificate = Certificate()
                certificate.name = company.rec_name
                certificate.pem_certificate = pem_certificate
                certificate.encrypted_private_key = encrypted_private_key
                certificate.save()

        Transaction().commit()

    logger.info('Done')
