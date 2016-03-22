__author__ = 'frank'

from addressimo.config import config
from addressimo.plugin import PluginManager
from addressimo.util import LogUtil

log = LogUtil.setup_logging()

PluginManager.register_plugins()
resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)


log.info('Starting Stale PaymentRequest Meta Data Cleanup')
resolver.cleanup_stale_payment_request_meta_data()
log.info('Completed Stale PaymentRequest Meta Data Cleanup')


log.info('Starting Stale Payment Meta Data Cleanup')
resolver.cleanup_stale_payment_meta_data()
log.info('Completed Stale Payment Meta Data Cleanup')


log.info('Starting Stale InvoiceRequest Data Cleanup')
resolver.cleanup_stale_invoicerequest_data()
log.info('Completed Stale InvoiceRequest Data Cleanup')


log.info('Starting Stale EncryptedPaymentRequest Data Cleanup')
resolver.cleanup_stale_encrypted_paymentrequest_data()
log.info('Completed Stale EncryptedPaymentRequest Data Cleanup')