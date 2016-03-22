__author__ = 'Matt David'

from addressimo.plugin import BasePlugin

class BaseResolver(BasePlugin):

    def get_id_obj(self, id):
        raise NotImplementedError

    def get_all_keys(self):
        raise NotImplementedError

    def get_branches(self, id):
        raise NotImplementedError

    def get_lg_index(self, id, branch):
        raise NotImplementedError

    def set_lg_index(self, id, branch, index):
        raise NotImplementedError

    def save(self, id_obj):
        raise NotImplementedError

    def delete(self, id_obj):
        raise NotImplementedError

    # InvoiceRequest Data Handling
    def add_invoicerequest(self, id, ir_data):
        raise NotImplementedError

    def get_invoicerequests(self, id):
        raise NotImplementedError

    def delete_invoicerequest(self, id, ir_id):
        raise NotImplementedError

    def set_invoicerequest_nonce(self, pubkey1, pubkey2, nonce):
        raise NotImplementedError

    def get_invoicerequest_nonce(self, pubkey1, pubkey2):
        raise NotImplementedError

    def cleanup_stale_invoicerequest_data(self):
        raise NotImplementedError

    # EncryptedPaymentRequest (EPR) Data Handling
    def add_encrypted_paymentrequest(self, encrypted_paymentrequest):
        raise NotImplementedError

    def get_encrypted_paymentrequest(self, id):
        raise NotImplementedError

    def cleanup_stale_encrypted_paymentrequest_data(self):
        raise NotImplementedError

    # Payment Data Handling
    def get_payment_request_meta_data(self, uuid):
        raise NotImplementedError

    def set_payment_request_meta_data(self, expiration_date, wallet_addr, amount):
        raise NotImplementedError

    def cleanup_stale_payment_request_meta_data(self):
        raise NotImplementedError

    def set_payment_meta_data(self, tx_hash, memo, refund_address):
        raise NotImplementedError

    def cleanup_stale_payment_meta_data(self):
        raise NotImplementedError

    def get_refund_address_from_tx_hash(self, tx_hash):
        raise NotImplementedError

    # EncryptedPayment / EncryptedPaymentAck
    def add_encrypted_payment(self, encrypted_payment):
        raise NotImplementedError

    def get_encrypted_payment(self, id):
        raise NotImplementedError

    def add_encrypted_paymentack(self, encrypted_payment_ack):
        raise NotImplementedError

    def get_encrypted_paymentack(self, id):
        raise NotImplementedError

    @classmethod
    def get_plugin_category(cls):
        return 'RESOLVER'

    @classmethod
    def get_plugin_name(cls):
        raise NotImplementedError