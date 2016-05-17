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

    ##################################
    # Payment Protocol Data Handling
    ##################################
    def get_paymentprotocol_messages(self, id=None, tx_id=None):
        raise NotImplementedError

    def add_paymentprotocol_message(self, message, id=None, tx_id=None):
        raise NotImplementedError

    def delete_paymentprotocol_message(self, tx_identifier, type, id=None, tx_id=None):
        raise NotImplementedError

    def cleanup_stale_paymentprotocol_messages(self):
        raise NotImplementedError

    def get_tx_last_nonce(self, message, id=None, tx_id=None):
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

    @classmethod
    def get_plugin_category(cls):
        return 'RESOLVER'

    @classmethod
    def get_plugin_name(cls):
        raise NotImplementedError