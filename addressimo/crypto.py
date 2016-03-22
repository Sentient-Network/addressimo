__author__ = 'Matt David'

import iptools
import ssl
from datetime import datetime, timedelta
from flask import request
import hashlib
import hmac
from pybitcointools import serialize_script, b58check_to_hex, hex_to_b58check, deserialize_script
from pycoin.key.BIP32Node import BIP32Node
from redis import Redis

from addressimo.paymentprotocol.paymentrequest_pb2 import PaymentRequest, PaymentDetails, X509Certificates
from addressimo.config import config
from addressimo.plugin import PluginManager
from addressimo.util import LogUtil

####################
# Bitcoin OP_CODES #
####################
OP_DUP = 118
OP_HASH160 = 169
OP_EQUALVERIFY = 136
OP_CHECKSIG = 172

log = LogUtil.setup_logging()

def derive_branch():
    branch = iptools.ipv4.ip2long(request.remote_addr)

    # This method will have a collision occasionally between two IP addresses.
    if branch > 2**31:
        branch %= 2**31

    # Use last two octets of the IP for branch uniqueness
    return branch & 0x0000ffff

def generate_bip32_address_from_extended_pubkey(extended_pubkey, branch, index):

    ext_key = BIP32Node.from_wallet_key(extended_pubkey)

    return ext_key.subkey_for_path('%d/%d' % (branch, index)).address()

def get_certs(x509_pem_format):

    certs = []
    loading_cert = ''
    for line in x509_pem_format.split('\n'):
        if not line:
            pass

        loading_cert += line
        if line == '-----END CERTIFICATE-----':
            if loading_cert:
                der_cert = ssl.PEM_cert_to_DER_cert(loading_cert)
                certs.append(der_cert)
            loading_cert = ''

    return certs

def generate_payment_request(crypto_addr, x509_cert, expires, signer=None, amount=0, memo=None, payment_url=None, merchant_data=None):

    # Setup & Populate PaymentDetails
    payment_details = PaymentDetails()

    # Setup Single PaymentDetails Output
    output = payment_details.outputs.add()
    output.amount = amount * 100000000 # BTC to Satoshis

    if crypto_addr[0] == '1':
        output.script = serialize_script([OP_DUP, OP_HASH160, b58check_to_hex(crypto_addr), OP_EQUALVERIFY, OP_CHECKSIG]).decode('hex')
    else:
        try:
            int(crypto_addr, 16)
            output.script = str(crypto_addr).decode('hex')
        except ValueError:
            output.script = str(crypto_addr)

    # Add current and expiration epoch time values
    payment_details.time = int(datetime.utcnow().strftime('%s'))

    payment_details.expires = expires

    # Handle Various Optional Fields in PaymentDetails
    payment_details.memo = memo if memo else ''
    payment_details.payment_url = payment_url if payment_url else ''
    payment_details.merchant_data = str(merchant_data) if merchant_data else ''

    # Setup & Populate PaymentRequest
    payment_request = PaymentRequest()
    payment_request.payment_details_version = 1
    payment_request.serialized_payment_details = payment_details.SerializeToString()

    # Set PKI Type / Data
    if not x509_cert or not signer:
        payment_request.pki_type = 'none'
        payment_request.pki_data = ''
    else:

        payment_request.pki_type = signer.get_pki_type()
        pki_data = X509Certificates()

        for cert in get_certs(x509_cert):
            pki_data.certificate.append(cert)

        payment_request.pki_data = pki_data.SerializeToString()

    # Sign PaymentRequest
    if signer and x509_cert:
        payment_request.signature = ''
        payment_request.signature = signer.sign(payment_request.SerializeToString())

    # Log Payment Request to Logging System
    logger = PluginManager.get_plugin('LOGGER', config.logger_type)
    logger.log_payment_request(crypto_addr, signer.__class__.__name__, amount, expires, memo, payment_url, merchant_data)

    log.debug('Generated Payment Request [Address: %s | Signer: %s | Amount: %s | Expires: %s | Memo: %s | Payment URL: %s | Merchant Data: %s]' %
              (crypto_addr, signer.__class__.__name__, amount, expires, memo, payment_url, merchant_data))

    return payment_request.SerializeToString()

def get_unused_presigned_payment_request(id_obj):

    redis_conn = Redis.from_url(config.redis_addr_cache_uri)
    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)

    return_pr = None
    used_pr = []

    if config.store_and_forward_only and id_obj.presigned_payment_requests:
        return_pr = id_obj.presigned_payment_requests[0]
        id_obj.presigned_payment_requests.remove(return_pr)
        resolver.save(id_obj)
        return return_pr

    for pr in id_obj.presigned_payment_requests:

        if any([redis_conn.get(x) for x in get_addrs_from_paymentrequest(pr.decode('hex'))]):
            used_pr.append(pr)
            continue

        return_pr = pr
        break

    for pr in used_pr:
        id_obj.presigned_payment_requests.remove(pr)

    if used_pr:
        resolver.save(id_obj)

    return return_pr


def get_addrs_from_paymentrequest(pr):

    ret_list = []
    pr_obj = PaymentRequest()
    pr_obj.ParseFromString(pr)

    pd = PaymentDetails()
    pd.ParseFromString(pr_obj.serialized_payment_details)

    for output in pd.outputs:
        script = deserialize_script(output.script)
        if script[0] == OP_DUP and script[1] == OP_HASH160 and script[3] == OP_EQUALVERIFY and script[4] == OP_CHECKSIG:
            ret_list.append(hex_to_b58check(script[2].encode('hex')))

    return ret_list

# Borrowed and updated (add nonce) from https://github.com/fpgaminer/python-hmac-drbg/blob/master/hmac_drbg/hmac_drbg.py
# The code was released under public domain per https://github.com/fpgaminer/python-hmac-drbg/blob/master/LICENSE
#
# Implements an HMAC_DRBG (NIST SP 800-90A) based on HMAC_SHA256.
# Supports security strengths up to 256 bits.
# Parameters are based on recommendations provided by Appendix D of NIST SP 800-90A.
class HMAC_DRBG(object):
    def __init__(self, entropy, nonce="", requested_security_strength=256, personalization_string=""):
        if requested_security_strength > 256:
            raise RuntimeError, "requested_security_strength cannot exceed 256 bits."

        # Modified from Appendix D, which specified 160 bits here
        if len(personalization_string) * 8 > 256:
            raise RuntimeError, "personalization_string cannot exceed 256 bits."

        if requested_security_strength <= 112:
            self.security_strength = 112
        elif requested_security_strength <= 128:
            self.security_strength = 128
        elif requested_security_strength <= 192:
            self.security_strength = 192
        else:
            self.security_strength = 256

        if (len(entropy) * 8 * 2) < (3 * self.security_strength):
            raise RuntimeError, "entropy must be at least %f bits." % (1.5 * self.security_strength)

        if len(entropy) * 8 > 1000:
            raise RuntimeError, "entropy cannot exceed 1000 bits."

        self._instantiate(entropy, nonce, personalization_string)

    # Just for convenience and succinctness
    def _hmac(self, key, data):
        return hmac.new(key, data, hashlib.sha256).digest()

    def _update(self, provided_data=None):
        self.K = self._hmac(self.K, self.V + "\x00" + ("" if provided_data is None else provided_data))
        self.V = self._hmac(self.K, self.V)

        if provided_data is not None:
            self.K = self._hmac(self.K, self.V + "\x01" + provided_data)
            self.V = self._hmac(self.K, self.V)

    def _instantiate(self, entropy, nonce, personalization_string):
        seed_material = entropy + nonce + personalization_string

        self.K = "\x00" * 32
        self.V = "\x01" * 32

        self._update(seed_material)
        self.reseed_counter = 1

    def reseed(self, entropy):
        if (len(entropy) * 8) < self.security_strength:
            raise RuntimeError, "entropy must be at least %f bits." % (self.security_strength)

        if len(entropy) * 8 > 1000:
            raise RuntimeError, "entropy cannot exceed 1000 bits."

        self._update(entropy)
        self.reseed_counter = 1

    def generate(self, num_bytes, requested_security_strength=256):
        if (num_bytes * 8) > 7500:
            raise RuntimeError, "generate cannot generate more than 7500 bits in a single call."

        if requested_security_strength > self.security_strength:
            raise RuntimeError, "requested_security_strength exceeds this instance's security_strength (%d)" % self.security_strength

        if self.reseed_counter >= 10000:
            return None

        temp = ""

        while len(temp) < num_bytes:
            self.V = self._hmac(self.K, self.V)
            temp += self.V

        self._update(None)
        self.reseed_counter += 1

        return temp[:num_bytes]
