__author__ = 'Matt David'

import json
import pybitcointools
import requests
import ssl
import time

from collections import defaultdict
from datetime import datetime
from ecdsa import VerifyingKey
from ecdsa.util import sigdecode_der
from flask import request, Response
from hashlib import sha256
from OpenSSL import crypto
from time import sleep

from ..blockchain import submit_transaction
from ..config import config
from ..sec_util import from_sec, to_sec
from ..plugin import PluginManager
from ..storeforward import requires_public_key, verify_public_key
from ..util import requires_valid_signature, create_json_response, get_id, LogUtil, PAYMENT_SIZE_MAX
from ..validators import *

from .paymentrequest_pb2 import InvoiceRequest, PaymentRequest, X509Certificates, Payment, PaymentACK, ProtocolMessage, EncryptedProtocolMessage, ProtocolMessageType

log = LogUtil.setup_logging()

PP_MESSAGE_TYPE = 'application/bitcoin-paymentprotocol-message'
PP_ENC_MESSAGE_TYPE = 'application/bitcoin-encrypted-paymentprotocol-message'
PAYMENT_PROTOCOL_CONTENT_TYPES = [PP_MESSAGE_TYPE, PP_ENC_MESSAGE_TYPE]

class EncryptedMessageValidationError(BaseException):
    pass

class NonceValidationError(BaseException):
    pass

def validate_encrypted_message(msg, sig_key='sender', sig_required=False):

    # Verify Keys in DER Format
    try:
        sender_key = from_sec(msg.sender_public_key) or VerifyingKey.from_der(msg.sender_public_key)
    except Exception as e:
        log.warn("sender_public_key NOT in DER Format")
        raise EncryptedMessageValidationError('sender_public_key not in DER format')

    try:
        receiver_key = from_sec(msg.receiver_public_key) or VerifyingKey.from_der(msg.receiver_public_key)
    except Exception as e:
        log.warn("receiver_public_key NOT in DER Format")
        raise EncryptedMessageValidationError('receiver_public_key not in DER format')

    # Validate Nonce
    if not msg.nonce or msg.nonce < (int(time.time() * 1000000) - config.ir_nonce_allowable * 1000000):
        log.warn("InvoiceRequest Nonce Missing or Before %d Seconds Ago" % config.ir_nonce_allowable)
        raise NonceValidationError('Invalid Nonce')

    if not msg.signature:
        if not sig_required:
            return
        else:
            raise EncryptedMessageValidationError('Signature Required')

    # Validate Signature
    try:
        sig_verify = msg.signature
        msg.signature = ''
        if sig_key == 'sender':
            sender_key.verify(sig_verify, msg.SerializeToString(), hashfunc=sha256, sigdecode=sigdecode_der)
        elif sig_key == 'receiver':
            receiver_key.verify(sig_verify, msg.SerializeToString(), hashfunc=sha256, sigdecode=sigdecode_der)
        else:
            raise Exception('Invalid sig_key argument')
        msg.signature = sig_verify
    except Exception as e:
        log.warn('Signature Validation Failed: %s' % str(e))
        raise EncryptedMessageValidationError('Invalid Signature')

def parse_paymentprotocol_message(data):
    try:
        epm = EncryptedProtocolMessage()
        epm.ParseFromString(data)
        epm.SerializeToString()
        return epm
    except:
        try:
            pm = ProtocolMessage()
            pm.ParseFromString(data)
            pm.SerializeToString()
            return pm
        except:
            pass

@requires_valid_signature
def get_paymentprotocol_messages(id=None, tx_id=None, ignore_pubkey_verify=False):

    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)

    if not id and not tx_id:
        log.error('Missing ID and TX_ID, Returning Error')
        return create_json_response(False, 'Invalid Payment Protocol Message Retrieval Attempt', 400)

    transactions = []
    if id:

        if not ignore_pubkey_verify:
            not_verified = verify_public_key()
            if not_verified:
                return not_verified

        try:
            id_obj = resolver.get_id_obj(id)
        except Exception as e:
            log.error('Exception retrieving id_obj [ID: %s | Exception: %s]' % (id, str(e)))
            return create_json_response(False, 'Exception Occurred, Please Try Again Later.', 500)

        if not id_obj:
            log.error('Unable to retrieve id_obj [ID: %s]' % id)
            return create_json_response(False, 'ID Not Recognized', 404)

        transactions = resolver.get_paymentprotocol_messages(id=id)

    if tx_id:
        transactions = resolver.get_paymentprotocol_messages(tx_id=tx_id)

    ret_data = {
        'count': 0,
        'protocol_messages': [],
        'encrypted_protocol_messages': []
    }

    for tx in transactions.values():
        for msg in tx.get('messages', []):
            ret_data['count'] += 1
            parsed_msg = parse_paymentprotocol_message(msg)
            if isinstance(parsed_msg, EncryptedProtocolMessage):
                ret_data['encrypted_protocol_messages'].append(parsed_msg.SerializeToString().encode('hex'))
            else:
                ret_data['protocol_messages'].append(parsed_msg.SerializeToString().encode('hex'))

    return create_json_response(True, data=ret_data)

@requires_valid_signature
def submit_paymentprotocol_message(id=None, tx_id=None, ignore_pubkey_verify=False):

    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)

    if not id and not tx_id:
        log.error('Missing ID and TX_ID, Returning Error')
        return create_json_response(False, 'Invalid Payment Protocol Message Retrieval Attempt', 400)

    if request.content_type not in PAYMENT_PROTOCOL_CONTENT_TYPES:
        log.warn('Received Request with Invalid Content-Type [CONTENT-TYPE: %s]' % str(request.content_type))
        return create_json_response(False, 'Invalid Content-Type for Payment Protocol Message', 400)

    if request.headers.get('Content-Transfer-Encoding', '') != 'binary':
        log.warn("PaymentProtocol Message Content-Transfer-Encoding IS NOT set to binary")
        return create_json_response(False, 'PaymentProtocol Message Content-Transfer-Encoding MUST be binary', 400)

    ##########################################################
    # Verify ID or TX Exists (and is correctly configured
    ##########################################################
    if id:

        if not ignore_pubkey_verify:
            not_verified = verify_public_key()
            if not_verified:
                return not_verified

        try:
            id_obj = resolver.get_id_obj(id)
        except Exception as e:
            log.error('Exception retrieving id_obj [ID: %s | Exception: %s]' % (id, str(e)))
            return create_json_response(False, 'Exception Occurred, Please Try Again Later.', 503)

        if not id_obj:
            log.error('Unable to retrieve id_obj [ID: %s]' % id)
            return create_json_response(False, 'ID Not Recognized', 404)

        if not id_obj.paymentprotocol_only:
            log.warn("PaymentProtocol Endpoint POST Submitted to Non-PaymentProtocol Endpoint")
            return create_json_response(False, 'Not a PaymentProtocol Endpoint', 400)

    if tx_id and not resolver.get_paymentprotocol_messages(tx_id=tx_id):

        log.error('No Messages Exist, Unable to Add Message to Transaction [TX ID: %s]' % str(tx_id))
        return create_json_response(False, 'Transaction Does Not Exist', 404)

    ########################################
    # Handle ProtocolMessages
    ########################################
    message = parse_paymentprotocol_message(request.get_data())
    if not message:
        log.error('Unable to Parse Payment Protocol Message, Returning an Error')
        return create_json_response(False, 'Unable to Parse Payment Protocol', 400)

    # Verify Identifier is Set
    if not message.identifier:
        log.warn('Identifier is Missing from Payment Protocol Message, Rejecting')
        return create_json_response(False, 'Payment Protocol Message Missing Required Field: identifier', 400)

    if isinstance(message, ProtocolMessage) and message.message_type != ProtocolMessageType.Value('INVOICE_REQUEST'):
        log.warn("Non-InvoiceRequest Message Send via Protocol Message")
        return create_json_response(False, 'Only InvoiceRequest Messages May Be Send Using ProtocolMessages, all others require EncryptedProtocolMessages', 400)

    #################################################
    # Verify Encrypted Protocol Message Signatures
    #################################################
    if isinstance(message, EncryptedProtocolMessage):

        required_identity = message.sender_public_key
        text_identity = 'sender'
        if message.message_type in [ProtocolMessageType.Value('PAYMENT_REQUEST'), ProtocolMessageType.Value('PAYMENT_ACK')]:
            required_identity = message.receiver_public_key
            text_identity = 'receiver'

        # Determine Possible Values the sender_public_key could have
        vk = from_sec(request.headers.get('x-identity').decode('hex')) or VerifyingKey.from_der(request.headers.get('x-identity').decode('hex'))
        pk_vals = [vk.to_der().encode('hex'), to_sec(vk, False).encode('hex'), to_sec(vk, True).encode('hex')]

        # Verify the Sender is the message signer
        if required_identity.encode('hex') not in pk_vals:
            log.warn("Message %s Public Key Does Not Match X-Identity Public Key" % text_identity)
            return create_json_response(False, 'Message %s Public Key Does Not Match X-Identity Public Key' % text_identity, 400)

        # Check Nonce is Increasing
        if message.message_type != ProtocolMessageType.Value('INVOICE_REQUEST') and resolver.get_tx_last_nonce(message, id=id) > message.nonce:
            log.warn('PaymentProtocol EncryptedProtocolMessage Submitted with Invalid Nonce')
            return create_json_response(False, 'Nonce is Not Valid', 400)

        # Validate Encrypted Message
        try:
            validate_encrypted_message(message, sig_key=text_identity, sig_required=True)
        except EncryptedMessageValidationError as e:
            return create_json_response(False, str(e), 400)
        except NonceValidationError as e:
            return create_json_response(False, str(e), 400, data={'utime': int(time.time() * 1000000)})

    # Process Submission
    if message.message_type == ProtocolMessageType.Value('INVOICE_REQUEST'):
        return process_invoicerequest(message, id)
    elif message.message_type == ProtocolMessageType.Value('PAYMENT_REQUEST'):
        return process_paymentrequest(message, id)
    else:
        ret_tx_id = resolver.add_paymentprotocol_message(message, id=id, tx_id=tx_id)
        if not ret_tx_id:
            log.error('Unknown Failure Occurred Adding PaymentProtocol message to service')
            return create_json_response(False, 'Message Store Failed', 500)
        return create_json_response(True, 'Payment Protocol message accepted')

@requires_valid_signature
def delete_paymentprotocol_message(identifier, message_type, id=None, tx_id=None):

    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)

    if id:
        not_verified = verify_public_key()
        if not_verified:
            return not_verified

    if not id and not tx_id:
        log.error('Missing ID and TX_ID, Returning Error')
        return create_json_response(False, 'Invalid Payment Protocol Message Retrieval Attempt', 400)

    if id:
        try:
            id_obj = resolver.get_id_obj(id)
        except Exception as e:
            log.error('Exception retrieving id_obj [ID: %s | Exception: %s]' % (id, str(e)))
            return create_json_response(False, 'Exception Occurred, Please Try Again Later.', 500)

        if not id_obj:
            log.error('Unable to retrieve id_obj [ID: %s]' % id)
            return create_json_response(False, 'ID Not Recognized', 404)

        messages = resolver.get_paymentprotocol_messages(id=id)

    if tx_id:
        messages = resolver.get_paymentprotocol_messages(tx_id=tx_id)

    vk = from_sec(request.headers.get('x-identity').decode('hex')) or VerifyingKey.from_der(request.headers.get('x-identity').decode('hex'))
    allowed_keys = [vk.to_der(), to_sec(vk, False), to_sec(vk, True)]

    for transaction_id, tx in messages.iteritems():
        for msg in tx.get('messages', []):
            parsed_msg = parse_paymentprotocol_message(msg)
            if isinstance(parsed_msg, EncryptedProtocolMessage) and (parsed_msg.sender_public_key in allowed_keys or parsed_msg.receiver_public_key in allowed_keys):

                if resolver.delete_paymentprotocol_message(identifier.decode('hex'), message_type, tx_id=transaction_id):
                    log.info('Deleted PaymentProtocol Message [TYPE: %s | TX: %s]' % (message_type.upper(), transaction_id))
                    return create_json_response(True, 'Payment Protocol Message Deleted', 204)

                else:
                    log.info('PaymentProtocol Message Delete Failure [TYPE: %s | TX: %s]' % (message_type.upper(), transaction_id))
                    return create_json_response(False, 'Payment Protocol Message Does Not Exist', 404)

            elif isinstance(parsed_msg, ProtocolMessage) and parsed_msg.message_type == ProtocolMessageType.Value('INVOICE_REQUEST'):

                if parsed_msg.message_type == 'InvoiceRequest' and (parsed_msg.sender_public_key in allowed_keys or id == tx.get('receiver')):

                    if resolver.delete_paymentprotocol_message(identifier.decode('hex'), message_type, tx_id=transaction_id):
                        log.info('Deleted PaymentProtocol Message [TYPE: %s | TX: %s]' % (message_type.upper(), transaction_id))
                        return create_json_response(True, 'Payment Protocol Message Deleted', 204)

                    else:
                        log.info('PaymentProtocol Message Delete Failure [TYPE: %s | TX: %s]' % (message_type.upper(), transaction_id))
                        return create_json_response(False, 'Payment Protocol Message Delete Failed, Try Again Later', 503)

    return create_json_response(False, 'Matching Payment Protocol Message Not Found', 404)


def process_invoicerequest(message, id):

    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)

    if isinstance(message, ProtocolMessage):

        invoice_request = InvoiceRequest()
        invoice_request.ParseFromString(message.serialized_message)

        # Validate Public Key
        vk = from_sec(request.headers.get('x-identity').decode('hex')) or VerifyingKey.from_der(request.headers.get('x-identity').decode('hex'))
        allowed_keys = [vk.to_der(), to_sec(vk, False), to_sec(vk, True)]

        if invoice_request.sender_public_key not in allowed_keys:
            log.warn("InvoiceRequest Public Key Does Not Match X-Identity Public Key")
            return create_json_response(False, 'InvoiceRequest Public Key Does Not Match X-Identity Public Key', 400)

        if invoice_request.pki_type == 'x509+sha256':
            log.debug("InvoiceRequest Contains X509 Certificate, Validating")

            if invoice_request.pki_data and not invoice_request.signature:
                log.warn('Submitted InvoiceRequest Missing Signature')
                return create_json_response(False, 'Requests including x509 cert must include signature', 400)

            # Verify signature if cert and signature are present
            if invoice_request.pki_data and invoice_request.signature:

                try:
                    x509_certs = X509Certificates()
                    x509_certs.ParseFromString(invoice_request.pki_data)

                    cert_data = ssl.DER_cert_to_PEM_cert(x509_certs.certificate[0])
                    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
                except Exception as e:
                    log.warn('Unable to load given x509 certificate [ID: %s]: %s' % (id, str(e)))
                    return create_json_response(False, 'Invalid x509 Certificate', 400)

                try:
                    sig_validate_ir = InvoiceRequest()
                    sig_validate_ir.ParseFromString(message.serialized_message)
                    sig_validate_ir.signature = ""
                    crypto.verify(cert, invoice_request.signature, sig_validate_ir.SerializeToString(), 'sha256')
                    log.info("InvoiceRequest Signature is Valid")
                except Exception as e:
                    log.info('Bad Signature Encountered During Signature Validation [ID: %s]: %s' % (id, str(e)))
                    return create_json_response(False, 'InvoiceRequest Signature Verification Error', 401)

    try:
        log.info('Adding InvoiceRequest %s' % id)
        ret_tx_id = resolver.add_paymentprotocol_message(message, id=id)
        if not ret_tx_id:
            log.error("Unexpected Add InvoiceRequest Failure [ID: %s]" % (id))
            return create_json_response(False, 'Unknown System Error, Please Try Again Later', 503)

        pp_tx_url = '%s/paymentprotocol/%s' % (request.host_url.rstrip('/'), ret_tx_id)
        log.debug('Accepted InvoiceRequest [ID: %s]' % id)
        return create_json_response(status=202, headers={'Access-Control-Expose-Headers': 'Location', 'Location':pp_tx_url})
    except Exception as e:
        log.error("Unexpected exception adding InvoiceRequest [ID: %s]: %s" % (id, str(e)))
        return create_json_response(False, 'Unknown System Error, Please Try Again Later', 503)

def process_paymentrequest(message, id):

    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)
    tx_id = resolver.add_paymentprotocol_message(message, id=id)
    if not tx_id:
        log.warn('No Matching Transaction Found [ID: %s]' % id)
        return create_json_response(False, 'No Matching Transaction Found', 404)

    messages = resolver.get_paymentprotocol_messages(tx_id=tx_id)
    tx_data = messages.values()[0]
    for msg in tx_data['messages']:
        pp_msg = parse_paymentprotocol_message(msg)
        if pp_msg.message_type == ProtocolMessageType.Value('INVOICE_REQUEST') and isinstance(pp_msg, ProtocolMessage):
            ir = InvoiceRequest()
            ir.ParseFromString(pp_msg.serialized_message)
            if ir.notification_url:
                try:
                    notification_headers = {
                        'Content-Type': PP_ENC_MESSAGE_TYPE,
                        'Content-Transfer-Encoding': 'binary'
                    }
                    response = requests.post(ir.notification_url, headers=notification_headers, data=message)
                    if 200 < response.status_code or response.status_code > 299:
                        log.warn('Non-200 HTTP Status Code Returned from Notification URL [URL: %s]' % (ir.notification_url))

                except Exception as e:
                    log.warn('Failure to HTTP GET Notification URL [URL: %s]: %s' % (ir.notification_url, str(e)))
            else:
                break

    log.info('Added PaymentRequest to TX [TX ID: %s]' % tx_id)
    return create_json_response(True, 'Message Accepted')