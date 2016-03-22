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
from ..plugin import PluginManager
from ..storeforward import requires_public_key
from ..util import requires_valid_signature, create_json_response, get_id, LogUtil, PAYMENT_SIZE_MAX
from ..validators import *

from .paymentrequest_pb2 import EncryptedPaymentRequest, EncryptedInvoiceRequest, InvoiceRequest, X509Certificates, Payment, PaymentACK, EncryptedPayment, EncryptedPaymentACK

log = LogUtil.setup_logging()


class EncryptedMessageValidationError(BaseException):
    pass

class NonceValidationError(BaseException):
    pass

def validate_encrypted_message(msg, sig_key='sender', sig_required=False):

    # Verify Keys in DER Format
    try:
        sender_key = VerifyingKey.from_der(msg.sender_public_key)
    except Exception as e:
        log.warn("sender_public_key NOT in DER Format")
        raise EncryptedMessageValidationError('sender_public_key not in DER format')

    try:
        receiver_key = VerifyingKey.from_der(msg.receiver_public_key)
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
            raise EncryptedMessageValidationError('signature required')

    # Validate Signature
    try:
        sig_verify = msg.signature
        msg.signature = ''
        if sig_key == 'sender':
            sender_key.verify(sig_verify, msg.SerializeToString(), hashfunc=sha256, sigdecode=sigdecode_der)
        elif sig_key == 'receiver':
            receiver_key.verify(sig_verify, msg.SerializeToString(), hashfunc=sha256, sigdecode=sigdecode_der)
        else:
            raise 'Invalid sig_key argument'
        msg.signature = sig_verify
    except Exception as e:
        log.warn('Signature Validation Failed EncryptedInvoiceRequest: %s' % str(e))
        raise EncryptedMessageValidationError('Invalid Signature')


@requires_valid_signature
def submit_invoicerequest(id):

    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)
    try:
        id_obj = resolver.get_id_obj(id)
    except Exception as e:
        log.error('Exception retrieving id_obj [ID: %s | Exception: %s]' % (id, str(e)))
        return create_json_response(False, 'Exception Occurred, Please Try Again Later.', 500)

    if not id_obj:
        log.error('Unable to retrieve id_obj [ID: %s]' % id)
        return create_json_response(False, 'ID Not Recognized', 404)

    # Handle InvoiceRequests
    if not id_obj.ir_only:
        log.warn("InvoiceRequest Endpoint POST Submitted to Non-InvoiceRequest Endpoint")
        return create_json_response(False, 'Invalid InvoiceRequest Endpoint', 400)

    # Validate Content-Type and Binary Data
    if request.content_type not in ['application/bitcoin-invoicerequest', 'application/bitcoin-encrypted-invoicerequest']:
        log.warn("InvoiceRequest Endpoint Content-Type IS NOT application/bitcoin-invoicerequest or application/bitcoin-encrypted-invoicerequest")
        return create_json_response(False, 'InvoiceRequest Content-Type Must Be application/bitcoin-invoicerequest or application/bitcoin-encrypted-invoicerequest', 400)

    if request.headers.get('Content-Transfer-Encoding','') != 'binary':
        log.warn("InvoiceRequest Endpoint Content-Transfer-Encoding IS NOT set to binary")
        return create_json_response(False, 'InvoiceRequest Content-Transfer-Encoding MUST be binary', 400)

    if request.content_type == 'application/bitcoin-encrypted-invoicerequest':

        # Handle EncryptedInvoiceRequests
        log.info("Received EncryptedInvoiceRequest")

        try:
            eir = EncryptedInvoiceRequest()
            eir.ParseFromString(request.get_data())
        except Exception as e:
            log.warn('Unable to Parse EncryptedInvoiceRequest: %s' % str(e))
            return create_json_response(False, 'Invalid EncryptedInvoiceRequest', 400)

        # Validate Public Key(s)
        if request.headers.get('x-identity') != eir.sender_public_key.encode('hex'):
            log.warn("InvoiceRequest Public Key Does Not Match X-Identity Public Key")
            return create_json_response(False, 'InvoiceRequest Public Key Does Not Match X-Identity Public Key', 400)

        # Validate Encrypted Message
        try:
            validate_encrypted_message(eir, sig_key='sender')
        except EncryptedMessageValidationError as e:
            return create_json_response(False, str(e), 400)
        except NonceValidationError as e:
            return create_json_response(False, str(e), 400, data={'utime': int(time.time() * 1000000)})

        # Extra Nonce Validation
        last_nonce = resolver.get_invoicerequest_nonce(eir.sender_public_key.encode('hex'), id_obj.auth_public_key)
        if last_nonce and eir.nonce < last_nonce:
            return create_json_response(False, 'Invalid Nonce', 400, data={'utime': int(time.time() * 1000000)})

        resolver.set_invoicerequest_nonce(eir.sender_public_key.encode('hex'), id_obj.auth_public_key, eir.nonce)

        ir_data = {
            'encrypted_invoice_request': eir.SerializeToString().encode('hex'),
            'submit_date': datetime.utcnow()
        }

    else:

        # Handle InvoiceRequests
        try:
            invoice_request = InvoiceRequest()
            invoice_request.ParseFromString(request.get_data())
        except Exception as e:
            log.warn('Unable to Parse InvoiceRequest: %s' % str(e))
            return create_json_response(False, 'Invalid InvoiceRequest', 400)

        # Validate Public Key
        if request.headers.get('x-identity') != invoice_request.sender_public_key.encode('hex'):
            log.warn("InvoiceRequest Public Key Does Not Match X-Identity Public Key")
            return create_json_response(False, 'InvoiceRequest Public Key Does Not Match X-Identity Public Key', 400)

        # Setup internally stored IR Data
        ir_data = {
            'invoice_request': invoice_request.SerializeToString().encode('hex'),
            'submit_date': datetime.utcnow()
        }

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
                    sig_validate_ir.ParseFromString(request.get_data())
                    sig_validate_ir.signature = ""
                    crypto.verify(cert, invoice_request.signature, sig_validate_ir.SerializeToString(), 'sha1')
                    log.info("InvoiceRequest Signature is Valid")
                except Exception as e:
                    log.info('Bad Signature Encountered During Signature Validation [ID: %s]: %s' % (id, str(e)))
                    return create_json_response(False, 'Signature Verification Error', 401)

    try:
        log.info('Adding InvoiceRequest %s' % id)
        ret_ir_data = resolver.add_invoicerequest(id, ir_data)
        if not ret_ir_data:
            log.error("Unexpected Add InvoiceRequest Failure [ID: %s]" % (id))
            return create_json_response(False, 'Unknown System Error, Please Try Again Later', 500)

        epr_url = 'https://%s/encryptedpaymentrequest/%s' % (config.site_url, ret_ir_data['id'])
        log.debug('Accepted InvoiceRequest [ID: %s]' % ret_ir_data['id'])
        return create_json_response(status=202, headers={'Location':epr_url})
    except Exception as e:
        log.error("Unexpected exception adding InvoiceRequest [ID: %s]: %s" % (id, str(e)))
        return create_json_response(False, 'Unknown System Error, Please Try Again Later', 500)


@requires_public_key
@requires_valid_signature
def get_queued_invoice_requests(id):

    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)
    id_obj = resolver.get_id_obj(get_id())
    if not id_obj:
        return create_json_response(False, 'Invalid Identifier', 404)

    try:
        queued_invoicerequests = resolver.get_invoicerequests(id)
        return create_json_response(data={"count":len(queued_invoicerequests), "requests": queued_invoicerequests})
    except Exception as e:
        log.error('Unable to Retrieve Queued InvoiceRequests [ID: %s]: %s' % (id, str(e)))
        return create_json_response(False, 'Unable to Retrieve Queued InvoiceRequests', 500)


@requires_public_key
@requires_valid_signature
def submit_encrypted_paymentrequest(id):

    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)
    id_obj = resolver.get_id_obj(get_id())
    if not id_obj:
        return create_json_response(False, 'Invalid Identifier', 404)

    if not id_obj.ir_only:
        log.warn("InvoiceRequest Endpoint POST Submitted to Non-InvoiceRequest Endpoint")
        return create_json_response(False, 'Invalid InvoiceRequest Endpoint', 400)

    rdata = request.get_json()
    if not rdata:
        return create_json_response(False, 'Invalid Request', 400)

    ready_request_list = rdata.get('ready_requests', [])
    failed_request_list = rdata.get('failed_requests', [])

    if not ready_request_list and not failed_request_list:
        log.warn('Submitted Request has no ready_requests or failed_requests')
        return create_json_response(False, 'Missing or Empty ready_requests and failed_requests lists', 400)

    if ready_request_list and not isinstance(ready_request_list, list):
        log.warn('Submitted Request Has Invalid ready_requests list')
        return create_json_response(False, 'Missing or Empty ready_requests list', 400)

    if failed_request_list and not isinstance(failed_request_list, list):
        log.warn('Submitted Request Has Invalid failed_requests list')
        return create_json_response(False, 'Missing or Empty failed_requests list', 400)

    # Process Failed Requests
    ready_exceptions = defaultdict(list)
    fail_exceptions = defaultdict(list)

    for failed_request in failed_request_list:

        # Validate Failed Request
        required_fields = {'id', 'error_code', 'error_message'}
        if not required_fields.issubset(set(failed_request.keys())):
            log.warn("Ready Request Missing Required Fields: id, error_code and/or error_message")
            if 'id' in failed_request and failed_request['id']:
                fail_exceptions[failed_request['id']].append('Missing Required Field error_code and/or error_message')
            else:
                fail_exceptions['unknown'].append('Missing failed_request id field')
            continue

        # Verify error_message and error_code are correct types
        if not is_valid_string(failed_request.get('error_message')):
            log.warn('Return Error Message is Invalid: %s' % failed_request.get('error_message'))
            fail_exceptions[failed_request['id']].append('error_message invalid')
            continue


        try:
            int_val = int(failed_request.get('error_code'))
            if not 400 <= int_val < 600:
                raise Exception("Invalid Status Code Range")
        except:
            log.warn('Return Error Code is Invalid: %s' % failed_request.get('error_code'))
            fail_exceptions[failed_request['id']].append('error_code invalid')
            continue

        try:
            failed_request['submit_date'] = datetime.utcnow()
            resolver.add_encrypted_paymentrequest(failed_request)
        except Exception as e:
            log.error("Unable to Add Failure Message for InvoiceRequest")
            fail_exceptions[failed_request['id']].append('Uanble to Process Failure Return Message')
            continue

        # Delete Original IR as it's been fulfilled
        try:
            resolver.delete_invoicerequest(id, failed_request['id'])
        except Exception as e:
            log.warn("Unable to Delete Original InvoiceRequest [ID: %s]: %s" % (failed_request.get('id'), str(e)))

    # Process Ready Requests
    for ready_request in ready_request_list:

        # Validate Ready Request
        required_fields = {'id', 'encrypted_payment_request'}
        if not required_fields.issubset(set(ready_request.keys())):
            log.warn("Ready Request Missing Required Fields: id and/or encrypted_payment_request")
            if 'id' in ready_request and ready_request['id']:
                ready_exceptions[ready_request['id']].append('Missing Required Field encrypted_payment_request')
            else:
                ready_exceptions['unknown'].append('Missing ready_request id field')
            continue

        # Verify EncryptedPaymentRequest Message
        epr = EncryptedPaymentRequest()
        try:
            epr.ParseFromString(ready_request['encrypted_payment_request'].decode('hex'))
        except Exception as e:
            log.error('Unable to Parse EncryptedPaymentRequest: %s' % str(e))
            ready_exceptions[ready_request['id']].append('EncryptedPaymentRequest Invalid')
            continue

        # Validate Encrypted Message
        try:
            validate_encrypted_message(epr, sig_key='receiver')
        except EncryptedMessageValidationError as e:
            ready_exceptions[ready_request['id']].append(str(e))
            continue
        except NonceValidationError as e:
            ready_exceptions[ready_request['id']].append(str(e))
            continue

        # Verify Sender Public Keys Match
        try:
            ir_data = resolver.get_invoicerequests(id, ready_request['id'])
            if ir_data and ir_data.get('invoice_request'):

                ir = InvoiceRequest()
                ir.ParseFromString(ir_data.get('invoice_request').decode('hex'))

                if ir.sender_public_key != epr.sender_public_key:
                    ready_exceptions[ready_request['id']].append('sender_public_key does not match original InvoiceRequest')
                    continue

                # Notify notification_url if available
                if ir.notification_url:
                    try:
                        notification_headers = {
                            'Content-Type': 'application/bitcoin-encrypted-paymentrequest',
                            'Content-Transfer-Encoding': 'binary'
                        }
                        response = requests.post(ir.notification_url, headers=notification_headers, data=epr)
                        if 200 < response.status_code or response.status_code > 299:
                            log.warn('Non-200 HTTP Status Code Returned from Notification URL [URL: %s]' % (ir.notification_url))

                    except Exception as e:
                        log.warn('Failure to HTTP GET Notification URL [URL: %s]: %s' % (ir.notification_url, str(e)))

            elif ir_data and ir_data.get('encrypted_invoice_request'):

                eir = EncryptedInvoiceRequest()
                eir.ParseFromString(ir_data.get('encrypted_invoice_request').decode('hex'))

                # Verify Sender Public Keys Match
                if eir.sender_public_key != epr.sender_public_key:
                    ready_exceptions[ready_request['id']].append('sender_public_key does not match original EncryptedInvoiceRequest')
                    continue
            else:
                log.warn('No InvoiceRequest Found [Endpoint ID: %s | ID: %s]' % (id, ready_request['id']))
                ready_exceptions[ready_request['id']].append('No Associated InvoiceRequest or EncryptedInvoiceRequest found')
                continue

        except Exception as e:
            log.warn("Unable to Parse Original InvoiceRequest [ID: %s]: %s" % (ready_request.get('id'), str(e)))

        # Add EncryptedPaymentRequest to Redis for later retrieval
        try:
            ready_request['submit_date'] = datetime.utcnow()
            resolver.add_encrypted_paymentrequest(ready_request)
        except Exception as e:
            log.error("Unable to Add Return PR: %s" % str(e))
            ready_exceptions[ready_request['id']].append('Unable to Process EncryptedPaymentRequest')
            continue

        # Delete Original IR as it's been fulfilled
        try:
            resolver.delete_invoicerequest(id, ready_request['id'])
        except Exception as e:
            log.warn("Unable to Delete Original InvoiceRequest [ID: %s]: %s" % (ready_request.get('id'), str(e)))

    combined_exceptions = ready_exceptions.copy()
    combined_exceptions.update(fail_exceptions)

    if not combined_exceptions:
        log.info("Accepted %d Encrypted Payment Requests [ID: %s]" % (len(ready_request_list), id))
        return create_json_response(data={"ready_accept_count":len(ready_request_list), "failed_accept_count": len(failed_request_list)})

    error_data = {
        "ready_accept_count": len(ready_request_list) - len(ready_exceptions.keys()),
        "failed_accept_count": len(failed_request_list) - len(fail_exceptions.keys()),
        "failures": combined_exceptions
    }
    return create_json_response(False, 'Submitted EncryptedPaymentRequests contain errors, please see failures field for more information', 400, error_data)


def get_encrypted_paymentrequest(id):

    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)
    try:
        return_pr = resolver.get_encrypted_paymentrequest(id)
        if not return_pr:
            return create_json_response(False, 'PaymentRequest Not Found or Not Yet Ready', 404, headers={'Retry-After': 120})

        # If there is an error response, return it
        if 'encrypted_payment_request' not in return_pr and 'error_message' in return_pr:
            return create_json_response(False, return_pr['error_message'], int(return_pr['error_code']))

        return Response(response=return_pr['encrypted_payment_request'].decode('hex'), status=200, mimetype='application/bitcoin-encrypted-paymentrequest', headers={'Content-Transfer-Encoding': 'binary'})
    except Exception as e:
        log.warn("Unable to Get Return PR %s: %s" % (id, str(e)))
        return create_json_response(False, 'PaymentRequest Not Found', 500, headers={'Retry-After': 120})

def process_payment(id):
    if not request.data:
        log.warn('Serialized Payment Data Missing')
        return create_json_response(False, 'Serialized Payment Data Missing', 400)

    if request.content_type not in ['application/bitcoin-payment', 'application/bitcoin-encrypted-payment']:
        log.warn('Invalid Content-Type Header: %s' % request.headers.get('Content-Type'))
        return create_json_response(False, 'Invalid Content-Type Header. Expecting application/bitcoin-payment or application/bitcoin-encrypted-payment', 400)

    if request.content_type == 'application/bitcoin-payment':
        return process_unencrypted_payment(id)
    elif request.content_type == 'application/bitcoin-encrypted-payment':
        return process_encrypted_payment(id)

def process_encrypted_payment(id):

    if request.content_type != 'application/bitcoin-encrypted-payment':
        log.warn('Invalid Content-Type [ID: %s]' % id)
        return create_json_response(False, 'Invalid Content-Type', 400)

    try:
        ep = EncryptedPayment()
        ep.ParseFromString(request.data)
        validate_encrypted_message(ep, sig_key='sender', sig_required=True)
    except EncryptedMessageValidationError as e:
        return create_json_response(False, str(e), 400)
    except NonceValidationError as e:
        return create_json_response(False, str(e), 400, data={'utime': int(time.time() * 1000000)})
    except Exception as e:
        log.error('Exception Parsing Payment: %s' % str(e))
        return create_json_response(False, 'Exception Parsing EncryptedPayment', 500)

    # Retrieve Associated EncryptedPaymentRequest
    try:
        resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)
        epr_data = resolver.get_encrypted_paymentrequest(id)
    except Exception as e:
        log.error('Error Retrieving EncryptedPaymentRequest for Payment validation [PR ID: %s]: %s' % (id, str(e)))
        return create_json_response(False, 'Error Retrieving EncryptedPaymentRequest', 404)

    if not epr_data or not epr_data.get('encrypted_payment_request'):
        log.warn('Received Payment for Unknown EncryptedPaymentRequest [PR ID: %s]' % id)
        return create_json_response(False, 'Unable to Retrieve EncryptedPaymentRequest associated with Payment', 404)

    try:
        epr = EncryptedPaymentRequest()
        epr.ParseFromString(epr_data.get('encrypted_payment_request').decode('hex'))
    except Exception as e:
        log.warn('Unable to parse EncryptedPaymentRequest [ID: %s]: %s' % (id, str(e)))
        return create_json_response(False, 'Unable to parse original EncryptedPaymentRequest')

    # Verify Sender and Receiver Public Keys
    if ep.sender_public_key != epr.sender_public_key or ep.receiver_public_key != epr.receiver_public_key:
        log.warn('EncryptedPayment Public Keys DO NOT Match Existing EncryptedPaymentRequest Public Keys [ID: %s]' % id)
        return create_json_response(False, 'EncryptedPaymentRequest Public Key Mismatch', 400)

    try:
        ep_data = {
            'encrypted_payment': ep.SerializeToString().encode('hex'),
            'id': id
        }
        resolver.add_encrypted_payment(ep_data)
    except Exception as e:
        log.warn('Unable to Store EncryptedPayment [ID: %s]' % id)
        return create_json_response(False, 'Unable to Store EncryptedPayment, Please Try Again Later', 503)

    return create_json_response(True, 'EncryptedPayment Accepted', 200)

def process_unencrypted_payment(id):

    # Validate Payment POST request follows bip-0070 specification
    if not request.headers.get('Accept') == 'application/bitcoin-paymentack':
        log.warn('Invalid Accept Header: %s' % request.headers.get('Accept'))
        return create_json_response(False, 'Invalid Accept header. Expect application/bitcoin-paymentack', 400)

    if len(request.data) > PAYMENT_SIZE_MAX:
        log.warn('Rejecting Payment for Size [ACCEPTED: %d bytes | ACTUAL: %d bytes]' % (PAYMENT_SIZE_MAX, len(request.data)))
        return create_json_response(False, 'Invalid Payment Submitted', 400)

    # Parse Payment
    try:
        payment = Payment()
        payment.ParseFromString(request.data)
    except Exception as e:
        log.error('Exception Parsing Payment data: %s' % str(e))
        return create_json_response(False, 'Exception Parsing Payment data.', 500)

    if not payment.merchant_data:
        log.warn('Received Payment with Missing merchant_data')
        return create_json_response(False, 'Payment missing merchant_data field.', 400)

    # Validate Payment satisfies associated PaymentRequest conditions
    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)

    try:
        payment_request = resolver.get_payment_request_meta_data(id)

    except Exception as e:
        log.error('Error Retrieving PaymentRequest for Payment validation [PR ID: %s]: %s' % (payment.merchant_data, str(e)))
        return create_json_response(False, 'Error Retrieving PaymentRequest.', 500)

    if not payment_request:
        log.warn('Received Payment for Unknown PaymentRequest [PR ID: %s]' % payment.merchant_data)
        return create_json_response(False, 'Unable to Retrieve PaymentRequest associated with Payment.', 404)

    try:
        payment_validation_addresses = json.loads(payment_request['payment_validation_data'])
    except Exception as e:
        log.warn('Error parsing payment_validation_data [PR ID: %s]: %s' % (payment.merchant_data, str(e)))
        return create_json_response(False, 'Unable to validate Payment.', 400)

    # Validate transactions match addresses and amounts requested in PaymentRequest
    for payment_tx in payment.transactions:
        result = pybitcointools.deserialize(payment_tx)
        for vout in result.get('outs', []):
            address = pybitcointools.script_to_address(vout['script'])
            amount = vout['value']

            if address in payment_validation_addresses.keys() and int(payment_validation_addresses[address]) == int(amount):
                del payment_validation_addresses[address]

    if payment_validation_addresses:
        log.warn('Payment Does Not Satisfy Requirements of PaymentRequest. Rejecting. [PR ID: %s]' % payment.merchant_data)
        return create_json_response(False, 'Payment Does Not Satisfy Requirements of PaymentRequest.', 400)

    bitcoin_tx_hashes = []
    for payment_tx in payment.transactions:
        for _ in range(config.payment_submit_tx_retries):
            try:
                # Necessary evil test code to allow functional testing without submitting (fail) real transactions
                if not request.headers.get('Test-Transaction'):
                    bitcoin_tx_hashes.append(submit_transaction(payment_tx))
                else:
                    bitcoin_tx_hashes.append('testtxhash')

                break
            except Exception as e:
                log.error('Exception Submitting Bitcoin Transaction: %s' % str(e))
                sleep(.3)

    if len(bitcoin_tx_hashes) != len(payment.transactions):
        log.error(
            'Unable To Submit All Payment Transactions To Bitcoin [Payment TX Count: %d | Submitted TX Count: %d]' %
            (len(payment.transactions), len(bitcoin_tx_hashes))
        )

        return create_json_response(
            False,
            'Unable to submit all transactions to the Bitcoin network. Please resubmit Payment.',
            500
        )

    # Store Payment meta data used for Refund request
    for tx_hash in bitcoin_tx_hashes:
        refund_list = [x.script.encode('hex') for x in payment.refund_to]
        try:
            resolver.set_payment_meta_data(tx_hash, payment.memo, refund_list)
        except Exception:
            return create_json_response(False, 'Internal Server Error. Please try again.', 500)

    return create_payment_ack(request.data)

def get_encrypted_payment(id):

    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)
    try:
        return_pr = resolver.get_encrypted_payment(id)
        if not return_pr:
            return create_json_response(False, 'EncryptedPayment Not Found or Not Yet Ready', 404, headers={'Retry-After': 120})

        return Response(response=return_pr['encrypted_payment'].decode('hex'), status=200, mimetype='application/bitcoin-encrypted-payment', headers={'Content-Transfer-Encoding': 'binary'})
    except Exception as e:
        log.warn("Unable to Get EncryptedPayment %s: %s" % (id, str(e)))
        return create_json_response(False, 'EncryptedPayment Not Found', 404, headers={'Retry-After': 120})

def create_payment_ack(payment_data, memo=''):
    headers = {
        'Content-Transfer-Encoding': 'binary'
    }

    payment_ack = PaymentACK()
    payment_ack.payment.ParseFromString(payment_data)
    payment_ack.memo = memo

    log.info('Sending PaymentACK')

    return Response(response=payment_ack.SerializeToString(), status=200, mimetype='application/bitcoin-paymentack', headers=headers)

@requires_public_key
@requires_valid_signature
def retrieve_refund_address(id, tx):

    result = PluginManager.get_plugin('RESOLVER', config.resolver_type).get_refund_address_from_tx_hash(tx)

    if not result:
        log.info('Refund Output Not Found [TX: %s]' % tx)
        return create_json_response(success=False, message='Refund Output Not Found For Submitted TX.', status=404)

    return create_json_response(success=True, data=result, status=200)

def process_encrypted_paymentack(id):

    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)

    # Store & Forward Error Response
    if request.content_type in ['application/json']:
        try:
            json_data = request.get_json()
        except Exception as e:
            return create_json_response(False, 'Unable to Parse JSON', 400)

        required_fields = {'error_code', 'error_message'}
        if not required_fields.issubset(set(json_data.keys())):
            return create_json_response(False, 'Invalid Data. error_code and error_message required', 400)

        # Verify error_message and error_code are correct types
        if not is_valid_string(json_data.get('error_message')):
            log.warn('Payment Error Message is Invalid: %s' % json_data.get('error_message'))
            return create_json_response(False, 'error_message invalid', 400)

        try:
            int_val = int(json_data.get('error_code'))
            if not 400 <= int_val < 600:
                raise Exception("Invalid Status Code Range")
        except:
            log.warn('Payment Error Code is Invalid: %s' % json_data.get('error_code'))
            return create_json_response(False, 'error_code invalid', 400)

        try:
            epa_data = {
                'error_code': int(json_data.get('error_code')),
                'error_message': json_data.get('error_message'),
                'submit_date': datetime.utcnow(),
                'id': id
            }
            resolver.add_encrypted_paymentack(epa_data)
            return create_json_response(True, 'failure data recorded for Payment message')
        except Exception as e:
            log.error("Unable to Add Failure Message for PaymentACK")
            return create_json_response(False, 'Unable to Process Failure PaymentACK Message', 400)

    if request.content_type != 'application/bitcoin-encrypted-paymentack':
        log.warn('Content-type Incorrect [ID: %s]' % id)
        return create_json_response(False, 'Invalid Content-Type', 400)

    try:
        epa = EncryptedPaymentACK()
        epa.ParseFromString(request.data)
        validate_encrypted_message(epa, sig_key='receiver')
    except EncryptedMessageValidationError as e:
        return create_json_response(False, str(e), 400)
    except NonceValidationError as e:
        return create_json_response(False, str(e), 400, data={'utime': int(time.time() * 1000000)})
    except Exception as e:
        log.error('Exception Parsing EncryptedPaymentAck: %s' % str(e))
        return create_json_response(False, 'Exception Parsing EncryptedPaymentAck', 500)

    # Retrieve Associated EncryptedPaymentRequest
    try:
        epr_data = resolver.get_encrypted_paymentrequest(id)
    except Exception as e:
        log.error('Error Retrieving EncryptedPaymentRequest for EncryptedPaymentAck validation [PR ID: %s]: %s' % (id, str(e)))
        return create_json_response(False, 'Error Retrieving EncryptedPaymentRequest', 404)

    if not epr_data or not epr_data.get('encrypted_payment_request'):
        log.warn('Received EncryptedPaymentAck for Unknown EncryptedPaymentRequest [PR ID: %s]' % id)
        return create_json_response(False, 'Unable to Retrieve EncryptedPaymentRequest associated with EncryptedPaymentAck', 404)

    try:
        epr = EncryptedPaymentRequest()
        epr.ParseFromString(epr_data.get('encrypted_payment_request').decode('hex'))
    except Exception as e:
        log.warn('Unable to parse EncryptedPaymentRequest [ID: %s]: %s' % (id, str(e)))
        return create_json_response(False, 'Unable to parse original EncryptedPaymentRequest')

    # Verify Sender and Receiver Public Keys
    if epa.sender_public_key != epr.sender_public_key or epa.receiver_public_key != epr.receiver_public_key:
        log.warn('EncryptedPaymentACK Public Keys DO NOT Match Existing EncryptedPaymentRequest Public Keys [ID: %s]' % id)
        return create_json_response(False, 'EncryptedPaymentAck Public Key Mismatch', 400)

    try:
        epa_data = {
            'encrypted_paymentack': epa.SerializeToString().encode('hex'),
            'id': id
        }
        resolver.add_encrypted_paymentack(epa_data)
    except Exception as e:
        log.warn('Unable to Store EncryptedPaymentAck [ID: %s]' % id)
        return create_json_response(False, 'Unable to Store EncryptedPaymentAck, Please Try Again Later', 503)

    return create_json_response(True, 'EncryptedPaymentAck Accepted', 200)

def get_encrypted_paymentack(id):

    resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)
    try:
        return_pr = resolver.get_encrypted_paymentack(id)
        if not return_pr:
            return create_json_response(False, 'EncryptedPaymentAck Not Found or Not Yet Ready', 404, headers={'Retry-After': 120})

        # If there is an error response, return it
        if 'encrypted_paymentack' not in return_pr and 'error_message' in return_pr:
            return create_json_response(False, return_pr['error_message'], int(return_pr['error_code']))

        return Response(response=return_pr['encrypted_paymentack'].decode('hex'), status=200, mimetype='application/bitcoin-encrypted-paymentack', headers={'Content-Transfer-Encoding': 'binary'})
    except Exception as e:
        log.warn("Unable to Get EncryptedPaymentAck %s: %s" % (id, str(e)))
        return create_json_response(False, 'EncryptedPaymentAck Not Found', 503, headers={'Retry-After': 120})