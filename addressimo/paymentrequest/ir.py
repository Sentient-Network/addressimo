__author__ = 'Matt David'

import copy
import json
import requests
import ssl
import time

from collections import defaultdict
from datetime import datetime
from flask import request, Response
from OpenSSL import crypto

from addressimo.config import config
from addressimo.plugin import PluginManager
from addressimo.storeforward import requires_public_key
from addressimo.util import requires_valid_signature, create_json_response, get_id, LogUtil
from addressimo.validators import *

from addressimo.paymentrequest.paymentrequest_pb2 import ReturnPaymentRequest, InvoiceRequest, X509Certificates

log = LogUtil.setup_logging()

class IR:

    @staticmethod
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
        if request.content_type != 'application/bitcoin-invoicerequest':
            log.warn("InvoiceRequest Endpoint Content-Type IS NOT application/bitcoin-invoicerequest")
            return create_json_response(False, 'InvoiceRequest Content-Type Must Be application/bitcoin-invoicerequest', 400)

        if request.headers.get('Content-Transfer-Encoding','') != 'binary':
            log.warn("InvoiceRequest Endpoint Content-Transfer-Encoding IS NOT set to binary")
            return create_json_response(False, 'InvoiceRequest Content-Transfer-Encoding MUST be binary', 400)

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

        # Validate Nonce
        if not invoice_request.nonce or invoice_request.nonce < (int(time.time() * 1000000) - config.ir_nonce_allowable * 1000000):
            log.warn("InvoiceRequest Nonce Missing or Before %d Seconds Ago" % config.ir_nonce_allowable)
            return create_json_response(False, 'Invalid Nonce', 400, data={'utime': int(time.time() * 1000000)})

        last_nonce = resolver.get_invoicerequest_nonce(invoice_request.sender_public_key.encode('hex'), id_obj.auth_public_key)
        if last_nonce and invoice_request.nonce < last_nonce:
            return create_json_response(False, 'Invalid Nonce', 400, data={'utime': int(time.time() * 1000000)})

        resolver.set_invoicerequest_nonce(invoice_request.sender_public_key.encode('hex'), id_obj.auth_public_key, invoice_request.nonce)

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
            log.info('Adding InvoiceRequest to Queue %s' % id)
            ret_ir_data = resolver.add_invoicerequest(id, ir_data)
            if not ret_ir_data:
                log.error("Unexpected Add InvoiceRequest Failure [ID: %s]" % (id))
                return create_json_response(False, 'Unknown System Error, Please Try Again Later', 500)

            rpr_url = 'https://%s/returnpaymentrequest/%s' % (config.site_url, ret_ir_data['id'])
            log.debug('Accepted InvoiceRequest [ID: %s]' % ret_ir_data['id'])
            return create_json_response(status=202, headers={'Location':rpr_url})
        except Exception as e:
            log.error("Unexpected exception adding InvoiceRequest [ID: %s]: %s" % (id, str(e)))
            return create_json_response(False, 'Unknown System Error, Please Try Again Later', 500)

    @staticmethod
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
            log.error('Unable to Retrieve Queued PR Requests [ID: %s]: %s' % (id, str(e)))
            return create_json_response(False, 'Unable to Retrieve Queued PR Requests', 500)

    @staticmethod
    @requires_public_key
    @requires_valid_signature
    def submit_return_paymentrequest(id):

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
                resolver.add_return_paymentrequest(failed_request)
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
            required_fields = {'id', 'return_payment_request'}
            if not required_fields.issubset(set(ready_request.keys())):
                log.warn("Ready Request Missing Required Fields: id and/or return_payment_request")
                if 'id' in ready_request and ready_request['id']:
                    ready_exceptions[ready_request['id']].append('Missing Required Field return_payment_request')
                else:
                    ready_exceptions['unknown'].append('Missing ready_request id field')
                continue

            # Verify ReturnPaymentRequest is of correct type
            rpr = ReturnPaymentRequest()
            try:
                rpr.ParseFromString(ready_request['return_payment_request'].decode('hex'))
            except Exception as e:
                log.error('Unable to Parse ReturnPaymentRequest: %s' % str(e))
                ready_exceptions[ready_request['id']].append('ReturnPaymentRequest Invalid')
                continue

            # Add Return PR to Redis for later retrieval
            try:
                ready_request['submit_date'] = datetime.utcnow()
                resolver.add_return_paymentrequest(ready_request)
            except Exception as e:
                log.error("Unable to Add Return PR: %s" % str(e))
                ready_exceptions[ready_request['id']].append('Unable to Process Return PaymentRequest')
                continue

            # Notify notification_url if it exists
            try:
                ir_data = resolver.get_invoicerequests(id, ready_request['id'])
                if ir_data and ir_data.get('invoice_request'):

                    ir = InvoiceRequest()
                    ir.ParseFromString(ir_data.get('invoice_request').decode('hex'))
                    if ir.notification_url:
                        try:
                            notification_headers = {
                                'Content-Type': 'application/bitcoin-returnpaymentrequest',
                                'Content-Transfer-Encoding': 'binary'
                            }
                            response = requests.post(ir.notification_url, headers=notification_headers, data=rpr)
                            if 200 < response.status_code or response.status_code > 299:
                                log.warn('Non-200 HTTP Status Code Returned from Notification URL [URL: %s]' % (ir.notification_url))

                        except Exception as e:
                            log.warn('Failure to HTTP GET Notification URL [URL: %s]: %s' % (ir.notification_url, str(e)))
                else:
                    log.warn('No InvoiceRequest Found [Endpoint ID: %s | ID: %s]' % (id, ready_request['id']))

            except Exception as e:
                log.warn("Unable to Parse Original InvoiceRequest [ID: %s]: %s" % (ready_request.get('id'), str(e)))

            # Delete Original IR as it's been fulfilled
            try:
                resolver.delete_invoicerequest(id, ready_request['id'])
            except Exception as e:
                log.warn("Unable to Delete Original InvoiceRequest [ID: %s]: %s" % (ready_request.get('id'), str(e)))

        combined_exceptions = ready_exceptions.copy()
        combined_exceptions.update(fail_exceptions)

        if not combined_exceptions:
            log.info("Accepted %d Return Payment Requests [ID: %s]" % (len(ready_request_list), id))
            return create_json_response(data={"ready_accept_count":len(ready_request_list), "failed_accept_count": len(failed_request_list)})

        error_data = {
            "ready_accept_count": len(ready_request_list) - len(ready_exceptions.keys()),
            "failed_accept_count": len(failed_request_list) - len(fail_exceptions.keys()),
            "failures": combined_exceptions
        }
        return create_json_response(False, 'Submitted Return PaymentRequests contain errors, please see failures field for more information', 400, error_data)


    @staticmethod
    def get_return_paymentrequest(id):

        resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)
        try:
            return_pr = resolver.get_return_paymentrequest(id)
            if not return_pr:
                return create_json_response(False, 'PaymentRequest Not Found or Not Yet Ready', 404, headers={'Retry-After': 120})

            # If there is an error response, return it
            if 'return_payment_request' not in return_pr and 'error_message' in return_pr:
                return create_json_response(False, return_pr['error_message'], int(return_pr['error_code']))

            return Response(response=return_pr['return_payment_request'].decode('hex'), status=200, mimetype='application/bitcoin-returnpaymentrequest', headers={'Content-Transfer-Encoding': 'binary'})
        except Exception as e:
            log.warn("Unable to Get Return PR %s: %s" % (id, str(e)))
            return create_json_response(False, 'PaymentRequest Not Found', 500, headers={'Retry-After': 120})

