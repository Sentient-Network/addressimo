__author__ = 'mdavid'

# System Imports
import hashlib
from mock import MagicMock, Mock, patch
from test import AddressimoTestCase

from ecdsa import SigningKey, curves
from ecdsa.util import sigencode_der, sigdecode_der

from addressimo.paymentprotocol import *

TEST_PRIVKEY = '9d5a020344dd6dffc8a79e9c0bce8148ab0bce08162b6a44fec40cb113e16647'
TEST_PUBKEY = 'ac79cd6b0ac5f2a6234996595cb2d91fceaa0b9d9a6495f12f1161c074587bd19ae86928bddea635c930c09ea9c7de1a6a9c468f9afd18fbaeed45d09564ded6'

SENDER_CERT = '''
-----BEGIN CERTIFICATE-----
MIIEjzCCA3egAwIBAgIJAIVQlqMNwBXHMA0GCSqGSIb3DQEBCwUAMIGLMQswCQYD
VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIGA1UEBxMLTG9zIEFuZ2Vs
ZXMxFTATBgNVBAoTDE5ldGtpIFNlbmRlcjEVMBMGA1UEAxMMTmV0a2kgU2VuZGVy
MSMwIQYJKoZIhvcNAQkBFhRvcGVuc291cmNlQG5ldGtpLmNvbTAeFw0xNTExMjMy
MzM2MjFaFw0yNTExMjAyMzM2MjFaMIGLMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
Q2FsaWZvcm5pYTEUMBIGA1UEBxMLTG9zIEFuZ2VsZXMxFTATBgNVBAoTDE5ldGtp
IFNlbmRlcjEVMBMGA1UEAxMMTmV0a2kgU2VuZGVyMSMwIQYJKoZIhvcNAQkBFhRv
cGVuc291cmNlQG5ldGtpLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAL96JZwop5I3kOsZFNiqWd86A+jyKU/X/xKYdwcMq9Sto4dYXWIh3vUKZVZX
y6P9kZhQ0RX2jlqN1uEijpD3JDkTpEQzyAEcH3PBG7R/BH9xVyWhitBCnW3Wv44d
GOOwYkvaY5BSTos4Kkowao2LxWhLYnPUMc9jwiNX0EWFE2ltPMb6404mINtuqVnz
Cp5b2sS7Xk0CnC1GsHVH/pc1/9ec2CVWVGxZ10aBCeWVtBOz0O5DBMRNaBbYYGr4
aLjS/1EFs1Gk2DpfdHWEmERtiTmt5K3bgn+CnpdQAxI5REhRsmAhvugDuohdlUQp
mbRCGM4SXntseX/R3HonEM2Lz88CAwEAAaOB8zCB8DAdBgNVHQ4EFgQUSrzo15NC
vWnKvQ3k9ckWnNsmbk4wgcAGA1UdIwSBuDCBtYAUSrzo15NCvWnKvQ3k9ckWnNsm
bk6hgZGkgY4wgYsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRQw
EgYDVQQHEwtMb3MgQW5nZWxlczEVMBMGA1UEChMMTmV0a2kgU2VuZGVyMRUwEwYD
VQQDEwxOZXRraSBTZW5kZXIxIzAhBgkqhkiG9w0BCQEWFG9wZW5zb3VyY2VAbmV0
a2kuY29tggkAhVCWow3AFccwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAsdzjZv2D8ufZ2wDUS9n1I+70Zhs792/lpKK6ml1b6goie12nBE6R3g4ljLiw
yxSDRV24gzRq4YMn6OZIsvrW8D/hk3tMVKPx94etImnRCw3Z6pDyl/Bhca6alC7X
fPmTc32vjiKsf3I0yauz4IhS4P/vuQdkVAVj6o29hy84C5kRrFsdP1/aR6RDKxCJ
D3/lKhBf9K0we7bljjBwdIu6DS4DfbL/tm9CnrMz7EdkaZtoZXLOi1uRYTyWoyY8
sO2reNRhJ8m9Pvhg5lxURwDz8VgTMA6nc+2854DClXWTfqK7HsdfNq4BXn9sOwPO
gKJacJl27b+w1/V04aZ+xFgwXQ==
-----END CERTIFICATE-----
'''

SENDER_CERT_PRIVKEY = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAv3olnCinkjeQ6xkU2KpZ3zoD6PIpT9f/Eph3Bwyr1K2jh1hd
YiHe9QplVlfLo/2RmFDRFfaOWo3W4SKOkPckOROkRDPIARwfc8EbtH8Ef3FXJaGK
0EKdbda/jh0Y47BiS9pjkFJOizgqSjBqjYvFaEtic9Qxz2PCI1fQRYUTaW08xvrj
TiYg226pWfMKnlvaxLteTQKcLUawdUf+lzX/15zYJVZUbFnXRoEJ5ZW0E7PQ7kME
xE1oFthgavhouNL/UQWzUaTYOl90dYSYRG2JOa3krduCf4Kel1ADEjlESFGyYCG+
6AO6iF2VRCmZtEIYzhJee2x5f9HceicQzYvPzwIDAQABAoIBABIdRCGZ1wCGMTeM
j+RPeWEc4/HNtwrOrFreAaSxFjBwnN/ZBDycZ7NW4G9iruk8u+FlA+LICH+Ym5OA
6WvddZfQu+GX5Hv2ZSNWSYCx44MK/euZdMBvDOWvQz/2kLw5m5MBfhnRL40MKzQJ
kIsDhhFv0EiU8oFkNqGRVSq+hC+c9BO+cCTSrgZ0fSkZJnx80IZFd2/IZTBxgsnX
F0vGPDY/VLRgOC8paT4pcR3PxW0ZlSEoiW7B3rztpZynY9g7wnkrHamlYH9mHret
jNx49gAs3gW02FeNt0cJOtfxe+3u8no8zFPZeb0ca6GfshNMdtScFqeJCtGVoD/W
IJo//QECgYEA4tlHJpNCRDJQ+VDA26Hq/pKh2LBQbvcEeFfQQZDY3eMFetyLysgh
1ZFSYqz3NAgsXPOTfmk2z0D9SEhHVS/h9DaIb3dhIdpSGvrbiXBnC22sJ9G7qwBZ
hh/NsBqZHuuf+9hHPELAerHNxjlc2CRKC39yZ7MeLAjCg/yI+lBXz1ECgYEA2BU8
qRs6SfNVsXTzcHzM0C06UYjiMsr1Ht9KG2D5YDOJXnPcL9G8x5auhJFwc585Z6Tl
68tC9rJUjFBmZx9BMzMIYQ3/6GMVBlQqr/EvBNoXnQrpa0yzjItOt1Y/3LcVdBZA
o6asuMtoI69+USEKdk4si/BJlLTP2RdI2LQDJR8CgYAumcIDC6dGSSvXO56Sv919
dHPpBrdPRFFXw3pVrcLPOi7LAXl6K8i/jb3l5XBW8QLkCWmYQ1buFoSxj5+PwWli
eL1oYJbElIvfXP8yabPRZjNCbtRlmYnKgsgHUD96WZ8g5loj5/aQfewut2P6RuIr
IIBJC0O8egQzhvJAsbaIMQKBgAyU7/tIwpQbvxmeHa6nFaXpfEPTHJioiK1Lgx0l
AGBBn/YH+QIvzDYy5+aAMXQKCWWnjFu2cie7KoEhDVVj1IAOsKY2EniNjGPZ8sJb
4Mj/ifBy+jRtOucsFWFHfGB1qKIhyZG92sDH10B8r3Y53koVMzLSwvYNsSyK1osH
sEcxAoGBAJDHBlIFSWwkDX/fV1H1VeX1vYi+Idi5iHkM3yTC52Yc6ilNs1KmbCx4
VLEc0GeytAzZecOdrQH5XGjWjqi3RDjxsp52yfL8xWkcKgMmdfBIAsSKNrl5ih6c
UYQnomt1/nv3xH9Q93gV4j0OF+G4IguID62mrqCq72Ca7i6TgnON
-----END RSA PRIVATE KEY-----
'''

class TestValidateEncryptedMessage(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.VerifyingKey')
        self.mockVerifyingKey = self.patcher1.start()

        self.sender_sk = SigningKey.generate(curve=curves.SECP256k1)
        self.receiver_sk = SigningKey.generate(curve=curves.SECP256k1)

        self.eir = EncryptedInvoiceRequest()
        self.eir.sender_public_key = self.sender_sk.get_verifying_key().to_der()
        self.eir.receiver_public_key = self.receiver_sk.get_verifying_key().to_der()
        self.eir.encrypted_invoice_request = 'deadbeef'.decode('hex')
        self.eir.invoice_request_hash = hashlib.sha256('deadbeef'.decode('hex')).digest()
        self.eir.nonce = int(time.time()*1000000)
        self.eir.signature = ''

        sig = self.sender_sk.sign(self.eir.SerializeToString(), hashfunc=sha256, sigencode=sigencode_der)
        self.eir.signature = sig

    def test_go_right(self):

        checkData = EncryptedInvoiceRequest()
        checkData.CopyFrom(self.eir)
        checkData.signature = ''

        validate_encrypted_message(self.eir, sig_key='sender', sig_required=True)

        self.assertEqual(2, self.mockVerifyingKey.from_der.call_count)
        self.assertEqual(self.eir.sender_public_key, self.mockVerifyingKey.from_der.call_args_list[0][0][0])
        self.assertEqual(self.eir.receiver_public_key, self.mockVerifyingKey.from_der.call_args_list[1][0][0])

        self.assertEqual(1, self.mockVerifyingKey.from_der.return_value.verify.call_count)
        self.assertEqual(self.eir.signature, self.mockVerifyingKey.from_der.return_value.verify.call_args[0][0])
        self.assertEqual(checkData.SerializeToString(), self.mockVerifyingKey.from_der.return_value.verify.call_args[0][1])
        self.assertEqual(sha256, self.mockVerifyingKey.from_der.return_value.verify.call_args[1]['hashfunc'])
        self.assertEqual(sigdecode_der, self.mockVerifyingKey.from_der.return_value.verify.call_args[1]['sigdecode'])

    def test_sender_key_invalid_format(self):

        self.mockVerifyingKey.from_der.side_effect = Exception()
        try:
            validate_encrypted_message(self.eir)
            self.fail('Expected Exception')
        except EncryptedMessageValidationError as e:
            self.assertEqual('sender_public_key not in DER format', str(e))

        self.assertEqual(1, self.mockVerifyingKey.from_der.call_count)
        self.assertEqual(self.eir.sender_public_key, self.mockVerifyingKey.from_der.call_args_list[0][0][0])
        self.assertEqual(0, self.mockVerifyingKey.from_der.return_value.verify.call_count)

    def test_receiver_key_invalid_format(self):

        self.mockVerifyingKey.from_der.side_effect = [None, Exception()]

        self.eir.receiver_public_key = self.receiver_sk.get_verifying_key().to_string()
        try:
            validate_encrypted_message(self.eir)
            self.fail('Expected Exception')
        except EncryptedMessageValidationError as e:
            self.assertEqual('receiver_public_key not in DER format', str(e))

        self.assertEqual(2, self.mockVerifyingKey.from_der.call_count)
        self.assertEqual(self.eir.sender_public_key, self.mockVerifyingKey.from_der.call_args_list[0][0][0])
        self.assertEqual(self.eir.receiver_public_key, self.mockVerifyingKey.from_der.call_args_list[1][0][0])
        self.assertEqual(0, self.mockVerifyingKey.from_der.return_value.verify.call_count)

    def test_nonce_behind_server_time(self):

        self.eir.nonce = 10000000

        try:
            validate_encrypted_message(self.eir)
            self.fail('Expected Exception')
        except NonceValidationError as e:
            self.assertEqual('Invalid Nonce', str(e))

    def test_go_right_no_sig_not_required(self):

        checkData = EncryptedInvoiceRequest()
        checkData.CopyFrom(self.eir)
        checkData.signature = ''

        self.eir.signature = ''
        validate_encrypted_message(self.eir, sig_key='sender', sig_required=False)

        self.assertEqual(2, self.mockVerifyingKey.from_der.call_count)
        self.assertEqual(self.eir.sender_public_key, self.mockVerifyingKey.from_der.call_args_list[0][0][0])
        self.assertEqual(self.eir.receiver_public_key, self.mockVerifyingKey.from_der.call_args_list[1][0][0])

        self.assertEqual(0, self.mockVerifyingKey.from_der.return_value.verify.call_count)

    def test_go_right_no_sig_required(self):

        checkData = EncryptedInvoiceRequest()
        checkData.CopyFrom(self.eir)
        checkData.signature = ''

        self.eir.signature = ''
        try:
            validate_encrypted_message(self.eir, sig_key='sender', sig_required=True)
            self.fail('Exception Expected')
        except EncryptedMessageValidationError as e:
            self.assertEqual('signature required', str(e))

        self.assertEqual(2, self.mockVerifyingKey.from_der.call_count)
        self.assertEqual(self.eir.sender_public_key, self.mockVerifyingKey.from_der.call_args_list[0][0][0])
        self.assertEqual(self.eir.receiver_public_key, self.mockVerifyingKey.from_der.call_args_list[1][0][0])

        self.assertEqual(0, self.mockVerifyingKey.from_der.return_value.verify.call_count)

class TestSubmitInvoiceRequest(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher2 = patch('addressimo.paymentprotocol.create_json_response')
        self.patcher3 = patch('addressimo.paymentprotocol.request')
        self.patcher4 = patch('addressimo.paymentprotocol.datetime')
        self.patcher5 = patch('addressimo.paymentprotocol.crypto')
        self.patcher6 = patch('addressimo.paymentprotocol.VerifyingKey')
        self.patcher7 = patch('addressimo.paymentprotocol.validate_encrypted_message')

        self.mockPluginManager = self.patcher1.start()
        self.mockCreateJsonResponse = self.patcher2.start()
        self.mockRequest = self.patcher3.start()
        self.mockDatetime = self.patcher4.start()
        self.mockCrypto = self.patcher5.start()
        self.mockVerifyingKey = self.patcher6.start()
        self.mockValidateEncryptedMessage = self.patcher7.start()

        # Setup Go Right Data
        self.sender_sk = SigningKey.generate(curve=curves.SECP256k1)
        self.receiver_sk = SigningKey.generate(curve=curves.SECP256k1)
        self.x509_sender_cert = crypto.load_certificate(crypto.FILETYPE_PEM, SENDER_CERT)
        self.x509_sender_cert_privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, SENDER_CERT_PRIVKEY)

        self.invoice_request = InvoiceRequest()
        self.invoice_request.sender_public_key = self.sender_sk.get_verifying_key().to_der()
        # self.invoice_request.nonce = int(time.time() * 1000000)
        self.invoice_request.amount = 75
        self.invoice_request.pki_type = 'x509+sha256'

        sender_certs = X509Certificates()
        sender_certs.certificate.append(ssl.PEM_cert_to_DER_cert(crypto.dump_certificate(crypto.FILETYPE_PEM, self.x509_sender_cert)))
        self.invoice_request.pki_data = sender_certs.SerializeToString()
        self.invoice_request.notification_url = 'https://notify.me/longId'
        self.invoice_request.signature = ""

        # Handle x509 Signature
        sig = crypto.sign(self.x509_sender_cert_privkey, self.invoice_request.SerializeToString(), 'sha1')
        self.invoice_request.signature = sig

        self.ret_ir_data = {"id": "ir_id"}

        self.mock_id_obj = Mock()
        self.mock_id_obj.ir_only = True
        self.mock_id_obj.auth_public_key = 'receiverAuthPubKey'

        self.mockGetIRNonce = MagicMock()
        self.mockSetIRNonce = MagicMock()
        self.mockGetIRNonce.return_value = int(time.time() * 1000000) - 1000000

        self.mockPluginManager.get_plugin.return_value.get_id_obj.return_value = self.mock_id_obj
        self.mockPluginManager.get_plugin.return_value.add_invoicerequest.return_value = self.ret_ir_data
        self.mockPluginManager.get_plugin.return_value.get_invoicerequest_nonce = self.mockGetIRNonce
        self.mockPluginManager.get_plugin.return_value.set_invoicerequest_nonce = self.mockSetIRNonce
        self.mockDatetime.utcnow.return_value = datetime(2015, 6, 13, 2, 43, 0)

        self.mockRequest.headers = {'x-identity': self.sender_sk.get_verifying_key().to_der().encode('hex'), 'Content-Transfer-Encoding': 'binary'}
        self.mockRequest.content_type = 'application/bitcoin-invoicerequest'
        self.mockRequest.get_data.return_value = self.invoice_request.SerializeToString()
        self.mockRequest.url = 'test_url'
        self.mockRequest.data = 'test_data'

        #################################################################
        # Mock to Pass @requires_valid_signature
        self.patcher100 = patch('addressimo.util.get_id')
        self.patcher101 = patch('addressimo.util.VerifyingKey')
        self.patcher102 = patch('addressimo.util.request')

        self.mockGetId = self.patcher100.start()
        self.mockSigVerifyingKey = self.patcher101.start()
        self.mockUtilRequest = self.patcher102.start()

        self.mockRequest.headers['x-signature'] = 'sigF'.encode('hex')
        self.mockSigVerifyingKey.from_string.return_value.verify.return_value = True

    def test_go_right(self):

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(2, self.mockRequest.get_data.call_count)
        self.assertEqual(1, self.mockDatetime.utcnow.call_count)

        # # Validate Nonce Checking
        # self.assertEqual(1, self.mockGetIRNonce.call_count)
        # self.assertEqual(self.sender_sk.get_verifying_key().to_string().encode('hex'), self.mockGetIRNonce.call_args[0][0])
        # self.assertEqual('receiverAuthPubKey', self.mockGetIRNonce.call_args[0][1])
        # self.assertEqual(1, self.mockSetIRNonce.call_count)
        # self.assertEqual(self.sender_sk.get_verifying_key().to_string().encode('hex'), self.mockSetIRNonce.call_args[0][0])
        # self.assertEqual('receiverAuthPubKey', self.mockSetIRNonce.call_args[0][1])
        # self.assertEqual(self.invoice_request.nonce, self.mockSetIRNonce.call_args[0][2])

        self.assertEqual(1, self.mockCrypto.load_certificate.call_count)
        self.assertEqual(self.mockCrypto.FILETYPE_PEM, self.mockCrypto.load_certificate.call_args[0][0])
        self.assertEqual(SENDER_CERT.strip(), self.mockCrypto.load_certificate.call_args[0][1].strip())

        self.assertEqual(1, self.mockCrypto.verify.call_count)
        self.assertEqual(self.mockCrypto.load_certificate.return_value, self.mockCrypto.verify.call_args[0][0])
        self.assertEqual(self.invoice_request.signature, self.mockCrypto.verify.call_args[0][1])

        sigIR = InvoiceRequest()
        sigIR.MergeFrom(self.invoice_request)
        sigIR.signature = ""
        self.assertEqual(sigIR.SerializeToString(), self.mockCrypto.verify.call_args[0][2])
        self.assertEqual("sha1", self.mockCrypto.verify.call_args[0][3])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_args[0][0])

        ir_data = self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_args[0][1]
        self.assertEqual(self.invoice_request.SerializeToString().encode('hex'), ir_data['invoice_request'])
        self.assertEqual(datetime(2015,6,13,2,43,0), ir_data['submit_date'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertEqual(202, self.mockCreateJsonResponse.call_args[1]['status'])
        self.assertIn('Location', self.mockCreateJsonResponse.call_args[1]['headers'])
        self.assertEqual('https://%s/encryptedpaymentrequest/ir_id' % config.site_url, self.mockCreateJsonResponse.call_args[1]['headers']['Location'])

    def test_go_right_encrypted(self):

        eir = EncryptedInvoiceRequest()
        eir.sender_public_key = self.sender_sk.get_verifying_key().to_der()
        eir.receiver_public_key = self.receiver_sk.get_verifying_key().to_der()
        eir.encrypted_invoice_request = 'deadbeef'.decode('hex')
        eir.invoice_request_hash = hashlib.sha256('deadbeef'.decode('hex')).digest()
        eir.nonce = int(time.time()*1000000)
        eir.signature = ''

        sig = self.sender_sk.sign(eir.SerializeToString(), hashfunc=sha256, sigencode=sigencode_der)
        eir.signature = sig

        self.mockRequest.content_type = 'application/bitcoin-encrypted-invoicerequest'
        self.mockRequest.get_data.return_value = eir.SerializeToString()

        result = submit_invoicerequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_data.call_count)
        self.assertEqual(1, self.mockDatetime.utcnow.call_count)

        # Verify Signature Validation
        checkData = EncryptedInvoiceRequest()
        checkData.ParseFromString(eir.SerializeToString())
        checkData.signature = ''
        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_args[0][0])

        ir_data = self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_args[0][1]
        self.assertEqual(eir.SerializeToString().encode('hex'), ir_data['encrypted_invoice_request'])
        self.assertEqual(datetime(2015,6,13,2,43,0), ir_data['submit_date'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertEqual(202, self.mockCreateJsonResponse.call_args[1]['status'])
        self.assertIn('Location', self.mockCreateJsonResponse.call_args[1]['headers'])
        self.assertEqual('https://%s/encryptedpaymentrequest/ir_id' % config.site_url, self.mockCreateJsonResponse.call_args[1]['headers']['Location'])

    def test_encrypted_message_validation_fail(self):

        eir = EncryptedInvoiceRequest()
        eir.sender_public_key = self.sender_sk.get_verifying_key().to_string()
        eir.receiver_public_key = self.receiver_sk.get_verifying_key().to_der()
        eir.encrypted_invoice_request = 'deadbeef'.decode('hex')
        eir.invoice_request_hash = hashlib.sha256('deadbeef'.decode('hex')).digest()
        eir.nonce = 10000000

        self.mockRequest.content_type = 'application/bitcoin-encrypted-invoicerequest'
        self.mockRequest.get_data.return_value = eir.SerializeToString()
        self.mockRequest.headers = {'x-identity': self.sender_sk.get_verifying_key().to_string().encode('hex'), 'Content-Transfer-Encoding': 'binary'}

        self.mockValidateEncryptedMessage.side_effect = EncryptedMessageValidationError('eir validation error')

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_data.call_count)
        self.assertEqual(0, self.mockDatetime.utcnow.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('eir validation error', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_encrypted_message_none_validation_fail(self):

        eir = EncryptedInvoiceRequest()
        eir.sender_public_key = self.sender_sk.get_verifying_key().to_string()
        eir.receiver_public_key = self.receiver_sk.get_verifying_key().to_der()
        eir.encrypted_invoice_request = 'deadbeef'.decode('hex')
        eir.invoice_request_hash = hashlib.sha256('deadbeef'.decode('hex')).digest()
        eir.nonce = 10000000

        self.mockRequest.content_type = 'application/bitcoin-encrypted-invoicerequest'
        self.mockRequest.get_data.return_value = eir.SerializeToString()
        self.mockRequest.headers = {'x-identity': self.sender_sk.get_verifying_key().to_string().encode('hex'), 'Content-Transfer-Encoding': 'binary'}

        self.mockValidateEncryptedMessage.side_effect = NonceValidationError('nonce validation error')

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_data.call_count)
        self.assertEqual(0, self.mockDatetime.utcnow.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('nonce validation error', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertIn('utime', self.mockCreateJsonResponse.call_args[1]['data'])

    def test_nonce_behind_last_nonce(self):

        eir = EncryptedInvoiceRequest()
        eir.sender_public_key = self.sender_sk.get_verifying_key().to_der()
        eir.receiver_public_key = self.receiver_sk.get_verifying_key().to_der()
        eir.encrypted_invoice_request = 'deadbeef'.decode('hex')
        eir.invoice_request_hash = hashlib.sha256('deadbeef'.decode('hex')).digest()
        eir.nonce = 10000000

        self.mockRequest.content_type = 'application/bitcoin-encrypted-invoicerequest'
        self.mockRequest.get_data.return_value = eir.SerializeToString()

        self.mockGetIRNonce.return_value = int(time.time() * 1000000) + 5000000

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_data.call_count)
        self.assertEqual(0, self.mockDatetime.utcnow.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid Nonce', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertIn('utime', self.mockCreateJsonResponse.call_args[1]['data'])

    def test_id_obj_resolve_exception(self):

        self.mockPluginManager.get_plugin.return_value.get_id_obj.side_effect = Exception()

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockRequest.get_json.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Exception Occurred, Please Try Again Later.', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])

    def test_no_id_obj(self):

        self.mockPluginManager.get_plugin.return_value.get_id_obj.return_value = None

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockRequest.get_json.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('ID Not Recognized', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_ir_only_flag_false(self):

        self.mock_id_obj.ir_only = False

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockRequest.get_json.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid InvoiceRequest Endpoint', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_incorrect_content_type(self):

        self.mockRequest.content_type = 'application/json'

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockRequest.get_json.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('InvoiceRequest Content-Type Must Be application/bitcoin-invoicerequest or application/bitcoin-encrypted-invoicerequest', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_incorrect_transfer_encoding_header(self):

        self.mockRequest.headers['Content-Transfer-Encoding'] = 'not_binary'

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockRequest.get_json.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('InvoiceRequest Content-Transfer-Encoding MUST be binary', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_missing_invoicerequest_data(self):

        self.mockRequest.get_data.return_value = None

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_data.call_count)
        self.assertEqual(0, self.mockDatetime.utcnow.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid InvoiceRequest', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_public_key_mismatch(self):

        self.invoice_request.sender_public_key = "fbfbfbfb42"
        self.mockRequest.get_data.return_value = self.invoice_request.SerializeToString()

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_data.call_count)
        self.assertEqual(0, self.mockDatetime.utcnow.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('InvoiceRequest Public Key Does Not Match X-Identity Public Key', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_missing_signature(self):

        self.invoice_request.signature = ""
        self.mockRequest.get_data.return_value = self.invoice_request.SerializeToString()

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_data.call_count)
        self.assertEqual(1, self.mockDatetime.utcnow.call_count)

        self.assertEqual(0, self.mockCrypto.load_certificate.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Requests including x509 cert must include signature', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_cert_load_exception(self):

        self.mockCrypto.load_certificate.side_effect = Exception()

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_data.call_count)
        self.assertEqual(1, self.mockDatetime.utcnow.call_count)

        self.assertEqual(1, self.mockCrypto.load_certificate.call_count)
        self.assertEqual(self.mockCrypto.FILETYPE_PEM, self.mockCrypto.load_certificate.call_args[0][0])
        self.assertEqual(SENDER_CERT.strip(), self.mockCrypto.load_certificate.call_args[0][1].strip())

        self.assertEqual(0, self.mockCrypto.verify.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid x509 Certificate', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_signture_verification_failure(self):

        self.mockCrypto.verify.side_effect = Exception()

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(2, self.mockRequest.get_data.call_count)
        self.assertEqual(1, self.mockDatetime.utcnow.call_count)

        self.assertEqual(1, self.mockCrypto.load_certificate.call_count)
        self.assertEqual(self.mockCrypto.FILETYPE_PEM, self.mockCrypto.load_certificate.call_args[0][0])
        self.assertEqual(SENDER_CERT.strip(), self.mockCrypto.load_certificate.call_args[0][1].strip())

        self.assertEqual(1, self.mockCrypto.verify.call_count)
        self.assertEqual(self.mockCrypto.load_certificate.return_value, self.mockCrypto.verify.call_args[0][0])
        self.assertEqual(self.invoice_request.signature, self.mockCrypto.verify.call_args[0][1])

        sigIR = InvoiceRequest()
        sigIR.MergeFrom(self.invoice_request)
        sigIR.signature = ""
        self.assertEqual(sigIR.SerializeToString(), self.mockCrypto.verify.call_args[0][2])
        self.assertEqual("sha1", self.mockCrypto.verify.call_args[0][3])

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Signature Verification Error', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(401, self.mockCreateJsonResponse.call_args[0][2])

    def test_add_invoicerequest_missing_return_data(self):

        self.mockPluginManager.get_plugin.return_value.add_invoicerequest.return_value = None

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(2, self.mockRequest.get_data.call_count)
        self.assertEqual(1, self.mockDatetime.utcnow.call_count)

        self.assertEqual(1, self.mockCrypto.load_certificate.call_count)
        self.assertEqual(self.mockCrypto.FILETYPE_PEM, self.mockCrypto.load_certificate.call_args[0][0])
        self.assertEqual(SENDER_CERT.strip(), self.mockCrypto.load_certificate.call_args[0][1].strip())

        self.assertEqual(1, self.mockCrypto.verify.call_count)
        self.assertEqual(self.mockCrypto.load_certificate.return_value, self.mockCrypto.verify.call_args[0][0])
        self.assertEqual(self.invoice_request.signature, self.mockCrypto.verify.call_args[0][1])

        sigIR = InvoiceRequest()
        sigIR.MergeFrom(self.invoice_request)
        sigIR.signature = ""
        self.assertEqual(sigIR.SerializeToString(), self.mockCrypto.verify.call_args[0][2])
        self.assertEqual("sha1", self.mockCrypto.verify.call_args[0][3])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_args[0][0])

        ir_data = self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_args[0][1]
        self.assertEqual(self.invoice_request.SerializeToString().encode('hex'), ir_data['invoice_request'])
        self.assertEqual(datetime(2015,6,13,2,43,0), ir_data['submit_date'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unknown System Error, Please Try Again Later', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])

    def test_add_invoicerequest_exception(self):

        self.mockPluginManager.get_plugin.return_value.add_invoicerequest.side_effect = Exception()

        result = submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(2, self.mockRequest.get_data.call_count)
        self.assertEqual(1, self.mockDatetime.utcnow.call_count)

        self.assertEqual(1, self.mockCrypto.load_certificate.call_count)
        self.assertEqual(self.mockCrypto.FILETYPE_PEM, self.mockCrypto.load_certificate.call_args[0][0])
        self.assertEqual(SENDER_CERT.strip(), self.mockCrypto.load_certificate.call_args[0][1].strip())

        self.assertEqual(1, self.mockCrypto.verify.call_count)
        self.assertEqual(self.mockCrypto.load_certificate.return_value, self.mockCrypto.verify.call_args[0][0])
        self.assertEqual(self.invoice_request.signature, self.mockCrypto.verify.call_args[0][1])

        sigIR = InvoiceRequest()
        sigIR.MergeFrom(self.invoice_request)
        sigIR.signature = ""
        self.assertEqual(sigIR.SerializeToString(), self.mockCrypto.verify.call_args[0][2])
        self.assertEqual("sha1", self.mockCrypto.verify.call_args[0][3])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_args[0][0])

        ir_data = self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_args[0][1]
        self.assertEqual(self.invoice_request.SerializeToString().encode('hex'), ir_data['invoice_request'])
        self.assertEqual(datetime(2015,6,13,2,43,0), ir_data['submit_date'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unknown System Error, Please Try Again Later', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])

class TestGetQueuedInvoiceRequests(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher2 = patch('addressimo.paymentprotocol.create_json_response')
        self.patcher3 = patch('addressimo.paymentprotocol.request')

        self.mockPluginManager = self.patcher1.start()
        self.mockCreateJsonResponse = self.patcher2.start()
        self.mockRequest = self.patcher3.start()

        # Setup Go Right Data
        self.queued_irs = [{"id": "id1"}, {"id": "id2"}]

        self.mock_id_obj = Mock()
        self.mock_id_obj.ir_only = True
        self.mockPluginManager.get_plugin.return_value.get_invoicerequests.return_value = self.queued_irs

        #################################################################
        # Mock to Pass @requires_valid_signature & @requires_public_key
        self.patcher100 = patch('addressimo.storeforward.get_id')
        self.patcher101 = patch('addressimo.util.VerifyingKey')
        self.patcher102 = patch('addressimo.storeforward.request')
        self.patcher103 = patch('addressimo.storeforward.PluginManager')
        self.patcher104 = patch('addressimo.util.get_id')
        self.patcher105 = patch('addressimo.util.request')

        self.mockGetId = self.patcher100.start()
        self.mockVerifyingKey = self.patcher101.start()
        self.mockIntRequest = self.patcher102.start()
        self.mockIntPluginManager = self.patcher103.start()
        self.mockIntGetId = self.patcher104.start()
        self.mockUtilRequest = self.patcher105.start()

        self.mockUtilRequest.headers = {
            'x-signature': 'sigF'.encode('hex'),
            'x-identity': TEST_PUBKEY
        }
        self.mockVerifyingKey.from_string.return_value.verify.return_value = True
        self.mockIdObj = Mock()
        self.mockIdObj.auth_public_key = TEST_PUBKEY
        self.mockIdObj.presigned_payment_requests = ['pr1', 'pr2']
        self.mockIntPluginManager.get_plugin.return_value.get_id_obj.return_value = self.mockIdObj
        self.mockIntRequest.headers = {"x-identity": TEST_PUBKEY}

    def test_go_right(self):

        get_queued_invoice_requests('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_args[0][0])
        self.assertEqual(1, self.mockCreateJsonResponse.call_count)

        resp_data = self.mockCreateJsonResponse.call_args[1]['data']
        self.assertIsNotNone(resp_data)
        self.assertEqual(2, resp_data.get('count'))
        self.assertIn({"id":"id1"}, resp_data.get('requests'))
        self.assertIn({"id":"id2"}, resp_data.get('requests'))

    def test_invalid_id(self):

        self.mockPluginManager.get_plugin.return_value.get_id_obj.return_value = None

        get_queued_invoice_requests('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_count)
        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid Identifier', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_get_irs_exception(self):

        self.mockPluginManager.get_plugin.return_value.get_invoicerequests.side_effect = Exception()

        get_queued_invoice_requests('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_args[0][0])
        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unable to Retrieve Queued InvoiceRequests', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])

class TestSubmitEncryptedPaymentRequest(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher2 = patch('addressimo.paymentprotocol.create_json_response')
        self.patcher3 = patch('addressimo.paymentprotocol.request')
        self.patcher4 = patch('addressimo.paymentprotocol.datetime')
        self.patcher5 = patch('addressimo.paymentprotocol.requests')
        self.patcher6 = patch('addressimo.paymentprotocol.validate_encrypted_message')

        self.mockPluginManager = self.patcher1.start()
        self.mockCreateJsonResponse = self.patcher2.start()
        self.mockRequest = self.patcher3.start()
        self.mockDatetime = self.patcher4.start()
        self.mockRequests = self.patcher5.start()
        self.mockValidateEncryptedMessage = self.patcher6.start()

        # Setup Go Right Data
        epr1 = EncryptedPaymentRequest()
        epr1.encrypted_payment_request = 'encrypted_payment_request'.encode('hex')
        epr1.sender_public_key = 'sender_public_key'.encode('hex')
        epr1.receiver_public_key = 'receiver_public_key'.encode('hex')
        epr1.payment_request_hash = 'payment_request_hash'.encode('hex')
        epr1.nonce = 1234567890

        epr2 = EncryptedPaymentRequest()
        epr2.encrypted_payment_request = 'encrypted_payment_request'.encode('hex')
        epr2.sender_public_key = 'sender_public_key'.encode('hex')
        epr2.receiver_public_key = 'receiver_public_key'.encode('hex')
        epr2.payment_request_hash = 'payment_request_hash'.encode('hex')
        epr2.nonce = 1234567890

        self.mockRequest.get_json.return_value = {
            "ready_requests": [
                {"id":"id1", "encrypted_payment_request": epr1.SerializeToString().encode('hex')},
                {"id":"id2", "encrypted_payment_request": epr2.SerializeToString().encode('hex')},
            ]
        }

        self.mock_id_obj = Mock()
        self.mock_id_obj.ir_only = True
        self.mockDatetime.utcnow.return_value = 'utcnow'

        # Setup notification URL tests
        self.mockIR = InvoiceRequest()
        self.mockIR.sender_public_key = 'sender_public_key'.encode('hex')
        self.mockIR.notification_url = "https://webhook.endpoint.com/rpr/d34db33f"

        self.mockPluginManager.get_plugin.return_value.get_invoicerequests.return_value = {
            'invoice_request': self.mockIR.SerializeToString().encode('hex')
        }

        self.mockRequests.post.return_value = MagicMock()
        self.mockRequests.post.return_value.status_code = 200

        #################################################################
        # Mock to Pass @requires_valid_signature & @requires_public_key
        self.patcher100 = patch('addressimo.storeforward.get_id')
        self.patcher101 = patch('addressimo.util.VerifyingKey')
        self.patcher102 = patch('addressimo.storeforward.request')
        self.patcher103 = patch('addressimo.storeforward.PluginManager')
        self.patcher104 = patch('addressimo.util.get_id')
        self.patcher105 = patch('addressimo.util.request')

        self.mockGetId = self.patcher100.start()
        self.mockVerifyingKey = self.patcher101.start()
        self.mockIntRequest = self.patcher102.start()
        self.mockIntPluginManager = self.patcher103.start()
        self.mockIntGetId = self.patcher104.start()
        self.mockUtilRequest = self.patcher105.start()

        self.mockUtilRequest.headers = {
            'x-signature': 'sigF'.encode('hex'),
            'x-identity': TEST_PUBKEY
        }
        self.mockVerifyingKey.from_string.return_value.verify.return_value = True
        self.mockIdObj = Mock()
        self.mockIdObj.auth_public_key = TEST_PUBKEY
        self.mockIdObj.presigned_payment_requests = ['pr1', 'pr2']
        self.mockIntPluginManager.get_plugin.return_value.get_id_obj.return_value = self.mockIdObj
        self.mockIntRequest.headers = {"x-identity": TEST_PUBKEY}

    def test_go_right(self):

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value
        self.assertEqual('utcnow', json_data['ready_requests'][0]['submit_date'])
        self.assertEqual(json_data['ready_requests'][0], add_pr_call.call_args_list[0][0][0])

        self.assertEqual('utcnow', json_data['ready_requests'][1]['submit_date'])
        self.assertEqual(json_data['ready_requests'][1], add_pr_call.call_args_list[1][0][0])

        self.assertEqual(2, self.mockValidateEncryptedMessage.call_count)

        # Verify Notification URL
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_count)
        self.assertEqual(2, self.mockRequests.post.call_count)
        self.assertEqual(self.mockIR.notification_url, self.mockRequests.post.call_args[0][0])
        self.assertIn('Content-Type', self.mockRequests.post.call_args[1]['headers'])
        self.assertEqual('application/bitcoin-encrypted-paymentrequest', self.mockRequests.post.call_args[1]['headers']['Content-Type'])
        self.assertIn('Content-Transfer-Encoding', self.mockRequests.post.call_args[1]['headers'])
        self.assertEqual('binary', self.mockRequests.post.call_args[1]['headers']['Content-Transfer-Encoding'])

        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][0])
        self.assertEqual('id1', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][1])
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[1][0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[1][0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertEqual(2, self.mockCreateJsonResponse.call_args[1]['data']['ready_accept_count'])
        self.assertEqual(0, self.mockCreateJsonResponse.call_args[1]['data']['failed_accept_count'])

    def test_go_right_original_encrypted_invoicerequest(self):

        self.mockEIR = EncryptedInvoiceRequest()
        self.mockEIR.sender_public_key = 'sender_public_key'.encode('hex')
        self.mockEIR.receiver_public_key = 'receiver_public_key'.encode('hex')
        self.mockEIR.encrypted_invoice_request = 'deadbeef'.decode('hex')
        self.mockEIR.invoice_request_hash = 'deadbeef'.decode('hex')
        self.mockEIR.nonce = 10000000

        self.mockPluginManager.get_plugin.return_value.get_invoicerequests.return_value = {
            'encrypted_invoice_request': self.mockEIR.SerializeToString().encode('hex')
        }

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value
        self.assertEqual('utcnow', json_data['ready_requests'][0]['submit_date'])
        self.assertEqual(json_data['ready_requests'][0], add_pr_call.call_args_list[0][0][0])

        self.assertEqual('utcnow', json_data['ready_requests'][1]['submit_date'])
        self.assertEqual(json_data['ready_requests'][1], add_pr_call.call_args_list[1][0][0])

        self.assertEqual(2, self.mockValidateEncryptedMessage.call_count)

        # Verify Notification URL
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_count)
        self.assertEqual(0, self.mockRequests.post.call_count)

        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][0])
        self.assertEqual('id1', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][1])
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[1][0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[1][0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertEqual(2, self.mockCreateJsonResponse.call_args[1]['data']['ready_accept_count'])
        self.assertEqual(0, self.mockCreateJsonResponse.call_args[1]['data']['failed_accept_count'])

    def test_go_right_original_encrypted_invoicerequest_sender_key_mismatch(self):

        self.mockEIR = EncryptedInvoiceRequest()
        self.mockEIR.sender_public_key = 'not_the_sender_public_key'.encode('hex')
        self.mockEIR.receiver_public_key = 'receiver_public_key'.encode('hex')
        self.mockEIR.encrypted_invoice_request = 'deadbeef'.decode('hex')
        self.mockEIR.invoice_request_hash = 'deadbeef'.decode('hex')
        self.mockEIR.nonce = 10000000

        self.mockPluginManager.get_plugin.return_value.get_invoicerequests.return_value = {
            'encrypted_invoice_request': self.mockEIR.SerializeToString().encode('hex')
        }

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        self.assertEqual(2, self.mockValidateEncryptedMessage.call_count)

        # Verify Notification URL
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_count)
        self.assertEqual(0, self.mockRequests.post.call_count)

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertEqual(0, self.mockCreateJsonResponse.call_args[0][3]['ready_accept_count'])
        self.assertEqual(0, self.mockCreateJsonResponse.call_args[0][3]['failed_accept_count'])
        self.assertEqual('sender_public_key does not match original EncryptedInvoiceRequest', self.mockCreateJsonResponse.call_args[0][3]['failures']['id1'][0])
        self.assertEqual('sender_public_key does not match original EncryptedInvoiceRequest', self.mockCreateJsonResponse.call_args[0][3]['failures']['id2'][0])

    def test_go_right_no_notification_url(self):

        self.mockIR.notification_url = ""

        self.mockPluginManager.get_plugin.return_value.get_invoicerequests.return_value = {
            'invoice_request': self.mockIR.SerializeToString().encode('hex')
        }

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value
        self.assertEqual('utcnow', json_data['ready_requests'][0]['submit_date'])
        self.assertEqual(json_data['ready_requests'][0], add_pr_call.call_args_list[0][0][0])

        self.assertEqual('utcnow', json_data['ready_requests'][1]['submit_date'])
        self.assertEqual(json_data['ready_requests'][1], add_pr_call.call_args_list[1][0][0])

        # Verify Notification URL
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_count)
        self.assertEqual(0, self.mockRequests.post.call_count)

        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][0])
        self.assertEqual('id1', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][1])
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[1][0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[1][0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertEqual(2, self.mockCreateJsonResponse.call_args[1]['data']['ready_accept_count'])
        self.assertEqual(0, self.mockCreateJsonResponse.call_args[1]['data']['failed_accept_count'])

    def test_go_right_missing_invoice_request(self):

        self.mockPluginManager.get_plugin.return_value.get_invoicerequests.return_value = None

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        # Verify Notification URL
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_count)
        self.assertEqual(0, self.mockRequests.post.call_count)

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual(1, self.mockCreateJsonResponse.call_count)

        jdata = self.mockCreateJsonResponse.call_args[0][3]
        self.assertEqual(0, jdata['ready_accept_count'])
        self.assertEqual(0, jdata['failed_accept_count'])
        self.assertEqual(2, len(jdata['failures']))
        self.assertEqual('No Associated InvoiceRequest or EncryptedInvoiceRequest found', jdata['failures']['id1'][0])
        self.assertEqual('No Associated InvoiceRequest or EncryptedInvoiceRequest found', jdata['failures']['id2'][0])

    def test_go_right_failure_only(self):

        self.mockRequest.get_json.return_value = {
            "failed_requests": [
                {"id":"id1", "error_code": "406", "error_message": "amount too high"},
                {"id":"id2", "error_code": 409, "error_message": "amount invalid"},
            ]
        }

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value
        self.assertEqual('utcnow', json_data['failed_requests'][0]['submit_date'])
        self.assertEqual(json_data['failed_requests'][0], add_pr_call.call_args_list[0][0][0])

        self.assertEqual('utcnow', json_data['failed_requests'][1]['submit_date'])
        self.assertEqual(json_data['failed_requests'][1], add_pr_call.call_args_list[1][0][0])

        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][0])
        self.assertEqual('id1', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][1])
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[1][0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[1][0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertEqual(0, self.mockCreateJsonResponse.call_args[1]['data']['ready_accept_count'])
        self.assertEqual(2, self.mockCreateJsonResponse.call_args[1]['data']['failed_accept_count'])

    def test_failure_missing_fields(self):

        self.mockRequest.get_json.return_value = {
            "failed_requests": [
                {"id":"id1", "error_code": "406", "error_message": "amount too high"},
                {"id":"id2", "error_message": "amount invalid"},
            ]
        }

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value
        self.assertEqual('utcnow', json_data['failed_requests'][0]['submit_date'])
        self.assertEqual(json_data['failed_requests'][0], add_pr_call.call_args_list[0][0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][0])
        self.assertEqual('id1', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual(0, self.mockCreateJsonResponse.call_args[0][3]['ready_accept_count'])
        self.assertEqual(1, self.mockCreateJsonResponse.call_args[0][3]['failed_accept_count'])
        self.assertEqual(1, len(self.mockCreateJsonResponse.call_args[0][3]['failures']))

    def test_failure_invalid_error_message(self):

        self.mockRequest.get_json.return_value = {
            "failed_requests": [
                {"id":"id1", "error_code": "406", "error_message": "amount too high();"},
                {"id":"id2", "error_code": 406, "error_message": "amount invalid"},
            ]
        }

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value
        self.assertEqual('utcnow', json_data['failed_requests'][1]['submit_date'])
        self.assertEqual(json_data['failed_requests'][1], add_pr_call.call_args_list[0][0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual(0, self.mockCreateJsonResponse.call_args[0][3]['ready_accept_count'])
        self.assertEqual(1, self.mockCreateJsonResponse.call_args[0][3]['failed_accept_count'])
        self.assertEqual(1, len(self.mockCreateJsonResponse.call_args[0][3]['failures']))

    def test_failure_bad_error_code(self):

        self.mockRequest.get_json.return_value = {
            "failed_requests": [
                {"id":"id1", "error_code": "406", "error_message": "amount too high"},
                {"id":"id2", "error_code": 700, "error_message": "amount invalid"},
            ]
        }

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value
        self.assertEqual('utcnow', json_data['failed_requests'][0]['submit_date'])
        self.assertEqual(json_data['failed_requests'][0], add_pr_call.call_args_list[0][0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][0])
        self.assertEqual('id1', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual(0, self.mockCreateJsonResponse.call_args[0][3]['ready_accept_count'])
        self.assertEqual(1, self.mockCreateJsonResponse.call_args[0][3]['failed_accept_count'])
        self.assertEqual(1, len(self.mockCreateJsonResponse.call_args[0][3]['failures']))

    def test_failure_add_epr_exception(self):

        self.mockRequest.get_json.return_value = {
            "failed_requests": [
                {"id":"id1", "error_code": "406", "error_message": "amount too high"},
                {"id":"id2", "error_code": 406, "error_message": "amount invalid"},
            ]
        }
        self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.side_effect = Exception()

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value
        self.assertEqual('utcnow', json_data['failed_requests'][0]['submit_date'])
        self.assertEqual(json_data['failed_requests'][0], add_pr_call.call_args_list[0][0][0])

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual(0, self.mockCreateJsonResponse.call_args[0][3]['ready_accept_count'])
        self.assertEqual(0, self.mockCreateJsonResponse.call_args[0][3]['failed_accept_count'])
        self.assertEqual(2, len(self.mockCreateJsonResponse.call_args[0][3]['failures']))

    def test_missing_id_obj(self):

        self.mockPluginManager.get_plugin.return_value.get_id_obj.return_value = None

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockRequest.get_json.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid Identifier', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_not_ir_only(self):

        self.mockPluginManager.get_plugin.return_value.get_id_obj.return_value.ir_only = False

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockRequest.get_json.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid InvoiceRequest Endpoint', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_request_not_json(self):

        self.mockRequest.get_json.return_value = None

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid Request', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_missing_ready_requests(self):

        del self.mockRequest.get_json.return_value['ready_requests']
        self.mockRequest.get_json.return_value['key'] = 'value'

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Missing or Empty ready_requests and failed_requests lists', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_empty_ready_requests(self):

        self.mockRequest.get_json.return_value['ready_requests'] = []

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Missing or Empty ready_requests and failed_requests lists', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_ready_requests_non_list(self):

        self.mockRequest.get_json.return_value['ready_requests'] = 'bob'

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Missing or Empty ready_requests list', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_failed_requests_non_list(self):

        self.mockRequest.get_json.return_value['failed_requests'] = 'bob'

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Missing or Empty failed_requests list', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_missing_id_required_field(self):

        del self.mockRequest.get_json.return_value['ready_requests'][0]['id']

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value

        self.assertNotIn('submit_data', json_data['ready_requests'][0])
        self.assertEqual('utcnow', json_data['ready_requests'][1]['submit_date'])
        self.assertEqual(json_data['ready_requests'][1], add_pr_call.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Submitted EncryptedPaymentRequests contain errors, please see failures field for more information', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual(1, self.mockCreateJsonResponse.call_args[0][3]['ready_accept_count'])
        self.assertEqual('Missing ready_request id field', self.mockCreateJsonResponse.call_args[0][3]['failures']['unknown'][0])

    def test_missing_id_required_field_failed_request(self):

        self.mockRequest.get_json.return_value = {
            "failed_requests": [
                {"error_code": "406", "error_message": "amount too high"},
                {"id":"id2", "error_code": 409, "error_message": "amount invalid"},
            ]
        }

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value

        self.assertNotIn('submit_data', json_data['failed_requests'][0])
        self.assertEqual('utcnow', json_data['failed_requests'][1]['submit_date'])
        self.assertEqual(json_data['failed_requests'][1], add_pr_call.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Submitted EncryptedPaymentRequests contain errors, please see failures field for more information', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual(1, self.mockCreateJsonResponse.call_args[0][3]['failed_accept_count'])
        self.assertEqual('Missing failed_request id field', self.mockCreateJsonResponse.call_args[0][3]['failures']['unknown'][0])

    def test_missing_rpr_required_field(self):

        del self.mockRequest.get_json.return_value['ready_requests'][0]['encrypted_payment_request']

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value

        self.assertNotIn('submit_data', json_data['ready_requests'][0])
        self.assertEqual('utcnow', json_data['ready_requests'][1]['submit_date'])
        self.assertEqual(json_data['ready_requests'][1], add_pr_call.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Submitted EncryptedPaymentRequests contain errors, please see failures field for more information', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual(1, self.mockCreateJsonResponse.call_args[0][3]['ready_accept_count'])
        self.assertEqual('Missing Required Field encrypted_payment_request', self.mockCreateJsonResponse.call_args[0][3]['failures']['id1'][0])

    def test_missing_fail_required_field(self):

        self.mockRequest.get_json.return_value = {
            "failed_requests": [
                {"id":"id1", "error_message": "amount too high"},
                {"id":"id2", "error_code": 409, "error_message": "amount invalid"},
            ]
        }

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value

        self.assertNotIn('submit_data', json_data['failed_requests'][0])
        self.assertEqual('utcnow', json_data['failed_requests'][1]['submit_date'])
        self.assertEqual(json_data['failed_requests'][1], add_pr_call.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Submitted EncryptedPaymentRequests contain errors, please see failures field for more information', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual(1, self.mockCreateJsonResponse.call_args[0][3]['failed_accept_count'])
        self.assertEqual('Missing Required Field error_code and/or error_message', self.mockCreateJsonResponse.call_args[0][3]['failures']['id1'][0])


    def test_add_return_pr_exception(self):

        self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.side_effect = [Exception('Test Error'), True]

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value
        self.assertEqual('utcnow', json_data['ready_requests'][0]['submit_date'])
        self.assertEqual(json_data['ready_requests'][0], add_pr_call.call_args_list[0][0][0])

        self.assertEqual('utcnow', json_data['ready_requests'][1]['submit_date'])
        self.assertEqual(json_data['ready_requests'][1], add_pr_call.call_args_list[1][0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Submitted EncryptedPaymentRequests contain errors, please see failures field for more information', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual(1, self.mockCreateJsonResponse.call_args[0][3]['ready_accept_count'])
        self.assertEqual('Unable to Process EncryptedPaymentRequest', self.mockCreateJsonResponse.call_args[0][3]['failures']['id1'][0])

    def test_delete_ir_exception(self):

        self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.side_effect = Exception()

        submit_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentrequest
        json_data = self.mockRequest.get_json.return_value
        self.assertEqual('utcnow', json_data['ready_requests'][0]['submit_date'])
        self.assertEqual(json_data['ready_requests'][0], add_pr_call.call_args_list[0][0][0])

        self.assertEqual('utcnow', json_data['ready_requests'][1]['submit_date'])
        self.assertEqual(json_data['ready_requests'][1], add_pr_call.call_args_list[1][0][0])

        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][0])
        self.assertEqual('id1', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[0][0][1])
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[1][0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args_list[1][0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertEqual(2, self.mockCreateJsonResponse.call_args[1]['data']['ready_accept_count'])
        self.assertEqual(0, self.mockCreateJsonResponse.call_args[1]['data']['failed_accept_count'])

class TestGetEncryptedPaymentRequest(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher2 = patch('addressimo.paymentprotocol.Response')
        self.patcher3 = patch('addressimo.paymentprotocol.create_json_response')

        self.mockPluginManager = self.patcher1.start()
        self.mockResponse = self.patcher2.start()
        self.mockCreateJsonResponse = self.patcher3.start()

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.return_value = {
            'encrypted_payment_request': 'encrypted_payment_request'.encode('hex')
        }

    def test_go_right(self):

        get_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_args[0][0])

        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual('encrypted_payment_request', self.mockResponse.call_args[1]['response'])
        self.assertEqual(200, self.mockResponse.call_args[1]['status'])
        self.assertEqual('application/bitcoin-encrypted-paymentrequest', self.mockResponse.call_args[1]['mimetype'])
        self.assertEqual({'Content-Transfer-Encoding': 'binary'}, self.mockResponse.call_args[1]['headers'])

    def test_no_return_pr(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.return_value = None

        get_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_args[0][0])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('PaymentRequest Not Found or Not Yet Ready', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_error_return(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.return_value = {
            'error_code': '406',
            'error_message': 'Amount not possible'
        }

        get_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_args[0][0])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Amount not possible', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(406, self.mockCreateJsonResponse.call_args[0][2])

    def test_get_return_pr_exception(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.side_effect = Exception()

        get_encrypted_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_args[0][0])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('PaymentRequest Not Found', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])
        
class TestProcessPayment(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.request')
        self.patcher2 = patch('addressimo.paymentprotocol.create_json_response')
        self.patcher3 = patch('addressimo.paymentprotocol.process_unencrypted_payment')
        self.patcher4 = patch('addressimo.paymentprotocol.process_encrypted_payment')

        self.mockRequest = self.patcher1.start()
        self.mockCreateJsonResponse = self.patcher2.start()
        self.mockProcessUnencryptedPayment = self.patcher3.start()
        self.mockProcessEncryptedPayment = self.patcher4.start()

        self.mockRequest.content_type = 'application/bitcoin-payment'

    def test_request_data_missing(self):

        # Setup test case
        self.mockRequest.data = None

        process_payment('id')

        # Validate call counts
        self.assertEqual(1, self.mockCreateJsonResponse.call_count)

        # Validate create_json_response args
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Serialized Payment Data Missing', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_invalid_content_type_header(self):

        # Setup test case
        self.mockRequest.content_type = 'application/json'

        process_payment('id')

        # Validate call counts
        self.assertEqual(1, self.mockCreateJsonResponse.call_count)

        # Validate create_json_response args
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual(
            'Invalid Content-Type Header. Expecting application/bitcoin-payment or application/bitcoin-encrypted-payment',
            self.mockCreateJsonResponse.call_args[0][1]
        )
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_go_right_unencrypted(self):

        process_payment('id')

        self.assertEqual(0, self.mockCreateJsonResponse.call_count)
        self.assertEqual(1, self.mockProcessUnencryptedPayment.call_count)
        self.assertEqual(0, self.mockProcessEncryptedPayment.call_count)

    def test_go_right_encrypted(self):

        self.mockRequest.content_type = 'application/bitcoin-encrypted-payment'

        process_payment('id')

        self.assertEqual(0, self.mockCreateJsonResponse.call_count)
        self.assertEqual(1, self.mockProcessEncryptedPayment.call_count)
        self.assertEqual(0, self.mockProcessUnencryptedPayment.call_count)

class TestProcessEncryptedPayment(AddressimoTestCase):

    def setUp(self):

        self.patcher2 = patch('addressimo.paymentprotocol.request')
        self.patcher3 = patch('addressimo.paymentprotocol.create_json_response')
        self.patcher4 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher5 = patch('addressimo.paymentprotocol.validate_encrypted_message')

        self.mockRequest = self.patcher2.start()
        self.mockCreateJsonResponse = self.patcher3.start()
        self.mockPluginManager = self.patcher4.start()
        self.mockValidateEncryptedMessage = self.patcher5.start()

        self.epr = EncryptedPaymentRequest()
        self.epr.sender_public_key = 'sender_public_key'.encode('hex')
        self.epr.receiver_public_key = 'receiver_public_key'.encode('hex')
        self.epr.nonce = 100000000
        self.epr.encrypted_payment_request = 'deadbeef'
        self.epr.payment_request_hash = 'deadbeef'

        self.ep = EncryptedPayment()
        self.ep.sender_public_key = 'sender_public_key'.encode('hex')
        self.ep.receiver_public_key = 'receiver_public_key'.encode('hex')
        self.ep.nonce = 100000000
        self.ep.encrypted_payment = 'deadbeef'
        self.ep.payment_hash = 'deadbeef'
        self.ep.signature = 'deadbeef'

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.return_value = {
            'id': 'txid',
            'encrypted_payment_request': self.epr.SerializeToString().encode('hex')
        }
        self.mockRequest.data = self.ep.SerializeToString()
        self.mockRequest.content_type = 'application/bitcoin-encrypted-payment'

    def test_go_right(self):

        process_encrypted_payment('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.ep, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_encrypted_payment.call_count)
        self.assertEqual(self.ep.SerializeToString().encode('hex'), self.mockPluginManager.get_plugin.return_value.add_encrypted_payment.call_args[0][0]['encrypted_payment'])
        self.assertEqual('txid', self.mockPluginManager.get_plugin.return_value.add_encrypted_payment.call_args[0][0]['id'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertTrue(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('EncryptedPayment Accepted', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(200, self.mockCreateJsonResponse.call_args[0][2])

    def test_invalid_content_type(self):

        self.mockRequest.content_type = 'application/json'

        process_encrypted_payment('txid')

        self.assertEqual(0, self.mockValidateEncryptedMessage.call_count)

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid Content-Type', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_validate_ep_error(self):

        self.mockValidateEncryptedMessage.side_effect = EncryptedMessageValidationError('error text')

        process_encrypted_payment('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.ep, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_payment.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('error text', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_validate_nonce_error(self):

        self.mockValidateEncryptedMessage.side_effect = NonceValidationError('error text')

        process_encrypted_payment('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.ep, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_payment.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('error text', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertIn('utime', self.mockCreateJsonResponse.call_args[1]['data'])

    def test_ep_parse_error(self):

        self.mockValidateEncryptedMessage.side_effect = Exception('error text')

        process_encrypted_payment('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.ep, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_payment.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Exception Parsing EncryptedPayment', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])

    def test_epr_retrieve_error(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.side_effect = Exception()

        process_encrypted_payment('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.ep, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_payment.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Error Retrieving EncryptedPaymentRequest', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_no_epr_data(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.return_value = {}

        process_encrypted_payment('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.ep, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_payment.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unable to Retrieve EncryptedPaymentRequest associated with Payment', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_no_epr_data_field(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.return_value = {'id': 'payment_request'}

        process_encrypted_payment('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.ep, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_payment.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unable to Retrieve EncryptedPaymentRequest associated with Payment', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_mismatched_sender_public_key(self):

        self.ep.sender_public_key = 'not_sender_public_key'.encode('hex')
        self.mockRequest.data = self.ep.SerializeToString()

        process_encrypted_payment('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.ep, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_payment.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('EncryptedPaymentRequest Public Key Mismatch', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_mismatched_receiver_public_key(self):

        self.ep.receiver_public_key = 'not_receiver_public_key'.encode('hex')
        self.mockRequest.data = self.ep.SerializeToString()

        process_encrypted_payment('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.ep, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_payment.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('EncryptedPaymentRequest Public Key Mismatch', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

class TestProcessUnencryptedPayment(AddressimoTestCase):

    def setUp(self):
        self.patcher1 = patch('addressimo.paymentprotocol.request')
        self.patcher2 = patch('addressimo.paymentprotocol.create_json_response')
        self.patcher3 = patch('addressimo.paymentprotocol.Payment')
        self.patcher4 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher5 = patch('addressimo.paymentprotocol.pybitcointools')
        self.patcher6 = patch('addressimo.paymentprotocol.submit_transaction')
        self.patcher7 = patch('addressimo.paymentprotocol.create_payment_ack')

        self.mockRequest = self.patcher1.start()
        self.mockCreateJSONResponse = self.patcher2.start()
        self.mockPayment = self.patcher3.start()
        self.mockPluginManager = self.patcher4.start()
        self.mockPyBitcoinTools = self.patcher5.start()
        self.mockSubmitBitcoinTransaction = self.patcher6.start()
        self.mockCreatePaymentAck = self.patcher7.start()

        # Setup request data
        self.mockRequest.headers = {
            'Content-Type': 'application/bitcoin-payment',
            'Accept': 'application/bitcoin-paymentack'
        }

        # Setup payment_request data for validation of Payment
        self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.return_value = {
            'payment_validation_data': '%s' % json.dumps({'address': 100})
        }

        # Setup Payment object
        self.mockPaymentObj = Mock()
        self.mockPaymentObj.merchant_data = 'uuid'
        self.mockPaymentObj.transactions = ['tx1', 'tx2']
        self.mockPaymentObj.memo = 'memo'

        refund_obj = Mock()
        refund_obj.script = 'script'

        self.mockPaymentObj.refund_to = [refund_obj]
        self.mockPayment.return_value = self.mockPaymentObj

        # Setup data for Payment <> PaymentRequest Validation
        outs = {
            'outs': [
                {
                    'script': 'script',
                    'value': 100
                }
            ]
        }
        self.mockPyBitcoinTools.deserialize.return_value = outs
        self.mockPyBitcoinTools.script_to_address.return_value = 'address'

        # Setup return data from submit_transaction for testing set_payment_meta_data
        self.mockSubmitBitcoinTransaction.side_effect = ['txhash1', 'txhash2']

    def test_go_right(self):

        process_unencrypted_payment('id')

        # Validate calls and counts
        self.assertEqual(0, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockPayment.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_count)
        self.assertEqual('id', self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_args[0][0])

        self.assertEqual(2, self.mockPyBitcoinTools.script_to_address.call_count)

        self.assertEqual(2, self.mockSubmitBitcoinTransaction.call_count)
        self.assertEqual('tx1', self.mockSubmitBitcoinTransaction.call_args_list[0][0][0])
        self.assertEqual('tx2', self.mockSubmitBitcoinTransaction.call_args_list[1][0][0])

        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_count)
        self.assertEqual('txhash1', self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_args_list[0][0][0])
        self.assertEqual('memo', self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_args_list[0][0][1])
        self.assertEqual(['script'.encode('hex')], self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_args_list[0][0][2])
        self.assertEqual('txhash2', self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_args_list[1][0][0])
        self.assertEqual('memo', self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_args_list[1][0][1])
        self.assertEqual(['script'.encode('hex')], self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_args_list[1][0][2])

        self.assertEqual(1, self.mockCreatePaymentAck.call_count)
        self.assertEqual(self.mockRequest.data, self.mockCreatePaymentAck.call_args[0][0])

    def test_invalid_accept_header(self):

        # Setup test case
        del self.mockRequest.headers['Accept']

        process_unencrypted_payment('id')

        # Validate call counts
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockPayment.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_count)
        self.assertEqual(0, self.mockPyBitcoinTools.script_to_address.call_count)
        self.assertEqual(0, self.mockSubmitBitcoinTransaction.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_count)
        self.assertEqual(0, self.mockCreatePaymentAck.call_count)

        # Validate create_json_response args
        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual(
            'Invalid Accept header. Expect application/bitcoin-paymentack',
            self.mockCreateJSONResponse.call_args[0][1]
        )
        self.assertEqual(400, self.mockCreateJSONResponse.call_args[0][2])

    def test_request_too_large(self):

        # Setup test case
        from os import urandom
        self.mockRequest.data = '%s' % bytearray(urandom(PAYMENT_SIZE_MAX + 1))

        process_unencrypted_payment('id')

        # Validate call counts
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockPayment.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_count)
        self.assertEqual(0, self.mockPyBitcoinTools.script_to_address.call_count)
        self.assertEqual(0, self.mockSubmitBitcoinTransaction.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_count)
        self.assertEqual(0, self.mockCreatePaymentAck.call_count)

        # Validate create_json_response args
        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual('Invalid Payment Submitted', self.mockCreateJSONResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJSONResponse.call_args[0][2])

    def test_exception_parsing_payment_data(self):

        # Setup test case
        self.mockPayment.return_value.ParseFromString.side_effect = Exception()

        process_unencrypted_payment('id')

        # Validate call counts
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockPayment.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_count)
        self.assertEqual(0, self.mockPyBitcoinTools.script_to_address.call_count)
        self.assertEqual(0, self.mockSubmitBitcoinTransaction.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_count)
        self.assertEqual(0, self.mockCreatePaymentAck.call_count)

        # Validate create_json_response args
        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual('Exception Parsing Payment data.', self.mockCreateJSONResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJSONResponse.call_args[0][2])

    def test_merchant_data_missing(self):

        # Setup test case
        self.mockPaymentObj.merchant_data = None

        process_unencrypted_payment('id')

        # Validate call counts
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockPayment.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_count)
        self.assertEqual(0, self.mockPyBitcoinTools.script_to_address.call_count)
        self.assertEqual(0, self.mockSubmitBitcoinTransaction.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_count)
        self.assertEqual(0, self.mockCreatePaymentAck.call_count)

        # Validate create_json_response args
        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual('Payment missing merchant_data field.', self.mockCreateJSONResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJSONResponse.call_args[0][2])

    def test_exception_retrieving_payment_request(self):

        # Setup test case
        self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.side_effect = Exception()

        process_unencrypted_payment('id')

        # Validate call counts
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockPayment.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_count)
        self.assertEqual(0, self.mockPyBitcoinTools.script_to_address.call_count)
        self.assertEqual(0, self.mockSubmitBitcoinTransaction.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_count)
        self.assertEqual(0, self.mockCreatePaymentAck.call_count)

        # Validate create_json_response args
        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual('Error Retrieving PaymentRequest.', self.mockCreateJSONResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJSONResponse.call_args[0][2])

    def test_unknown_payment_request(self):

        # Setup test case
        self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.return_value = None

        process_unencrypted_payment('id')

        # Validate call counts
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockPayment.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_count)
        self.assertEqual(0, self.mockPyBitcoinTools.script_to_address.call_count)
        self.assertEqual(0, self.mockSubmitBitcoinTransaction.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_count)
        self.assertEqual(0, self.mockCreatePaymentAck.call_count)

        # Validate create_json_response args
        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual(
            'Unable to Retrieve PaymentRequest associated with Payment.',
            self.mockCreateJSONResponse.call_args[0][1]
        )
        self.assertEqual(404, self.mockCreateJSONResponse.call_args[0][2])

    def test_exception_loading_payment_validation_data(self):

        # Setup test case
        self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.return_value = {'key': 'value'}

        process_unencrypted_payment('id')

        # Validate call counts
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockPayment.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_count)
        self.assertEqual(0, self.mockPyBitcoinTools.script_to_address.call_count)
        self.assertEqual(0, self.mockSubmitBitcoinTransaction.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_count)
        self.assertEqual(0, self.mockCreatePaymentAck.call_count)

        # Validate create_json_response args
        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual('Unable to validate Payment.', self.mockCreateJSONResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJSONResponse.call_args[0][2])

    def test_payment_not_satisfying_payment_request(self):

        # Setup test case
        self.mockPyBitcoinTools.deserialize.return_value = {}

        process_unencrypted_payment('id')

        # Validate call counts
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockPayment.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_count)
        self.assertEqual(0, self.mockPyBitcoinTools.script_to_address.call_count)
        self.assertEqual(0, self.mockSubmitBitcoinTransaction.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_count)
        self.assertEqual(0, self.mockCreatePaymentAck.call_count)

        # Validate create_json_response args
        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual(
            'Payment Does Not Satisfy Requirements of PaymentRequest.',
            self.mockCreateJSONResponse.call_args[0][1]
        )
        self.assertEqual(400, self.mockCreateJSONResponse.call_args[0][2])

    def test_exception_submitting_payment_transactions_one_retry(self):

        # Setup test case
        self.mockSubmitBitcoinTransaction.side_effect = [Exception('Failed to connect'), 'txhash1', 'txhash2']

        process_unencrypted_payment('id')

        # Validate call counts
        self.assertEqual(0, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockPayment.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_count)
        self.assertEqual(2, self.mockPyBitcoinTools.script_to_address.call_count)
        self.assertEqual(3, self.mockSubmitBitcoinTransaction.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_count)
        self.assertEqual(1, self.mockCreatePaymentAck.call_count)

    def test_exception_submitting_payment_transactions_retries_exceeded(self):

        # Setup test case
        config.payment_submit_tx_retries = 1
        self.mockSubmitBitcoinTransaction.side_effect = Exception('Failed to connect')

        process_unencrypted_payment('id')

        # Validate call counts
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockPayment.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_count)
        self.assertEqual(2, self.mockPyBitcoinTools.script_to_address.call_count)
        self.assertEqual(2, self.mockSubmitBitcoinTransaction.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_count)
        self.assertEqual(0, self.mockCreatePaymentAck.call_count)

        # Validate create_json_response args
        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual(
            'Unable to submit all transactions to the Bitcoin network. Please resubmit Payment.',
            self.mockCreateJSONResponse.call_args[0][1]
        )
        self.assertEqual(500, self.mockCreateJSONResponse.call_args[0][2])

    def test_exception_saving_payment_meta_data_to_redis(self):

        # Setup test case
        self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.side_effect = Exception

        process_unencrypted_payment('id')

        # Validate call counts
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockPayment.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_payment_request_meta_data.call_count)
        self.assertEqual(2, self.mockPyBitcoinTools.script_to_address.call_count)
        self.assertEqual(2, self.mockSubmitBitcoinTransaction.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.set_payment_meta_data.call_count)
        self.assertEqual(0, self.mockCreatePaymentAck.call_count)

        # Validate create_json_response args
        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual('Internal Server Error. Please try again.', self.mockCreateJSONResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJSONResponse.call_args[0][2])

class TestGetEncryptedPayment(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher2 = patch('addressimo.paymentprotocol.Response')
        self.patcher3 = patch('addressimo.paymentprotocol.create_json_response')

        self.mockPluginManager = self.patcher1.start()
        self.mockResponse = self.patcher2.start()
        self.mockCreateJsonResponse = self.patcher3.start()

        self.mockPluginManager.get_plugin.return_value.get_encrypted_payment.return_value = {
            'encrypted_payment': 'encrypted_payment'.encode('hex')
        }

    def test_go_right(self):

        get_encrypted_payment('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_payment.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_encrypted_payment.call_args[0][0])

        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual('encrypted_payment', self.mockResponse.call_args[1]['response'])
        self.assertEqual(200, self.mockResponse.call_args[1]['status'])
        self.assertEqual('application/bitcoin-encrypted-payment', self.mockResponse.call_args[1]['mimetype'])
        self.assertEqual({'Content-Transfer-Encoding': 'binary'}, self.mockResponse.call_args[1]['headers'])

    def test_no_return_pr(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_payment.return_value = None

        get_encrypted_payment('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_payment.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_encrypted_payment.call_args[0][0])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('EncryptedPayment Not Found or Not Yet Ready', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_get_return_pr_exception(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_payment.side_effect = Exception()

        get_encrypted_payment('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_payment.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_encrypted_payment.call_args[0][0])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('EncryptedPayment Not Found', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

class TestCreatePaymentAck(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.paymentprotocol.Response')

        self.mockResponse = self.patcher1.start()

        from addressimo.paymentprotocol.paymentrequest_pb2 import Payment
        self.payment_details = Payment()
        self.payment_details.memo = 'foo'

    def test_go_right_with_memo(self):

        create_payment_ack(self.payment_details.SerializeToString(), 'memo')

        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual('\n\x05"\x03foo\x12\x04memo', self.mockResponse.call_args[1]['response'])
        self.assertEqual(200, self.mockResponse.call_args[1]['status'])
        self.assertEqual('application/bitcoin-paymentack', self.mockResponse.call_args[1]['mimetype'])
        self.assertDictEqual({'Content-Transfer-Encoding': 'binary'}, self.mockResponse.call_args[1].get('headers'))

    def test_go_right_without_memo(self):

        create_payment_ack(self.payment_details.SerializeToString())

        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual('\n\x05"\x03foo\x12\x00', self.mockResponse.call_args[1]['response'])
        self.assertEqual(200, self.mockResponse.call_args[1]['status'])
        self.assertEqual('application/bitcoin-paymentack', self.mockResponse.call_args[1]['mimetype'])
        self.assertDictEqual({'Content-Transfer-Encoding': 'binary'}, self.mockResponse.call_args[1].get('headers'))

class TestRetrieveRefundAddress(AddressimoTestCase):

    def setUp(self):
        self.patcher1 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher2 = patch('addressimo.paymentprotocol.create_json_response')

        self.mockPluginManager = self.patcher1.start()
        self.mockCreateJSONResponse = self.patcher2.start()

        self.mockPluginManager.get_plugin.return_value.get_refund_address_from_tx_hash.return_value = {'key': 'value'}

        #################################################################
        # Mock to Pass @requires_valid_signature & @requires_public_key
        self.patcher100 = patch('addressimo.util.get_id')
        self.patcher101 = patch('addressimo.util.VerifyingKey')
        self.patcher102 = patch('addressimo.util.request')
        self.patcher103 = patch('addressimo.storeforward.request')
        self.patcher104 = patch('addressimo.storeforward.get_id')
        self.patcher105 = patch('addressimo.storeforward.PluginManager')

        self.mockGetId = self.patcher100.start()
        self.mockVerifyingKey = self.patcher101.start()
        self.mockUtilRequest = self.patcher102.start()
        self.mockSFRequest = self.patcher103.start()
        self.mockSFGetId = self.patcher104.start()
        self.mockSFPluginManager = self.patcher105.start()

        self.mockSFRequest.headers = {
            'x-identity': self.mockSFPluginManager.get_plugin.return_value.get_id_obj.return_value.auth_public_key
        }

        self.mockVerifyingKey.from_string.return_value.verify.return_value = True
        #################################################################

    def test_go_right(self):

        retrieve_refund_address('id', 'tx')

        # Validate call counts
        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_refund_address_from_tx_hash.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)

        # Validate call args
        self.assertEqual(
            'tx',
            self.mockPluginManager.get_plugin.return_value.get_refund_address_from_tx_hash.call_args[0][0]
        )

        self.assertTrue(self.mockCreateJSONResponse.call_args[1].get('success'))
        self.assertEqual(
            self.mockPluginManager.get_plugin.return_value.get_refund_address_from_tx_hash.return_value,
            self.mockCreateJSONResponse.call_args[1].get('data')
        )
        self.assertEqual(200, self.mockCreateJSONResponse.call_args[1].get('status'))

class TestProcessEncryptedPaymentAck(AddressimoTestCase):

    def setUp(self):

        self.patcher2 = patch('addressimo.paymentprotocol.request')
        self.patcher3 = patch('addressimo.paymentprotocol.create_json_response')
        self.patcher4 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher5 = patch('addressimo.paymentprotocol.validate_encrypted_message')

        self.mockRequest = self.patcher2.start()
        self.mockCreateJsonResponse = self.patcher3.start()
        self.mockPluginManager = self.patcher4.start()
        self.mockValidateEncryptedMessage = self.patcher5.start()

        self.epr = EncryptedPaymentRequest()
        self.epr.sender_public_key = 'sender_public_key'.encode('hex')
        self.epr.receiver_public_key = 'receiver_public_key'.encode('hex')
        self.epr.nonce = 100000000
        self.epr.encrypted_payment_request = 'deadbeef'
        self.epr.payment_request_hash = 'deadbeef'

        self.epa = EncryptedPaymentACK()
        self.epa.sender_public_key = 'sender_public_key'.encode('hex')
        self.epa.receiver_public_key = 'receiver_public_key'.encode('hex')
        self.epa.nonce = 100000000
        self.epa.encrypted_payment_ack = 'deadbeef'
        self.epa.payment_ack_hash = 'deadbeef'
        self.epa.signature = 'deadbeef'

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.return_value = {
            'id': 'txid',
            'encrypted_payment_request': self.epr.SerializeToString().encode('hex')
        }
        self.mockRequest.data = self.epa.SerializeToString()
        self.mockRequest.content_type = 'application/bitcoin-encrypted-paymentack'

    def test_go_right(self):

        process_encrypted_paymentack('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.epa, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)
        self.assertEqual(self.epa.SerializeToString().encode('hex'), self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_args[0][0]['encrypted_paymentack'])
        self.assertEqual('txid', self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_args[0][0]['id'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertTrue(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('EncryptedPaymentAck Accepted', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(200, self.mockCreateJsonResponse.call_args[0][2])

    def test_error_submit_go_right(self):

        self.mockRequest.content_type = 'application/json'
        self.mockRequest.get_json.return_value = {
            'error_code': 400,
            'error_message': 'test error'
        }

        process_encrypted_paymentack('txid')

        self.assertEqual(0, self.mockValidateEncryptedMessage.call_count)

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)
        self.assertEqual(400, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_args[0][0]['error_code'])
        self.assertEqual('test error', self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_args[0][0]['error_message'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertTrue(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('failure data recorded for Payment message', self.mockCreateJsonResponse.call_args[0][1])

    def test_error_submit_bad_json(self):

        self.mockRequest.content_type = 'application/json'
        self.mockRequest.get_json.side_effect = Exception()

        process_encrypted_paymentack('txid')

        self.assertEqual(0, self.mockValidateEncryptedMessage.call_count)

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unable to Parse JSON', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_error_submit_missing_fields(self):

        self.mockRequest.content_type = 'application/json'
        self.mockRequest.get_json.return_value = {
            'error_code': 400
        }

        process_encrypted_paymentack('txid')

        self.assertEqual(0, self.mockValidateEncryptedMessage.call_count)

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid Data. error_code and error_message required', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_error_submit_invalid_message(self):

        self.mockRequest.content_type = 'application/json'
        self.mockRequest.get_json.return_value = {
            'error_code': 400,
            'error_message': ';()'
        }

        process_encrypted_paymentack('txid')

        self.assertEqual(0, self.mockValidateEncryptedMessage.call_count)

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('error_message invalid', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_error_submit_bad_error_code(self):

        self.mockRequest.content_type = 'application/json'
        self.mockRequest.get_json.return_value = {
            'error_code': 700,
            'error_message': 'test error'
        }

        process_encrypted_paymentack('txid')

        self.assertEqual(0, self.mockValidateEncryptedMessage.call_count)

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('error_code invalid', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_error_submit_add_epa_error_failure(self):

        self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.side_effect = Exception()
        self.mockRequest.content_type = 'application/json'
        self.mockRequest.get_json.return_value = {
            'error_code': 400,
            'error_message': 'test error'
        }

        process_encrypted_paymentack('txid')

        self.assertEqual(0, self.mockValidateEncryptedMessage.call_count)

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)
        self.assertEqual(400, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_args[0][0]['error_code'])
        self.assertEqual('test error', self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_args[0][0]['error_message'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unable to Process Failure PaymentACK Message', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_validate_ep_error(self):

        self.mockValidateEncryptedMessage.side_effect = EncryptedMessageValidationError('error text')

        process_encrypted_paymentack('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.epa, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('error text', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_validate_nonce_error(self):

        self.mockValidateEncryptedMessage.side_effect = NonceValidationError('error text')

        process_encrypted_paymentack('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.epa, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('error text', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertIn('utime', self.mockCreateJsonResponse.call_args[1]['data'])

    def test_ep_parse_error(self):

        self.mockValidateEncryptedMessage.side_effect = Exception('error text')

        process_encrypted_paymentack('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.epa, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Exception Parsing EncryptedPaymentAck', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])

    def test_epr_retrieve_error(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.side_effect = Exception()

        process_encrypted_paymentack('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.epa, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Error Retrieving EncryptedPaymentRequest', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_no_epr_data(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.return_value = {}

        process_encrypted_paymentack('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.epa, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unable to Retrieve EncryptedPaymentRequest associated with EncryptedPaymentAck', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_no_epr_data_field(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.return_value = {'id': 'payment_request'}

        process_encrypted_paymentack('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.epa, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unable to Retrieve EncryptedPaymentRequest associated with EncryptedPaymentAck', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_mismatched_sender_public_key(self):

        self.epa.sender_public_key = 'not_sender_public_key'.encode('hex')
        self.mockRequest.data = self.epa.SerializeToString()

        process_encrypted_paymentack('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.epa, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('EncryptedPaymentAck Public Key Mismatch', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_mismatched_receiver_public_key(self):

        self.epa.receiver_public_key = 'not_receiver_public_key'.encode('hex')
        self.mockRequest.data = self.epa.SerializeToString()

        process_encrypted_paymentack('txid')

        self.assertEqual(1, self.mockValidateEncryptedMessage.call_count)
        self.assertEqual(self.epa, self.mockValidateEncryptedMessage.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentrequest.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_encrypted_paymentack.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('EncryptedPaymentAck Public Key Mismatch', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

class TestGetEncryptedPaymentAck(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher2 = patch('addressimo.paymentprotocol.Response')
        self.patcher3 = patch('addressimo.paymentprotocol.create_json_response')

        self.mockPluginManager = self.patcher1.start()
        self.mockResponse = self.patcher2.start()
        self.mockCreateJsonResponse = self.patcher3.start()

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentack.return_value = {
            'encrypted_paymentack': 'encrypted_paymentack'.encode('hex')
        }

    def test_go_right(self):

        get_encrypted_paymentack('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentack.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentack.call_args[0][0])

        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual('encrypted_paymentack', self.mockResponse.call_args[1]['response'])
        self.assertEqual(200, self.mockResponse.call_args[1]['status'])
        self.assertEqual('application/bitcoin-encrypted-paymentack', self.mockResponse.call_args[1]['mimetype'])
        self.assertEqual({'Content-Transfer-Encoding': 'binary'}, self.mockResponse.call_args[1]['headers'])

    def test_no_return_pr(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentack.return_value = None

        get_encrypted_paymentack('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentack.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentack.call_args[0][0])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('EncryptedPaymentAck Not Found or Not Yet Ready', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_error_return(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentack.return_value = {
            'error_code': '406',
            'error_message': 'Amount not possible'
        }

        get_encrypted_paymentack('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentack.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentack.call_args[0][0])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Amount not possible', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(406, self.mockCreateJsonResponse.call_args[0][2])

    def test_get_return_pr_exception(self):

        self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentack.side_effect = Exception()

        get_encrypted_paymentack('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentack.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_encrypted_paymentack.call_args[0][0])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('EncryptedPaymentAck Not Found', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(503, self.mockCreateJsonResponse.call_args[0][2])
