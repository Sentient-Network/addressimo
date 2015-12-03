__author__ = 'mdavid'

# System Imports
from mock import MagicMock, Mock, patch
from test import AddressimoTestCase

from ecdsa import SigningKey, curves

from addressimo.paymentrequest.ir import *

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

class TestSubmitInvoiceRequest(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentrequest.ir.PluginManager')
        self.patcher2 = patch('addressimo.paymentrequest.ir.create_json_response')
        self.patcher3 = patch('addressimo.paymentrequest.ir.request')
        self.patcher4 = patch('addressimo.paymentrequest.ir.datetime')
        self.patcher5 = patch('addressimo.paymentrequest.ir.crypto')

        self.mockPluginManager = self.patcher1.start()
        self.mockCreateJsonResponse = self.patcher2.start()
        self.mockRequest = self.patcher3.start()
        self.mockDatetime = self.patcher4.start()
        self.mockCrypto = self.patcher5.start()

        # Setup Go Right Data
        self.sender_sk = SigningKey.generate(curve=curves.SECP256k1)
        self.x509_sender_cert = crypto.load_certificate(crypto.FILETYPE_PEM, SENDER_CERT)
        self.x509_sender_cert_privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, SENDER_CERT_PRIVKEY)

        self.invoice_request = InvoiceRequest()
        self.invoice_request.sender_public_key = self.sender_sk.get_verifying_key().to_string()
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

        self.ret_prr_data = {"id":"ir_id"}

        self.mock_id_obj = Mock()
        self.mock_id_obj.ir_only = True
        self.mockPluginManager.get_plugin.return_value.get_id_obj.return_value = self.mock_id_obj
        self.mockPluginManager.get_plugin.return_value.add_invoicerequest.return_value = self.ret_prr_data
        self.mockDatetime.utcnow.return_value = datetime(2015, 6, 13, 2, 43, 0)

        self.mockRequest.headers = {'x-identity': self.sender_sk.get_verifying_key().to_string().encode('hex'), 'Content-Transfer-Encoding': 'binary'}
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
        self.mockVerifyingKey = self.patcher101.start()
        self.mockUtilRequest = self.patcher102.start()

        self.mockRequest.headers['x-signature'] = 'sigF'.encode('hex')
        self.mockVerifyingKey.from_string.return_value.verify.return_value = True

    def test_go_right(self):

        result = IR.submit_invoicerequest('test_id')

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

        prr_data = self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_args[0][1]
        self.assertEqual(self.invoice_request.SerializeToString().encode('hex'), prr_data['invoice_request'])
        self.assertEqual(datetime(2015,6,13,2,43,0), prr_data['submit_date'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertEqual(202, self.mockCreateJsonResponse.call_args[1]['status'])
        self.assertIn('Location', self.mockCreateJsonResponse.call_args[1]['headers'])
        self.assertEqual('https://%s/returnpaymentrequest/ir_id' % config.site_url, self.mockCreateJsonResponse.call_args[1]['headers']['Location'])

    def test_id_obj_resolve_exception(self):

        self.mockPluginManager.get_plugin.return_value.get_id_obj.side_effect = Exception()

        result = IR.submit_invoicerequest('test_id')

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

        result = IR.submit_invoicerequest('test_id')

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

        result = IR.submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockRequest.get_json.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid PaymentRequest Request Endpoint', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_incorrect_content_type(self):

        self.mockRequest.content_type = 'application/json'

        result = IR.submit_invoicerequest('test_id')

        self.assertIsNotNone(result)

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockRequest.get_json.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('InvoiceRequest Content-Type Must Be application/bitcoin-invoicerequest', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_incorrect_transfer_encoding_header(self):

        self.mockRequest.headers['Content-Transfer-Encoding'] = 'not_binary'

        result = IR.submit_invoicerequest('test_id')

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

        result = IR.submit_invoicerequest('test_id')

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

        result = IR.submit_invoicerequest('test_id')

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

        result = IR.submit_invoicerequest('test_id')

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

        result = IR.submit_invoicerequest('test_id')

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

        result = IR.submit_invoicerequest('test_id')

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

        result = IR.submit_invoicerequest('test_id')

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

        prr_data = self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_args[0][1]
        self.assertEqual(self.invoice_request.SerializeToString().encode('hex'), prr_data['invoice_request'])
        self.assertEqual(datetime(2015,6,13,2,43,0), prr_data['submit_date'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unknown System Error, Please Try Again Later', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])

    def test_add_invoicerequest_exception(self):

        self.mockPluginManager.get_plugin.return_value.add_invoicerequest.side_effect = Exception()

        result = IR.submit_invoicerequest('test_id')

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

        prr_data = self.mockPluginManager.get_plugin.return_value.add_invoicerequest.call_args[0][1]
        self.assertEqual(self.invoice_request.SerializeToString().encode('hex'), prr_data['invoice_request'])
        self.assertEqual(datetime(2015,6,13,2,43,0), prr_data['submit_date'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unknown System Error, Please Try Again Later', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])

class TestGetQueuedInvoiceRequests(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentrequest.ir.PluginManager')
        self.patcher2 = patch('addressimo.paymentrequest.ir.create_json_response')
        self.patcher3 = patch('addressimo.paymentrequest.ir.request')

        self.mockPluginManager = self.patcher1.start()
        self.mockCreateJsonResponse = self.patcher2.start()
        self.mockRequest = self.patcher3.start()

        # Setup Go Right Data
        self.queued_prrs = [{"id":"id1"},{"id":"id2"}]

        self.mock_id_obj = Mock()
        self.mock_id_obj.ir_only = True
        self.mockPluginManager.get_plugin.return_value.get_invoicerequests.return_value = self.queued_prrs

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

        IR.get_queued_invoice_requests('test_id')

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

        IR.get_queued_invoice_requests('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_count)
        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid Identifier', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_get_prrs_exception(self):

        self.mockPluginManager.get_plugin.return_value.get_invoicerequests.side_effect = Exception()

        IR.get_queued_invoice_requests('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_invoicerequests.call_args[0][0])
        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unable to Retrieve Queued PR Requests', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])

class TestSubmitReturnPaymentRequest(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentrequest.ir.PluginManager')
        self.patcher2 = patch('addressimo.paymentrequest.ir.create_json_response')
        self.patcher3 = patch('addressimo.paymentrequest.ir.request')
        self.patcher4 = patch('addressimo.paymentrequest.ir.datetime')

        self.mockPluginManager = self.patcher1.start()
        self.mockCreateJsonResponse = self.patcher2.start()
        self.mockRequest = self.patcher3.start()
        self.mockDatetime = self.patcher4.start()

        # Setup Go Right Data
        rpr1 = ReturnPaymentRequest()
        rpr1.encrypted_payment_request = 'encrypted_payment_request'.encode('hex')
        rpr1.receiver_public_key = 'receiver_public_key'.encode('hex')
        rpr1.ephemeral_public_key = 'ephemeral_public_key'.encode('hex')
        rpr1.payment_request_hash = 'payment_request_hash'.encode('hex')

        rpr2 = ReturnPaymentRequest()
        rpr2.encrypted_payment_request = 'encrypted_payment_request'.encode('hex')
        rpr2.receiver_public_key = 'receiver_public_key'.encode('hex')
        rpr2.ephemeral_public_key = 'ephemeral_public_key'.encode('hex')
        rpr2.payment_request_hash = 'payment_request_hash'.encode('hex')

        self.mockRequest.get_json.return_value = {
            "ready_requests": [
                {"id":"id1", "return_payment_request": rpr1.SerializeToString().encode('hex')},
                {"id":"id2", "return_payment_request": rpr2.SerializeToString().encode('hex')},
            ]
        }

        self.mock_id_obj = Mock()
        self.mock_id_obj.ir_only = True
        self.mockDatetime.utcnow.return_value = 'utcnow'

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

        IR.submit_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest
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
        self.assertEqual(2, self.mockCreateJsonResponse.call_args[1]['data']['accept_count'])

    def test_missing_id_obj(self):

        self.mockPluginManager.get_plugin.return_value.get_id_obj.return_value = None

        IR.submit_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockRequest.get_json.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid Identifier', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_not_ir_only(self):

        self.mockPluginManager.get_plugin.return_value.get_id_obj.return_value.ir_only = False

        IR.submit_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(0, self.mockRequest.get_json.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid PaymentRequest Request Endpoint', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_request_not_json(self):

        self.mockRequest.get_json.return_value = None

        IR.submit_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid Request', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_missing_ready_requests(self):

        del self.mockRequest.get_json.return_value['ready_requests']
        self.mockRequest.get_json.return_value['key'] = 'value'

        IR.submit_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Missing or Empty ready_requests list', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_empty_ready_requests(self):

        self.mockRequest.get_json.return_value['ready_requests'] = []

        IR.submit_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Missing or Empty ready_requests list', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_ready_requests_non_list(self):

        self.mockRequest.get_json.return_value['ready_requests'] = 'bob'

        IR.submit_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest.call_count)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Missing or Empty ready_requests list', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_missing_id_required_field(self):

        del self.mockRequest.get_json.return_value['ready_requests'][0]['id']

        IR.submit_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest
        json_data = self.mockRequest.get_json.return_value

        self.assertNotIn('submit_data', json_data['ready_requests'][0])
        self.assertEqual('utcnow', json_data['ready_requests'][1]['submit_date'])
        self.assertEqual(json_data['ready_requests'][1], add_pr_call.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Submitted Return PaymentRequests contain errors, please see failures field for more information', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual(1, self.mockCreateJsonResponse.call_args[0][3]['accept_count'])
        self.assertEqual('Missing ready_request id field', self.mockCreateJsonResponse.call_args[0][3]['failures']['unknown'][0])

    def test_missing_rpr_required_field(self):

        del self.mockRequest.get_json.return_value['ready_requests'][0]['return_payment_request']

        IR.submit_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest
        json_data = self.mockRequest.get_json.return_value

        self.assertNotIn('submit_data', json_data['ready_requests'][0])
        self.assertEqual('utcnow', json_data['ready_requests'][1]['submit_date'])
        self.assertEqual(json_data['ready_requests'][1], add_pr_call.call_args[0][0])

        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][0])
        self.assertEqual('id2', self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.call_args[0][1])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Submitted Return PaymentRequests contain errors, please see failures field for more information', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual(1, self.mockCreateJsonResponse.call_args[0][3]['accept_count'])
        self.assertEqual('Missing Required Field return_payment_request', self.mockCreateJsonResponse.call_args[0][3]['failures']['id1'][0])


    def test_add_return_pr_exception(self):

        self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest.side_effect = [Exception('Test Error'), True]

        IR.submit_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest
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
        self.assertEqual('Submitted Return PaymentRequests contain errors, please see failures field for more information', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual(1, self.mockCreateJsonResponse.call_args[0][3]['accept_count'])
        self.assertEqual('Unable to Process Return PaymentRequest', self.mockCreateJsonResponse.call_args[0][3]['failures']['id1'][0])

    def test_delete_prr_exception(self):

        self.mockPluginManager.get_plugin.return_value.delete_invoicerequest.side_effect = Exception()

        IR.submit_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockRequest.get_json.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest.call_count)

        add_pr_call = self.mockPluginManager.get_plugin.return_value.add_return_paymentrequest
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
        self.assertEqual(2, self.mockCreateJsonResponse.call_args[1]['data']['accept_count'])

class TestGetReturnPaymentRequest(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentrequest.ir.PluginManager')
        self.patcher2 = patch('addressimo.paymentrequest.ir.Response')
        self.patcher3 = patch('addressimo.paymentrequest.ir.create_json_response')

        self.mockPluginManager = self.patcher1.start()
        self.mockResponse = self.patcher2.start()
        self.mockCreateJsonResponse = self.patcher3.start()

        self.mockPluginManager.get_plugin.return_value.get_return_paymentrequest.return_value = {
            'return_payment_request': 'return_payment_request'.encode('hex')
        }

    def test_go_right(self):

        IR.get_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_return_paymentrequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_return_paymentrequest.call_args[0][0])

        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual('return_payment_request', self.mockResponse.call_args[1]['response'])
        self.assertEqual(200, self.mockResponse.call_args[1]['status'])
        self.assertEqual('application/bitcoin-returnpaymentrequest', self.mockResponse.call_args[1]['mimetype'])
        self.assertEqual({'Content-Transfer-Encoding': 'binary'}, self.mockResponse.call_args[1]['headers'])

    def test_no_return_pr(self):

        self.mockPluginManager.get_plugin.return_value.get_return_paymentrequest.return_value = None

        IR.get_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_return_paymentrequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_return_paymentrequest.call_args[0][0])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('PaymentRequest Not Found or Not Yet Ready', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_get_return_pr_exception(self):

        self.mockPluginManager.get_plugin.return_value.get_return_paymentrequest.side_effect = Exception()

        IR.get_return_paymentrequest('test_id')

        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual('RESOLVER', self.mockPluginManager.get_plugin.call_args[0][0])
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_return_paymentrequest.call_count)
        self.assertEqual('test_id', self.mockPluginManager.get_plugin.return_value.get_return_paymentrequest.call_args[0][0])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('PaymentRequest Not Found', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])