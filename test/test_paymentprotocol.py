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

def build_epm():
    
    epm = EncryptedProtocolMessage()
    epm.message_type = ProtocolMessageType.Value('INVOICE_REQUEST')
    epm.encrypted_message = 'deadbeef'
    epm.sender_public_key = 'deadbeef'
    epm.receiver_public_key = 'deadbeef'
    epm.nonce = 42
    epm.identifier = 'tx_identifier'
    return epm

def build_pm():
    pm = ProtocolMessage()
    pm.message_type = ProtocolMessageType.Value('INVOICE_REQUEST')
    pm.serialized_message = 'deadbeef'
    pm.identifier = 'tx_identifier'
    return pm

class TestValidateEncryptedMessage(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.VerifyingKey')
        self.mockVerifyingKey = self.patcher1.start()

        self.sender_sk = SigningKey.generate(curve=curves.SECP256k1)
        self.receiver_sk = SigningKey.generate(curve=curves.SECP256k1)

        # Setup Base EPM
        self.epm = EncryptedProtocolMessage()
        self.epm.sender_public_key = self.sender_sk.get_verifying_key().to_der()
        self.epm.receiver_public_key = self.receiver_sk.get_verifying_key().to_der()
        self.epm.message_type = ProtocolMessageType.Value('INVOICE_REQUEST')
        self.epm.encrypted_message = 'deadbeef'.decode('hex')
        self.epm.nonce = int(time.time() * 1000000)
        self.epm.signature = ''

        # Sign EPM
        sig = self.sender_sk.sign(self.epm.SerializeToString(), hashfunc=sha256, sigencode=sigencode_der)
        self.epm.signature = sig

    def test_go_right(self):

        checkData = EncryptedProtocolMessage()
        checkData.CopyFrom(self.epm)
        checkData.signature = ''

        validate_encrypted_message(self.epm, sig_key='sender', sig_required=True)

        self.assertEqual(2, self.mockVerifyingKey.from_der.call_count)
        self.assertEqual(self.epm.sender_public_key, self.mockVerifyingKey.from_der.call_args_list[0][0][0])
        self.assertEqual(self.epm.receiver_public_key, self.mockVerifyingKey.from_der.call_args_list[1][0][0])

        self.assertEqual(1, self.mockVerifyingKey.from_der.return_value.verify.call_count)
        self.assertEqual(self.epm.signature, self.mockVerifyingKey.from_der.return_value.verify.call_args[0][0])
        self.assertEqual(checkData.SerializeToString(), self.mockVerifyingKey.from_der.return_value.verify.call_args[0][1])
        self.assertEqual(sha256, self.mockVerifyingKey.from_der.return_value.verify.call_args[1]['hashfunc'])
        self.assertEqual(sigdecode_der, self.mockVerifyingKey.from_der.return_value.verify.call_args[1]['sigdecode'])

    def test_sender_key_invalid_format(self):

        self.mockVerifyingKey.from_der.side_effect = Exception()
        try:
            validate_encrypted_message(self.epm)
            self.fail('Expected Exception')
        except EncryptedMessageValidationError as e:
            self.assertEqual('sender_public_key not in DER format', str(e))

        self.assertEqual(1, self.mockVerifyingKey.from_der.call_count)
        self.assertEqual(self.epm.sender_public_key, self.mockVerifyingKey.from_der.call_args_list[0][0][0])
        self.assertEqual(0, self.mockVerifyingKey.from_der.return_value.verify.call_count)

    def test_receiver_key_invalid_format(self):

        self.mockVerifyingKey.from_der.side_effect = [None, Exception()]

        self.epm.receiver_public_key = self.receiver_sk.get_verifying_key().to_string()
        try:
            validate_encrypted_message(self.epm)
            self.fail('Expected Exception')
        except EncryptedMessageValidationError as e:
            self.assertEqual('receiver_public_key not in DER format', str(e))

        self.assertEqual(2, self.mockVerifyingKey.from_der.call_count)
        self.assertEqual(self.epm.sender_public_key, self.mockVerifyingKey.from_der.call_args_list[0][0][0])
        self.assertEqual(self.epm.receiver_public_key, self.mockVerifyingKey.from_der.call_args_list[1][0][0])
        self.assertEqual(0, self.mockVerifyingKey.from_der.return_value.verify.call_count)

    def test_nonce_behind_server_time(self):

        self.epm.nonce = 10000000

        try:
            validate_encrypted_message(self.epm)
            self.fail('Expected Exception')
        except NonceValidationError as e:
            self.assertEqual('Invalid Nonce', str(e))

    def test_go_right_no_sig_not_required(self):

        checkData = EncryptedProtocolMessage()
        checkData.CopyFrom(self.epm)
        checkData.signature = ''

        self.epm.signature = ''
        validate_encrypted_message(self.epm, sig_key='sender', sig_required=False)

        self.assertEqual(2, self.mockVerifyingKey.from_der.call_count)
        self.assertEqual(self.epm.sender_public_key, self.mockVerifyingKey.from_der.call_args_list[0][0][0])
        self.assertEqual(self.epm.receiver_public_key, self.mockVerifyingKey.from_der.call_args_list[1][0][0])

        self.assertEqual(0, self.mockVerifyingKey.from_der.return_value.verify.call_count)

    def test_go_right_no_sig_required(self):

        checkData = EncryptedProtocolMessage()
        checkData.CopyFrom(self.epm)
        checkData.signature = ''

        self.epm.signature = ''
        try:
            validate_encrypted_message(self.epm, sig_key='sender', sig_required=True)
            self.fail('Exception Expected')
        except EncryptedMessageValidationError as e:
            self.assertEqual('Signature Required', str(e))

        self.assertEqual(2, self.mockVerifyingKey.from_der.call_count)
        self.assertEqual(self.epm.sender_public_key, self.mockVerifyingKey.from_der.call_args_list[0][0][0])
        self.assertEqual(self.epm.receiver_public_key, self.mockVerifyingKey.from_der.call_args_list[1][0][0])

        self.assertEqual(0, self.mockVerifyingKey.from_der.return_value.verify.call_count)

class TestParsePaymentProtocolMessage(AddressimoTestCase):

    def setUp(self):

        self.epm = EncryptedProtocolMessage()
        self.epm.message_type = ProtocolMessageType.Value('INVOICE_REQUEST')
        self.epm.encrypted_message = 'deadbeef'
        self.epm.sender_public_key = 'deadbeef'
        self.epm.receiver_public_key = 'deadbeef'
        self.epm.nonce = 42
        self.epm.identifier = 'epm_identifier'

        self.pm = ProtocolMessage()
        self.pm.message_type = ProtocolMessageType.Value('INVOICE_REQUEST')
        self.pm.serialized_message = 'deadbeef'
        self.pm.identifier = 'pm_identifier'

    def test_go_right_epm(self):

        msg = parse_paymentprotocol_message(self.epm.SerializeToString())
        self.assertEqual(msg, self.epm)
        self.assertIsInstance(msg, EncryptedProtocolMessage)

    def test_go_right_pm(self):
        msg = parse_paymentprotocol_message(self.pm.SerializeToString())
        self.assertEqual(msg, self.pm)
        self.assertIsInstance(msg, ProtocolMessage)

    def test_bad_data(self):
        msg = parse_paymentprotocol_message('ffffffff'.decode('hex'))
        self.assertIsNone(msg)

class TestGetPaymentProtocolMessages(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher2 = patch('addressimo.paymentprotocol.create_json_response')
        self.patcher3 = patch('addressimo.paymentprotocol.verify_public_key')
        self.patcher4 = patch('addressimo.paymentprotocol.parse_paymentprotocol_message')

        self.mockPluginManager = self.patcher1.start()
        self.mockCreateJsonRespose = self.patcher2.start()
        self.mockVerifyPublicKey = self.patcher3.start()
        self.mockParsePaymentProtocolMessage = self.patcher4.start()

        self.mockResolver = MagicMock()
        self.mockPluginManager.get_plugin.return_value = self.mockResolver
        self.mockVerifyPublicKey.return_value = None

        self.epm = EncryptedProtocolMessage()
        self.epm.message_type = ProtocolMessageType.Value('INVOICE_REQUEST')
        self.epm.encrypted_message = 'deadbeef'
        self.epm.sender_public_key = 'deadbeef'
        self.epm.receiver_public_key = 'deadbeef'
        self.epm.nonce = 42

        self.pm = ProtocolMessage()
        self.pm.message_type = ProtocolMessageType.Value('INVOICE_REQUEST')
        self.pm.serialized_message = 'deadbeef'

        self.mockParsePaymentProtocolMessage.return_value = self.epm

        self.mockResolver.get_paymentprotocol_messages.return_value = {
            'tx_id1': {
                'messages': ['msg1']
            },
            'tx_id2': {
                'messages': ['msg1', 'msg2']
            }
        }

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

    def test_go_right_id_epm(self):

        get_paymentprotocol_messages(id='id')

        self.assertTrue(self.mockPluginManager.get_plugin.called)
        self.assertTrue(self.mockVerifyPublicKey.called)

        self.assertEqual(1, self.mockResolver.get_id_obj.call_count)
        self.assertEqual('id', self.mockResolver.get_id_obj.call_args[0][0])

        self.assertEqual(1, self.mockResolver.get_paymentprotocol_messages.call_count)
        self.assertEqual('id', self.mockResolver.get_paymentprotocol_messages.call_args[1]['id'])

        self.assertEqual(3, self.mockParsePaymentProtocolMessage.call_count)
        self.assertEqual('msg1', self.mockParsePaymentProtocolMessage.call_args[0][0])

        self.assertEqual(1, self.mockCreateJsonRespose.call_count)
        self.assertTrue(self.mockCreateJsonRespose.call_args[0][0])
        self.assertIsNotNone(self.mockCreateJsonRespose.call_args[1]['data'])

        self.assertEqual(3, self.mockCreateJsonRespose.call_args[1]['data']['count'])
        self.assertEqual(self.epm.SerializeToString().encode('hex'), self.mockCreateJsonRespose.call_args[1]['data']['encrypted_protocol_messages'][0])

    def test_go_right_txid_pm(self):

        self.mockParsePaymentProtocolMessage.return_value = self.pm

        get_paymentprotocol_messages(tx_id='tx_id')

        self.assertTrue(self.mockPluginManager.get_plugin.called)
        self.assertFalse(self.mockVerifyPublicKey.called)

        self.assertEqual(3, self.mockParsePaymentProtocolMessage.call_count)
        self.assertEqual('msg1', self.mockParsePaymentProtocolMessage.call_args[0][0])

        self.assertEqual(1, self.mockCreateJsonRespose.call_count)
        self.assertTrue(self.mockCreateJsonRespose.call_args[0][0])
        self.assertIsNotNone(self.mockCreateJsonRespose.call_args[1]['data'])

        self.assertEqual(3, self.mockCreateJsonRespose.call_args[1]['data']['count'])
        self.assertEqual(self.pm.SerializeToString().encode('hex'), self.mockCreateJsonRespose.call_args[1]['data']['protocol_messages'][0])

    def test_noid_notxid(self):

        get_paymentprotocol_messages()

        self.assertTrue(self.mockPluginManager.get_plugin.called)
        self.assertFalse(self.mockVerifyPublicKey.called)

        self.assertEqual(1, self.mockCreateJsonRespose.call_count)
        self.assertFalse(self.mockCreateJsonRespose.call_args[0][0])
        self.assertEqual('Invalid Payment Protocol Message Retrieval Attempt', self.mockCreateJsonRespose.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonRespose.call_args[0][2])

    def test_id_with_ignore_pubkey_verify(self):

        get_paymentprotocol_messages(id='id', ignore_pubkey_verify=True)

        self.assertFalse(self.mockVerifyPublicKey.called)

    def test_id_verify_pubkey_fail(self):

        self.mockVerifyPublicKey.return_value = 'nope'

        ret = get_paymentprotocol_messages(id='id')

        self.assertEqual('nope', ret)
        self.assertFalse(self.mockResolver.get_id_obj.called)

    def test_get_id_obj_exception(self):

        self.mockResolver.get_id_obj.side_effect = Exception()

        get_paymentprotocol_messages(id='id')

        self.assertFalse(self.mockResolver.get_paymentprotocol_messages.called)

        self.assertEqual(1, self.mockCreateJsonRespose.call_count)
        self.assertFalse(self.mockCreateJsonRespose.call_args[0][0])
        self.assertEqual('Exception Occurred, Please Try Again Later.', self.mockCreateJsonRespose.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonRespose.call_args[0][2])

    def test_no_id_obj(self):

        self.mockResolver.get_id_obj.return_value = None

        get_paymentprotocol_messages(id='id')

        self.assertFalse(self.mockResolver.get_paymentprotocol_messages.called)

        self.assertEqual(1, self.mockCreateJsonRespose.call_count)
        self.assertFalse(self.mockCreateJsonRespose.call_args[0][0])
        self.assertEqual('ID Not Recognized', self.mockCreateJsonRespose.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonRespose.call_args[0][2])


class TestSubmitPaymentProtocolMessage(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher2 = patch('addressimo.paymentprotocol.request')
        self.patcher3 = patch('addressimo.paymentprotocol.verify_public_key')
        self.patcher4 = patch('addressimo.paymentprotocol.parse_paymentprotocol_message')
        self.patcher5 = patch('addressimo.paymentprotocol.create_json_response')
        self.patcher6 = patch('addressimo.paymentprotocol.validate_encrypted_message')
        self.patcher7 = patch('addressimo.paymentprotocol.process_invoicerequest')
        self.patcher8 = patch('addressimo.paymentprotocol.process_paymentrequest')
        self.patcher9 = patch('addressimo.paymentprotocol.time')

        self.mockPluginManager = self.patcher1.start()
        self.mockRequest = self.patcher2.start()
        self.mockVerifyPublicKey = self.patcher3.start()
        self.mockParsePaymentProtocolMessage = self.patcher4.start()
        self.mockCreateJsonResponse = self.patcher5.start()
        self.mockValidateEncryptedMessage = self.patcher6.start()
        self.mockProcessInvoiceRequest = self.patcher7.start()
        self.mockProcessPaymentRequest = self.patcher8.start()
        self.mockTime = self.patcher9.start()

        self.mockResolver = MagicMock()
        self.mockPluginManager.get_plugin.return_value = self.mockResolver

        # Setup Mock Data
        self.mockVerifyPublicKey.return_value = None

        self.mockIdObj = MagicMock()
        self.mockIdObj.paymentprotocol_only = True

        self.mockResolver.get_id_obj.return_value = self.mockIdObj
        self.mockResolver.get_tx_last_nonce.return_value = 30

        self.mockRequest.content_type = 'application/bitcoin-encrypted-paymentprotocol-message'
        self.mockRequest.headers = {
            'Content-Transfer-Encoding': 'binary',
            'x-identity': 'deadbeef'.encode('hex')
        }

        self.epm = build_epm()
        self.pm = build_pm()
        self.mockParsePaymentProtocolMessage.return_value = self.epm
        self.mockTime.time.return_value = 1

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

    def test_go_right_id_payment_request(self):

        self.epm.message_type = ProtocolMessageType.Value('PAYMENT_REQUEST')

        submit_paymentprotocol_message(id='id')

        self.assertTrue(self.mockPluginManager.get_plugin.called)
        self.assertTrue(self.mockVerifyPublicKey.called)
        self.assertTrue(self.mockResolver.get_id_obj.called)
        self.assertFalse(self.mockResolver.get_paymentprotocol_messages.called)

        self.assertTrue(self.mockParsePaymentProtocolMessage.called)
        self.assertEqual(self.mockRequest.get_data.return_value, self.mockParsePaymentProtocolMessage.call_args[0][0])

        self.assertTrue(self.mockResolver.get_tx_last_nonce.called)
        self.assertEqual(self.epm, self.mockResolver.get_tx_last_nonce.call_args[0][0])
        self.assertEqual('id', self.mockResolver.get_tx_last_nonce.call_args[1]['id'])

        self.assertTrue(self.mockValidateEncryptedMessage.called)
        self.assertEqual(self.epm, self.mockValidateEncryptedMessage.call_args[0][0])
        self.assertEqual('receiver', self.mockValidateEncryptedMessage.call_args[1]['sig_key'])
        self.assertTrue(self.mockValidateEncryptedMessage.call_args[1]['sig_required'])

        self.assertTrue(self.mockProcessPaymentRequest.called)
        self.assertEqual(self.epm, self.mockProcessPaymentRequest.call_args[0][0])
        self.assertEqual('id', self.mockProcessPaymentRequest.call_args[0][1])

        self.assertFalse(self.mockCreateJsonResponse.called)

    def test_go_right_id_invoice_request(self):

        submit_paymentprotocol_message(id='id', ignore_pubkey_verify=True)

        self.assertTrue(self.mockPluginManager.get_plugin.called)
        self.assertFalse(self.mockVerifyPublicKey.called)
        self.assertTrue(self.mockResolver.get_id_obj.called)
        self.assertFalse(self.mockResolver.get_paymentprotocol_messages.called)

        self.assertTrue(self.mockParsePaymentProtocolMessage.called)
        self.assertEqual(self.mockRequest.get_data.return_value, self.mockParsePaymentProtocolMessage.call_args[0][0])

        self.assertFalse(self.mockResolver.get_tx_last_nonce.called)

        self.assertTrue(self.mockValidateEncryptedMessage.called)
        self.assertEqual(self.epm, self.mockValidateEncryptedMessage.call_args[0][0])
        self.assertEqual('sender', self.mockValidateEncryptedMessage.call_args[1]['sig_key'])
        self.assertTrue(self.mockValidateEncryptedMessage.call_args[1]['sig_required'])

        self.assertTrue(self.mockProcessInvoiceRequest.called)
        self.assertEqual(self.epm, self.mockProcessInvoiceRequest.call_args[0][0])
        self.assertEqual('id', self.mockProcessInvoiceRequest.call_args[0][1])

        self.assertFalse(self.mockCreateJsonResponse.called)

    def test_go_right_tx_id_payment(self):

        self.epm.message_type = ProtocolMessageType.Value('PAYMENT')

        submit_paymentprotocol_message(tx_id='tx_id')

        self.assertTrue(self.mockPluginManager.get_plugin.called)
        self.assertFalse(self.mockVerifyPublicKey.called)

        self.assertTrue(self.mockResolver.get_paymentprotocol_messages.called)
        self.assertEqual('tx_id', self.mockResolver.get_paymentprotocol_messages.call_args[1]['tx_id'])

        self.assertTrue(self.mockResolver.add_paymentprotocol_message)
        self.assertEqual(self.epm, self.mockResolver.add_paymentprotocol_message.call_args[0][0])
        self.assertIsNone(self.mockResolver.add_paymentprotocol_message.call_args[1]['id'])
        self.assertEqual('tx_id', self.mockResolver.add_paymentprotocol_message.call_args[1]['tx_id'])

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertTrue(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Payment Protocol message accepted', self.mockCreateJsonResponse.call_args[0][1])

    def test_noid_notxid(self):

        submit_paymentprotocol_message()

        self.assertFalse(self.mockVerifyPublicKey.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid Payment Protocol Message Retrieval Attempt', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_bad_content_type(self):

        self.mockRequest.content_type = 'application/json'

        submit_paymentprotocol_message(id='id')

        self.assertFalse(self.mockVerifyPublicKey.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid Content-Type for Payment Protocol Message', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_bad_content_transfer_encoding(self):

        self.mockRequest.headers['Content-Transfer-Encoding'] = 'ascii'

        submit_paymentprotocol_message(id='id')

        self.assertFalse(self.mockVerifyPublicKey.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('PaymentProtocol Message Content-Transfer-Encoding MUST be binary', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_ignore_pubkey_verify(self):

        submit_paymentprotocol_message(id='id', ignore_pubkey_verify=True)

        self.assertFalse(self.mockVerifyPublicKey.called)

    def test_pubkey_verify_failure(self):

        self.mockVerifyPublicKey.return_value = 'nope'

        ret = submit_paymentprotocol_message(id='id')

        self.assertEqual('nope', ret)
        self.assertFalse(self.mockResolver.get_id_obj.called)

    def test_get_id_obj_exception(self):

        self.mockResolver.get_id_obj.side_effect = Exception()

        submit_paymentprotocol_message(id='id')

        self.assertFalse(self.mockParsePaymentProtocolMessage.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Exception Occurred, Please Try Again Later.', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(503, self.mockCreateJsonResponse.call_args[0][2])

    def test_no_id_obj(self):

        self.mockResolver.get_id_obj.return_value = None

        submit_paymentprotocol_message(id='id')

        self.assertFalse(self.mockParsePaymentProtocolMessage.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('ID Not Recognized', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_id_obj_not_payment_protocol(self):

        self.mockIdObj.paymentprotocol_only = False

        submit_paymentprotocol_message(id='id')

        self.assertFalse(self.mockParsePaymentProtocolMessage.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Not a PaymentProtocol Endpoint', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_invalid_tx_id(self):

        self.mockResolver.get_paymentprotocol_messages.return_value = []

        submit_paymentprotocol_message(tx_id='tx_id')

        self.assertFalse(self.mockValidateEncryptedMessage.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Transaction Does Not Exist', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_no_message(self):

        self.mockParsePaymentProtocolMessage.return_value = None

        submit_paymentprotocol_message(id='id')

        self.assertFalse(self.mockValidateEncryptedMessage.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unable to Parse Payment Protocol', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_no_identifier(self):

        self.epm.identifier = ''

        submit_paymentprotocol_message(id='id')

        self.assertFalse(self.mockValidateEncryptedMessage.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Payment Protocol Message Missing Required Field: identifier', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_nonencrypted_payment_request(self):

        self.mockParsePaymentProtocolMessage.return_value = self.pm
        self.pm.message_type = ProtocolMessageType.Value('PAYMENT_REQUEST')

        submit_paymentprotocol_message(id='id')

        self.assertFalse(self.mockValidateEncryptedMessage.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Only InvoiceRequest Messages May Be Send Using ProtocolMessages, all others require EncryptedProtocolMessages', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_mismatched_x_identity(self):

        self.mockRequest.headers['x-identity'] = 'not_matching'.encode('hex')

        submit_paymentprotocol_message(id='id')

        self.assertFalse(self.mockValidateEncryptedMessage.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Message sender Public Key Does Not Match X-Identity Public Key', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_nonce_non_increasing(self):

        self.epm.message_type = ProtocolMessageType.Value('PAYMENT_REQUEST')
        self.mockResolver.get_tx_last_nonce.return_value = 100

        submit_paymentprotocol_message(id='id')

        self.assertFalse(self.mockValidateEncryptedMessage.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Nonce is Not Valid', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_validate_message_EncryptedMessageValidationError(self):

        self.mockValidateEncryptedMessage.side_effect = EncryptedMessageValidationError('bad')

        submit_paymentprotocol_message(id='id')

        self.assertFalse(self.mockProcessInvoiceRequest.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('bad', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_validate_message_NonceValidationError(self):

        self.mockValidateEncryptedMessage.side_effect = NonceValidationError('bad')

        submit_paymentprotocol_message(id='id')

        self.assertFalse(self.mockProcessInvoiceRequest.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('bad', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])
        self.assertEqual({'utime': 1000000}, self.mockCreateJsonResponse.call_args[1]['data'])

    def test_add_payment_failure(self):

        self.epm.message_type = ProtocolMessageType.Value('PAYMENT')
        self.mockResolver.add_paymentprotocol_message.return_value = None

        submit_paymentprotocol_message(id='id')

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Message Store Failed', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])

class TestDeletePaymentProtocolMessage(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher2 = patch('addressimo.paymentprotocol.verify_public_key')
        self.patcher3 = patch('addressimo.paymentprotocol.create_json_response')
        self.patcher4 = patch('addressimo.paymentprotocol.request')
        self.patcher5 = patch('addressimo.paymentprotocol.parse_paymentprotocol_message')

        self.mockPluginManager = self.patcher1.start()
        self.mockVerifyPublicKey = self.patcher2.start()
        self.mockCreateJsonResponse = self.patcher3.start()
        self.mockRequest = self.patcher4.start()
        self.mockParsePaymentProtocolMessage = self.patcher5.start()

        self.mockResolver = MagicMock()
        self.mockPluginManager.get_plugin.return_value = self.mockResolver

        self.mockVerifyPublicKey.return_value = None

        self.mockRequest.headers = {
            'x-identity': 'deadbeef'.encode('hex')
        }

        self.mockResolver.get_paymentprotocol_messages.return_value = {
            'tx_id1': {
                'receiver_id': 'receiver_id',
                'messages': ['msg1']
            }
        }

        self.epm = build_epm()
        self.pm = build_pm()
        self.mockParsePaymentProtocolMessage.return_value = self.epm

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

    def test_go_right_id(self):

        delete_paymentprotocol_message('msg_identifier'.encode('hex'), 'invoice_request', id='id')

        self.assertTrue(self.mockPluginManager.get_plugin.called)
        self.assertTrue(self.mockVerifyPublicKey.called)

        self.assertTrue(self.mockResolver.get_id_obj.called)
        self.assertEqual('id', self.mockResolver.get_id_obj.call_args[0][0])

        self.assertTrue(self.mockResolver.get_paymentprotocol_messages.called)
        self.assertEqual('id', self.mockResolver.get_paymentprotocol_messages.call_args[1]['id'])

        self.assertTrue(self.mockParsePaymentProtocolMessage.called)
        self.assertEqual('msg1', self.mockParsePaymentProtocolMessage.call_args[0][0])

        self.assertTrue(self.mockResolver.delete_paymentprotocol_message.called)
        self.assertEqual('msg_identifier', self.mockResolver.delete_paymentprotocol_message.call_args[0][0])
        self.assertEqual('invoice_request', self.mockResolver.delete_paymentprotocol_message.call_args[0][1])
        self.assertEqual('tx_id1', self.mockResolver.delete_paymentprotocol_message.call_args[1]['tx_id'])

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertTrue(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Payment Protocol Message Deleted', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(204, self.mockCreateJsonResponse.call_args[0][2])

    def test_go_right_txid(self):

        delete_paymentprotocol_message('msg_identifier'.encode('hex'), 'invoice_request', tx_id='tx_id')

        self.assertTrue(self.mockPluginManager.get_plugin.called)
        self.assertFalse(self.mockVerifyPublicKey.called)
        self.assertFalse(self.mockResolver.get_id_obj.called)
        self.assertTrue(self.mockResolver.get_paymentprotocol_messages.called)
        self.assertEqual('tx_id', self.mockResolver.get_paymentprotocol_messages.call_args[1]['tx_id'])

        self.assertTrue(self.mockParsePaymentProtocolMessage.called)
        self.assertEqual('msg1', self.mockParsePaymentProtocolMessage.call_args[0][0])

        self.assertTrue(self.mockResolver.delete_paymentprotocol_message.called)
        self.assertEqual('msg_identifier', self.mockResolver.delete_paymentprotocol_message.call_args[0][0])
        self.assertEqual('invoice_request', self.mockResolver.delete_paymentprotocol_message.call_args[0][1])
        self.assertEqual('tx_id1', self.mockResolver.delete_paymentprotocol_message.call_args[1]['tx_id'])

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertTrue(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Payment Protocol Message Deleted', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(204, self.mockCreateJsonResponse.call_args[0][2])

    def test_go_right_txid_protocolmessage_txid(self):

        ir = InvoiceRequest()
        ir.sender_public_key = 'deadbeef'

        self.pm.serialized_message = ir.SerializeToString()
        self.mockParsePaymentProtocolMessage.return_value = self.pm

        delete_paymentprotocol_message('msg_identifier'.encode('hex'), 'invoice_request', tx_id='tx_id')

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertEqual(204, self.mockCreateJsonResponse.call_args[0][2])

    def test_go_right_id_protocolmessage(self):

        self.mockRequest.headers['x-identity'] = 'incorrect_identity'.encode('hex')

        ir = InvoiceRequest()
        ir.sender_public_key = 'deadbeef'

        self.pm.serialized_message = ir.SerializeToString()
        self.mockParsePaymentProtocolMessage.return_value = self.pm

        delete_paymentprotocol_message('msg_identifier'.encode('hex'), 'invoice_request', id='receiver_id')

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertEqual(204, self.mockCreateJsonResponse.call_args[0][2])

    def test_verify_public_key_fail(self):

        self.mockVerifyPublicKey.return_value = 'nope'

        ret = delete_paymentprotocol_message('msg_identifier'.encode('hex'), 'invoice_request', id='id')

        self.assertEqual('nope', ret)
        self.assertFalse(self.mockResolver.get_id_obj.called)

    def test_noid_notxid(self):

        delete_paymentprotocol_message('msg_identifier'.encode('hex'), 'invoice_request')

        self.assertFalse(self.mockResolver.get_id_obj.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid Payment Protocol Message Retrieval Attempt', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_get_id_exception(self):

        self.mockResolver.get_id_obj.side_effect = Exception()

        delete_paymentprotocol_message('msg_identifier'.encode('hex'), 'invoice_request', id='id')

        self.assertFalse(self.mockResolver.get_paymentprotocol_messages.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Exception Occurred, Please Try Again Later.', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(500, self.mockCreateJsonResponse.call_args[0][2])

    def test_no_id_obj(self):

        self.mockResolver.get_id_obj.return_value = None

        delete_paymentprotocol_message('msg_identifier'.encode('hex'), 'invoice_request', id='id')

        self.assertFalse(self.mockResolver.get_paymentprotocol_messages.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('ID Not Recognized', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_empty_messages(self):

        self.mockResolver.get_paymentprotocol_messages.return_value = {}

        delete_paymentprotocol_message('msg_identifier'.encode('hex'), 'invoice_request', id='id')

        self.assertFalse(self.mockResolver.delete_paymentprotocol_message.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Matching Payment Protocol Message Not Found', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_identity_not_allowed(self):

        self.mockRequest.headers['x-identity'] = 'wrong_key'.encode('hex')

        delete_paymentprotocol_message('msg_identifier'.encode('hex'), 'invoice_request', id='id')

        self.assertFalse(self.mockResolver.delete_paymentprotocol_message.called)

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Matching Payment Protocol Message Not Found', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_delete_failure(self):

        self.mockResolver.delete_paymentprotocol_message.return_value = False

        delete_paymentprotocol_message('msg_identifier'.encode('hex'), 'invoice_request', id='id')

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Payment Protocol Message Delete Failed, Try Again Later', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(503, self.mockCreateJsonResponse.call_args[0][2])

    def test_delete_failure_pm_only(self):

        ir = InvoiceRequest()
        ir.sender_public_key = 'deadbeef'

        self.pm.serialized_message = ir.SerializeToString()
        self.mockParsePaymentProtocolMessage.return_value = self.pm

        self.mockResolver.delete_paymentprotocol_message.return_value = False

        delete_paymentprotocol_message('msg_identifier'.encode('hex'), 'invoice_request', id='id')

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Payment Protocol Message Delete Failed, Try Again Later', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(503, self.mockCreateJsonResponse.call_args[0][2])

class TestProcessInvoiceRequest(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher2 = patch('addressimo.paymentprotocol.create_json_response')
        self.patcher3 = patch('addressimo.paymentprotocol.request')
        self.patcher5 = patch('addressimo.paymentprotocol.crypto')

        self.mockPluginManager = self.patcher1.start()
        self.mockCreateJsonResponse = self.patcher2.start()
        self.mockRequest = self.patcher3.start()
        self.mockCrypto = self.patcher5.start()

        # Setup Go Right Data
        self.sender_sk = SigningKey.generate(curve=curves.SECP256k1)
        self.receiver_sk = SigningKey.generate(curve=curves.SECP256k1)
        self.x509_sender_cert = crypto.load_certificate(crypto.FILETYPE_PEM, SENDER_CERT)
        self.x509_sender_cert_privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, SENDER_CERT_PRIVKEY)

        self.invoice_request = InvoiceRequest()
        self.invoice_request.sender_public_key = self.sender_sk.get_verifying_key().to_der()
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

        self.pm = build_pm()
        self.pm.serialized_message = self.invoice_request.SerializeToString()
        self.epm = build_epm()

        self.mockResolver = MagicMock()
        self.mockPluginManager.get_plugin.return_value = self.mockResolver
        self.mockResolver.add_paymentprotocol_message.return_value = 'new_tx_id'

        self.mockRequest.headers = {
            'x-identity': self.sender_sk.get_verifying_key().to_der().encode('hex')
        }

    def test_go_right_epm(self):

        process_invoicerequest(self.epm, 'test_id')

        self.assertFalse(self.mockCrypto.load_certificate.called)

        self.assertEqual(1, self.mockResolver.add_paymentprotocol_message.call_count)
        self.assertEqual(self.epm, self.mockResolver.add_paymentprotocol_message.call_args[0][0])
        self.assertEqual('test_id', self.mockResolver.add_paymentprotocol_message.call_args[1]['id'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertEqual(202, self.mockCreateJsonResponse.call_args[1]['status'])
        self.assertIn('Location', self.mockCreateJsonResponse.call_args[1]['headers'])
        self.assertEqual('https://%s/paymentprotocol/new_tx_id' % config.site_url, self.mockCreateJsonResponse.call_args[1]['headers']['Location'])

    def test_go_right_pm(self):

        process_invoicerequest(self.pm, 'test_id')

        self.assertTrue(self.mockPluginManager.get_plugin.called)

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

        self.assertEqual(1, self.mockResolver.add_paymentprotocol_message.call_count)
        self.assertEqual(self.pm, self.mockResolver.add_paymentprotocol_message.call_args[0][0])
        self.assertEqual('test_id', self.mockResolver.add_paymentprotocol_message.call_args[1]['id'])

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertEqual(202, self.mockCreateJsonResponse.call_args[1]['status'])
        self.assertIn('Location', self.mockCreateJsonResponse.call_args[1]['headers'])
        self.assertEqual('https://%s/paymentprotocol/new_tx_id' % config.site_url, self.mockCreateJsonResponse.call_args[1]['headers']['Location'])

    def test_invalid_xidentity_header(self):

        self.mockRequest.headers['x-identity'] = 'i_m_wrong'.encode('hex')

        process_invoicerequest(self.pm, 'test_id')

        self.assertFalse(self.mockCrypto.load_certificate.called)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('InvoiceRequest Public Key Does Not Match X-Identity Public Key', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_cert_no_signature(self):

        self.invoice_request.signature = ''
        self.pm.serialized_message = self.invoice_request.SerializeToString()

        process_invoicerequest(self.pm, 'test_id')

        self.assertFalse(self.mockCrypto.load_certificate.called)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Requests including x509 cert must include signature', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_load_cert_exception(self):

        self.mockCrypto.load_certificate.side_effect = Exception()

        process_invoicerequest(self.pm, 'test_id')

        self.assertFalse(self.mockCrypto.verify.called)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Invalid x509 Certificate', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(400, self.mockCreateJsonResponse.call_args[0][2])

    def test_verify_exception(self):

        self.mockCrypto.verify.side_effect = Exception

        process_invoicerequest(self.pm, 'test_id')

        self.assertFalse(self.mockResolver.add_paymentprotocol_message.called)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Signature Verification Error', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(401, self.mockCreateJsonResponse.call_args[0][2])

    def test_add_paymentprotocol_message_failure(self):

        self.mockResolver.add_paymentprotocol_message.return_value = None

        process_invoicerequest(self.pm, 'test_id')

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unknown System Error, Please Try Again Later', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(503, self.mockCreateJsonResponse.call_args[0][2])

    def test_add_paymentprotocol_message_exception(self):

        self.mockResolver.add_paymentprotocol_message.side_effect = Exception()

        process_invoicerequest(self.pm, 'test_id')

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Unknown System Error, Please Try Again Later', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(503, self.mockCreateJsonResponse.call_args[0][2])


class TestProcessPaymentRequest(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.paymentprotocol.PluginManager')
        self.patcher2 = patch('addressimo.paymentprotocol.create_json_response')
        self.patcher3 = patch('addressimo.paymentprotocol.parse_paymentprotocol_message')
        self.patcher4 = patch('addressimo.paymentprotocol.requests')

        self.mockPluginManager = self.patcher1.start()
        self.mockCreateJsonResponse = self.patcher2.start()
        self.mockParsePaymentProtocolMessage = self.patcher3.start()
        self.mockRequests = self.patcher4.start()

        self.mockResolver = MagicMock()
        self.mockPluginManager.get_plugin.return_value = self.mockResolver

        self.epm = build_epm()
        self.pm = build_pm()

        self.mockResolver.get_paymentprotocol_messages.return_value = {
            'tx_id': {
                'messages': ['msg1']
            }
        }

        self.ir = InvoiceRequest()
        self.ir.notification_url = 'notification_url'
        self.ir.sender_public_key = 'deadbeef'
        self.pm.serialized_message = self.ir.SerializeToString()

        self.mockParsePaymentProtocolMessage.return_value = self.pm
        self.mockRequests.post.return_value = 200

    def test_go_right(self):

        process_paymentrequest('msg', 'id')

        self.assertTrue(self.mockPluginManager.get_plugin.called)

        self.assertTrue(self.mockResolver.add_paymentprotocol_message.called)
        self.assertEqual('msg', self.mockResolver.add_paymentprotocol_message.call_args[0][0])
        self.assertEqual('id', self.mockResolver.add_paymentprotocol_message.call_args[1]['id'])

        self.assertTrue(self.mockResolver.get_paymentprotocol_messages.called)
        self.assertEqual(self.mockResolver.add_paymentprotocol_message.return_value, self.mockResolver.get_paymentprotocol_messages.call_args[1]['tx_id'])

        self.assertEqual(1, self.mockParsePaymentProtocolMessage.call_count)

        self.assertEqual(1, self.mockRequests.post.call_count)
        self.assertEqual('notification_url', self.mockRequests.post.call_args[0][0])
        self.assertEqual({'Content-Type': 'application/bitcoin-encrypted-paymentprotocol-message', 'Content-Transfer-Encoding': 'binary'}, self.mockRequests.post.call_args[1]['headers'])
        self.assertEqual('msg', self.mockRequests.post.call_args[1]['data'])

        self.assertTrue(self.mockCreateJsonResponse.called)
        self.assertTrue(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('Message Accepted', self.mockCreateJsonResponse.call_args[0][1])

    def test_add_message_fail(self):

        self.mockResolver.add_paymentprotocol_message.return_value = None

        process_paymentrequest('msg', 'id')

        self.assertFalse(self.mockResolver.get_paymentprotocol_messages.called)

        self.assertEqual(1, self.mockCreateJsonResponse.call_count)
        self.assertFalse(self.mockCreateJsonResponse.call_args[0][0])
        self.assertEqual('No Matching Transaction Found', self.mockCreateJsonResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJsonResponse.call_args[0][2])

    def test_invoicerequest_encrypted(self):

        self.mockParsePaymentProtocolMessage.return_value = self.epm
        process_paymentrequest('msg', 'id')
        self.assertFalse(self.mockRequests.post.called)

    def test_paymentrequest_unencrypted(self):

        self.pm.message_type = ProtocolMessageType.Value('PAYMENT_REQUEST')
        process_paymentrequest('msg', 'id')
        self.assertFalse(self.mockRequests.post.called)