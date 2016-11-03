__author__ = 'Matt David'

import hashlib
import json
import os
import requests
import ssl
import sys
import time
import unittest

from OpenSSL import crypto

from binascii import unhexlify
from datetime import datetime, timedelta
from ecdsa import SigningKey, curves, VerifyingKey
from ecdsa.util import sigdecode_der, sigencode_der
from flask.ext.testing import LiveServerTestCase
from hashlib import sha256
from OpenSSL import crypto
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from addressimo.config import config
from addressimo.crypto import HMAC_DRBG
from addressimo.data import IdObject
from addressimo.plugin import PluginManager
from addressimo.paymentprotocol.bip75util import BIP75_STATUS_OK
from addressimo.paymentprotocol.paymentrequest_pb2 import PaymentRequest, PaymentDetails, InvoiceRequest, X509Certificates, Payment, PaymentACK, Output, ProtocolMessage, EncryptedProtocolMessage, ProtocolMessageType
from addressimo.util import LogUtil
from server import app

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

RECEIVER_CERT = '''
-----BEGIN CERTIFICATE-----
MIIDjjCCAnYCCQCEYiGXmolUUjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFDASBgNVBAcMC0xvcyBBbmdlbGVzMRQw
EgYDVQQKDAtOZXRraSwgSW5jLjETMBEGA1UEAwwKYWRkcmVzc2ltbzEjMCEGCSqG
SIb3DQEJARYUb3BlbnNvdXJjZUBuZXRraS5jb20wHhcNMTUwNzA2MTc0NzU3WhcN
MTYwNzA1MTc0NzU3WjCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3Ju
aWExFDASBgNVBAcMC0xvcyBBbmdlbGVzMRQwEgYDVQQKDAtOZXRraSwgSW5jLjET
MBEGA1UEAwwKYWRkcmVzc2ltbzEjMCEGCSqGSIb3DQEJARYUb3BlbnNvdXJjZUBu
ZXRraS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD0mXwQNo1t
+mWmUBOvzQu9c3dNc019NL22MhjQtj5xtloSURpKJEDnkSH9QmiKmwCmCP534fpe
EjjTMnssa211j9CrRjGhlw2utj758+0+fWxNcaw2axBqFaLTZ08kI9325kOmMqj3
ZihzGKl9k6TTa+F/yYBsUg9gWM8R2Kx+TPhDWd2F2qtYEsJ/+FuSmbTbhVK1xyKw
xt6pgnLuON7n012rDzFpWp6xhpnxdwJKT618I6EvzgImQQXwrHcaxMfsYvbIx3t6
WadNwe3DV0onmlP2HWgrZjqlSyZkJtbJNt9M9UNPvHpan2nhM+uFFNYm7Lds3HWn
E80Erde6DUFnAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAO7HuYR3eDQtJfvmqF9z
whduPlI2tcuQaC5qnAuw9QACJ1P7f/JgjBa4ZdUp3ll0Ka9H4XK+zdh9FE8NGSXX
2kOdkJvw3S9rKacXkFKfDqbHOURyrXZ5Qnd7gn9UjStrt7nULYQR2CnND018MXT2
ojK1hGJt5Hh7jGwjKvPQe8Xb4i6u36zOQMNk7t7x+ryhoUxtX5uiiJFOt9ZsTsbn
RmkGxmG3vqq0S4yqClEG8MbRU4XVSu73OL+WM8Eo7eTltHirP81CztR8ki6WrD5W
VaTgdpiY90zRckz8wdX1WsAZs4xOL4ECxdDU9puvwDBWME4Ijt9PRSlzwsukv08B
yfk=
-----END CERTIFICATE-----
'''

RECEIVER_CERT_PRIVKEY = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA9Jl8EDaNbfplplATr80LvXN3TXNNfTS9tjIY0LY+cbZaElEa
SiRA55Eh/UJoipsApgj+d+H6XhI40zJ7LGttdY/Qq0YxoZcNrrY++fPtPn1sTXGs
NmsQahWi02dPJCPd9uZDpjKo92YocxipfZOk02vhf8mAbFIPYFjPEdisfkz4Q1nd
hdqrWBLCf/hbkpm024VStccisMbeqYJy7jje59Ndqw8xaVqesYaZ8XcCSk+tfCOh
L84CJkEF8Kx3GsTH7GL2yMd7elmnTcHtw1dKJ5pT9h1oK2Y6pUsmZCbWyTbfTPVD
T7x6Wp9p4TPrhRTWJuy3bNx1pxPNBK3Xug1BZwIDAQABAoIBAQDZvRf3xtg3osOC
PZ6IzNs6luMJCy9b2etXmVkF0nXb/BxKWfAxN/yfJ08+iDNPz5PQOgls5rldrJLx
TurfK/KQyKlVDnN4CWOgt5NwJnh3PGeAuUQ4XS6LgR8lWb3Vyif5dhmahVZshYBU
lQusQhZkLpDalKHBy3rspaIPnPZQpq6FwGuLoOb469Evv1HdXT1CsSQKoPnQaWnv
l1IwYAOtbsQOYIL3xqEpMXqMwFOx/5V4qzCkrgZYhRTlJ5MJJgNZ60EswP6cm9AG
PIoYtelqQiYVlcLXc4fSLzT7QN94ncX5Qf0Xs0hDpCENxJsiiHzIARa3dz7C+fx9
lPpROW/hAoGBAPpyLukh24j4Hc+RD9dSt02ISFaeeI98EvwesEl73HFTB5w9QrA6
dLIG4cT7RHMI3vUMj/BUN3cyEMCRyibdnulAmoQhvBy6dSMnRKdbHmdXCKEA8Nkx
JSYcgFgPP6hqMDVtC2jmkERb8UTjIXQyN5ly1HSWaVtd0bMcthlYGJS9AoGBAPoG
HC//eQYAmcFwDkO08ckS+AKEJOdqZgNBW/CCKn3YiXi9adrbRaaHSDEr7hGSM5aT
jmJh0PGJKELMVoa3zHTQQ0PgKuWUQ7wLnUV4qy1XSOiCyVnk5nYDHknNF8n7sTUs
foc5IWYcQQ3VKwSNmIXgdW8nnsxPJwm1D0gfjnrzAoGBANxMdFc+IQ5qsk5TG8wc
RoE8z+ThoMsWKNz9YbRB77b/gkI84NyDjwLKau4K2DsYIocLddHBQsjmkTXTCC8H
4zDqUwDHa+EZYtB5SjqsPCJKvJxjZ3ilcjgD+iF7yFMslRtpwA+WQHDhL2mZIWRE
iAPCrn+fjy1/aWZUaxoAFB9BAoGAafobCpFMOCobAi5ALZzN+7/plg9zIRAta2XR
1bEm167oHmCTNOxKqpqfFBCd2Z7R9RpYeQUjLq5HfYDlkDbqF/2K9YNYS3W7/EIk
CKVsUUy1H7EILe1jblRGC1w+oCPqajKQ8zpZGNITFQztLgHiy6RnwpTVr55BWtD/
SD/wAdcCgYBUMjnggyFXCBlatQwJ0x0kvSts9ssoYAHPjnrM6E4PpG9okSrlCBQ0
zSc+dbwv1qsO2j4i2PlHShMSoR/Vrv+69a9d6S2D2hZzl6L/B4Na+250xdyHyfGS
TWeo5LnGCgNnyl/Mfte1mYjJLJ/A1QAK/NEpddrF2TNMzOiVw9cBWQ==
-----END RSA PRIVATE KEY-----
'''

log = LogUtil.setup_logging()

# Crypto Utility Functions
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class BIP75FunctionalTest(LiveServerTestCase):

    def create_app(self):
        app.config['TESTING'] = True
        app.config['LIVESERVER_PORT'] = 47294
        app.config['DEBUG'] = True
        return app

    @classmethod
    def setUpClass(cls):

        log.info('Generating ECDSA Keypairs for Testing')
        cls.sender_sk = SigningKey.generate(curve=curves.SECP256k1)
        cls.receiver_sk = SigningKey.generate(curve=curves.SECP256k1)

        log.info('Setup IdObj for testid')
        cls.test_id_obj = IdObject()
        cls.test_id_obj.auth_public_key = cls.receiver_sk.get_verifying_key().to_der().encode('hex')
        cls.test_id_obj.id = 'testid'
        cls.test_id_obj.paymentprotocol_only = True

        cls.resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)
        cls.resolver.save(cls.test_id_obj)
        log.info('Save testid IdObj')

        log.info('Setup Class Identifier')

        cls.identifier = None

    @classmethod
    def tearDownClass(cls):

        time.sleep(1)

        resolver = PluginManager.get_plugin('RESOLVER', config.resolver_type)
        log.info('Clean Up Functest')

        log.info('Deleting All testid InvoiceRequests if any exist')
        for message_type in ProtocolMessageType.keys():
            resolver.delete_paymentprotocol_message(cls.identifier, message_type, id='testid')

        log.info('Deleting Test IdObj')
        resolver.delete(BIP75FunctionalTest.test_id_obj)

    def get_signing_data(self, url, method, data=None):
        sdata = method.upper() + url.replace('http://', '')
        if data and isinstance(data, dict):
            sdata += json.dumps(data)
        if data and isinstance(data, basestring):
            sdata += data
        return sdata

    def register_endpoint(self):

        log.info('Registering Addressimo Endpoint')

        url = '%s/address' % self.get_server_url()
        headers = {
            'X-Identity': BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': BIP75FunctionalTest.receiver_sk.sign(self.get_signing_data(url, 'post'), hashfunc=hashlib.sha256, sigencode=sigencode_der).encode('hex')
        }

        response = requests.post(url, headers=headers)

        rdata = response.json()
        self.addressimo_endpoint_id = str(rdata.get('id'))

    def cleanup_endpoint(self):

        log.info('Cleaning Up Registered Addressimo Endpoint [ID: %s]' % self.addressimo_endpoint_id)

        url = '%s/address/%s/sf' % (self.get_server_url(), self.addressimo_endpoint_id)
        headers = {
            'X-Identity': BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': BIP75FunctionalTest.receiver_sk.sign(self.get_signing_data(url, 'delete'), hashfunc=hashlib.sha256, sigencode=sigencode_der).encode('hex')
        }
        requests.delete(url, headers=headers)

    def long_to_bytes(self, val, endianness='big'):
        width = val.bit_length()
        width += 8 - ((width % 8) or 8)
        fmt = '%%0%dx' % (width // 4)
        s = unhexlify(fmt % val)
        if endianness == 'little':
            # see http://stackoverflow.com/a/931095/309233
            s = s[::-1]
        return s

    def get_ecdh_value(self, pubkey, privkey):

        ecdh_point = privkey.privkey.secret_multiplier * pubkey.pubkey.point
        return hashlib.sha512(self.long_to_bytes(ecdh_point.x())).digest()

    def ecdh_encrypt(self, plaintext, nonce, pubkey, privkey, aad=None):

        ecdh_point_hash = self.get_ecdh_value(pubkey, privkey)
        log.info('ECDH_POINT: %s' % ecdh_point_hash.encode('hex'))

        # Encrypt PR using HMAC-DRBG
        drbg = HMAC_DRBG(entropy=ecdh_point_hash, nonce=self.long_to_bytes(nonce))
        encryption_key = drbg.generate(32)
        iv = drbg.generate(12)

        encryptor = Cipher(algorithms.AES(encryption_key), modes.GCM(iv), backend=default_backend()).encryptor()
        if aad:
            encryptor.authenticate_additional_data(aad)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return encryptor.tag + ciphertext

    def ecdh_decrypt(self, ciphertext, nonce, pubkey, privkey, aad=None):

        ecdh_point_hash = self.get_ecdh_value(pubkey, privkey)
        log.info('ECDH_POINT: %s' % ecdh_point_hash.encode('hex'))

        # Encrypt PR using HMAC-DRBG
        drbg = HMAC_DRBG(entropy=ecdh_point_hash, nonce=self.long_to_bytes(nonce))
        encryption_key = drbg.generate(32)
        iv = drbg.generate(12)

        decryptor = Cipher(algorithms.AES(encryption_key), modes.GCM(iv, ciphertext[:16]), backend=default_backend()).decryptor()
        if aad:
            decryptor.authenticate_additional_data(aad)

        return decryptor.update(ciphertext[16:]) + decryptor.finalize()

    def parse_protocol_message(self, data):
        try:
            epm = EncryptedProtocolMessage()
            epm.ParseFromString(data)
            return epm
        except:
            try:
                pm = ProtocolMessage()
                pm.ParseFromString()
                return pm
            except:
                pass

        self.fail(msg='Unable to Parse Payment Protocol Message')
        
    def create_encrypted_protocol_message(self, message, receiver_pubkey, sender_pubkey, private_key, identifier=None):

        ecdh_pubkey = receiver_pubkey
        if private_key.get_verifying_key().to_der() == receiver_pubkey.to_der():
            ecdh_pubkey = sender_pubkey

        nonce = int(time.time() * 1000000)

        ciphertext = self.ecdh_encrypt(
            plaintext=message.SerializeToString(),
            nonce=nonce,
            pubkey=ecdh_pubkey,
            privkey=private_key
        )

        epm = EncryptedProtocolMessage()

        if isinstance(message, InvoiceRequest):
            epm.message_type = ProtocolMessageType.Value('INVOICE_REQUEST')
        elif isinstance(message, PaymentRequest):
            epm.message_type = ProtocolMessageType.Value('PAYMENT_REQUEST')
        elif isinstance(message, Payment):
            epm.message_type = ProtocolMessageType.Value('PAYMENT')
        elif isinstance(message, PaymentACK):
            epm.message_type = ProtocolMessageType.Value('PAYMENT_ACK')
        else:
            self.fail("Invalid ProtocolMessage Type")

        if not identifier:
            identifier = hashlib.sha256(message.SerializeToString()).digest()

        epm.version = 1
        epm.status_code = BIP75_STATUS_OK
        epm.encrypted_message = ciphertext
        epm.receiver_public_key = receiver_pubkey.to_der()
        epm.sender_public_key = sender_pubkey.to_der()
        epm.identifier = identifier
        epm.nonce = nonce
        epm.signature = ''
        epm.signature = private_key.sign(epm.SerializeToString(), hashfunc=hashlib.sha256, sigencode=sigencode_der)

        return epm

    def get_decrypted_protocol_message(self, message, pubkey, privkey):

        try:
            decrypted = self.ecdh_decrypt(
                ciphertext=message.encrypted_message,
                nonce=message.nonce,
                pubkey=pubkey,
                privkey=privkey
            )
        except InvalidTag:
            self.fail("InvalidTag Exception Occurred While Decrypting Message")

        if not decrypted:
            self.fail('Unable to Decrypt Protocol Message')

        msg = None
        try:
            if message.message_type == ProtocolMessageType.Value('INVOICE_REQUEST'):
                msg = InvoiceRequest()
                msg.ParseFromString(decrypted)
            elif message.message_type == ProtocolMessageType.Value('PAYMENT_REQUEST'):
                msg = PaymentRequest()
                msg.ParseFromString(decrypted)
            elif message.message_type == ProtocolMessageType.Value('PAYMENT'):
                msg = Payment()
                msg.ParseFromString(decrypted)
            elif message.message_type == ProtocolMessageType.Value('PAYMENT_ACK'):
                msg = PaymentACK()
                msg.ParseFromString(decrypted)
        except:
            self.fail("Unable to Parse Decrpyted Serialized Payment Protocol Message")

        return msg

    def test_bip75_flow(self):

        ###################
        # Load Crypto Keys
        ###################
        self.x509_sender_cert = crypto.load_certificate(crypto.FILETYPE_PEM, SENDER_CERT)
        self.x509_sender_cert_privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, SENDER_CERT_PRIVKEY)

        self.x509_receiver_cert = crypto.load_certificate(crypto.FILETYPE_PEM, RECEIVER_CERT)
        self.x509_receiver_cert_privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, RECEIVER_CERT_PRIVKEY)

        ################################
        # Register Addressimo Endpoint
        ################################
        self.register_endpoint()

        #########################
        # Create InvoiceRequest
        #########################
        log.info("Building InvoiceRequest")

        sender_certs = X509Certificates()
        sender_certs.certificate.append(ssl.PEM_cert_to_DER_cert(crypto.dump_certificate(crypto.FILETYPE_PEM, self.x509_sender_cert)))

        invoice_request = InvoiceRequest()
        invoice_request.sender_public_key = BIP75FunctionalTest.sender_sk.get_verifying_key().to_der()
        invoice_request.amount = 75
        invoice_request.pki_type = 'x509+sha256'
        invoice_request.pki_data = sender_certs.SerializeToString()
        invoice_request.notification_url = 'https://notify.me/longId'
        invoice_request.signature = ""

        # Handle x509 Signature
        sig = crypto.sign(self.x509_sender_cert_privkey, invoice_request.SerializeToString(), 'sha256')
        invoice_request.signature = sig

        ##################################
        # Create Encrypted InvoiceRequest
        ##################################
        eir = self.create_encrypted_protocol_message(
            message=invoice_request,
            receiver_pubkey=BIP75FunctionalTest.receiver_sk.get_verifying_key(),
            sender_pubkey=BIP75FunctionalTest.sender_sk.get_verifying_key(),
            private_key=BIP75FunctionalTest.sender_sk
        )

        BIP75FunctionalTest.identifier = eir.identifier

        #############################
        # Sign & Submit HTTP Request
        #############################
        post_url = "%s/address/%s/resolve" % (self.get_server_url(), self.addressimo_endpoint_id)
        msg_sig = BIP75FunctionalTest.sender_sk.sign(self.get_signing_data(post_url, 'post',eir.SerializeToString()), hashfunc=sha256, sigencode=sigencode_der)

        ir_headers = {
            'X-Identity': BIP75FunctionalTest.sender_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': msg_sig.encode('hex'),
            'Content-Type': 'application/bitcoin-encrypted-paymentprotocol-message',
            'Content-Transfer-Encoding': 'binary'
        }
        log.info("Submitting InvoiceRequest using an EncryptedProtocolMessage")
        response = requests.post(post_url, headers=ir_headers, data=eir.SerializeToString())

        # Validate Response
        self.assertEqual(202, response.status_code)
        self.assertTrue(response.headers.get('Location').startswith('https://%s/paymentprotocol' % config.site_url))
        self.payment_id = response.headers.get('Location').rsplit('/', 1)[1]
        log.info('Payment ID: %s' % self.payment_id)

        ###############################################
        # Get Pending InvoiceRequests from Addressimo
        ###############################################
        sign_url = "%s/address/%s/paymentprotocol" % (self.get_server_url(), self.addressimo_endpoint_id)
        msg_sig = BIP75FunctionalTest.receiver_sk.sign(self.get_signing_data(sign_url, 'get'), hashfunc=sha256, sigencode=sigencode_der)

        ir_req_headers = {
            'X-Identity': BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': msg_sig.encode('hex')
        }

        log.info("Retrieving Encrypted InvoiceRequests")
        response = requests.get(sign_url, headers=ir_req_headers)

        log.info("Encrypted InvoiceRequest Retrieval Response [CODE: %d | TEXT: %s]" % (response.status_code, response.text))
        self.assertEqual(200, response.status_code)
        self.assertIsNotNone(response.text)

        ###############################################
        # Retrieve and Decrypt Encrypted InvoiceRequest
        ###############################################
        received_eir = None
        for epm in response.json()['encrypted_protocol_messages']:
            _local_msg = self.parse_protocol_message(epm.decode('hex'))
            if _local_msg.message_type == ProtocolMessageType.Value('INVOICE_REQUEST') and _local_msg.identifier == BIP75FunctionalTest.identifier:
                received_eir = _local_msg

        if not received_eir:
            self.fail('Failed to Retrieve Encrypted InvoiceRequest message')

        sender_vk = VerifyingKey.from_der(received_eir.sender_public_key)
        self.assertEqual(received_eir.receiver_public_key, BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der())

        received_invoice_request = self.get_decrypted_protocol_message(received_eir, sender_vk, BIP75FunctionalTest.receiver_sk)

        #########################
        # Create PaymentRequest
        #########################
        log.info("Building PaymentRequest")

        pd = PaymentDetails()
        pd.network = 'main'
        output = pd.outputs.add()
        output.amount = received_invoice_request.amount
        output.script = 'paymesomemoneyhere'.encode('hex')
        pd.time = int(datetime.utcnow().strftime('%s'))
        pd.expires = int((datetime.utcnow() + timedelta(seconds=3600)).strftime('%s'))
        pd.memo = ''
        pd.payment_url = ''
        pd.merchant_data = ''

        receiver_certs = X509Certificates()
        receiver_certs.certificate.append(ssl.PEM_cert_to_DER_cert(crypto.dump_certificate(crypto.FILETYPE_PEM, self.x509_receiver_cert)))

        pr = PaymentRequest()
        pr.payment_details_version = 1
        pr.pki_type = 'x509+sha256'
        pr.pki_data = receiver_certs.SerializeToString()
        pr.serialized_payment_details = pd.SerializeToString()
        pr.signature = ''

        sig = crypto.sign(self.x509_receiver_cert_privkey, pr.SerializeToString(), 'sha256')
        pr.signature = sig

        log.info('Encapsulating PaymentRequest in EncryptedProtocolMessage')
        epr = self.create_encrypted_protocol_message(
            message=pr,
            receiver_pubkey=BIP75FunctionalTest.receiver_sk.get_verifying_key(),
            sender_pubkey=BIP75FunctionalTest.sender_sk.get_verifying_key(),
            private_key=BIP75FunctionalTest.receiver_sk,
            identifier=BIP75FunctionalTest.identifier
        )

        sign_url = "%s/address/%s/paymentprotocol" % (self.get_server_url(), self.addressimo_endpoint_id)
        msg_sig = BIP75FunctionalTest.receiver_sk.sign(self.get_signing_data(sign_url, 'post', epr.SerializeToString()), hashfunc=sha256, sigencode=sigencode_der)

        ir_req_headers = {
            'X-Identity': BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': msg_sig.encode('hex'),
            'Content-Type': 'application/bitcoin-encrypted-paymentprotocol-message',
            'Content-Transfer-Encoding': 'binary'
        }

        log.info("Submitting PaymentRequest using an EncryptedProtocolMessage")
        response = requests.post(sign_url, data=epr.SerializeToString(), headers=ir_req_headers)
        log.info('Submit PaymentRequest Response: %s' % response.text)
        self.assertEqual(200, response.status_code)

        ##############################################################################
        # Delete InvoiceRequest after the PaymentRequest was submitted successfully
        ##############################################################################
        delete_url = "%s/address/%s/paymentprotocol/%s/invoice_request" % (self.get_server_url(), self.addressimo_endpoint_id, received_eir.identifier.encode('hex'))
        msg_sig = BIP75FunctionalTest.receiver_sk.sign(self.get_signing_data(delete_url, 'delete'), hashfunc=sha256, sigencode=sigencode_der)

        ir_delete_headers = {
            'X-Identity': BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': msg_sig.encode('hex')
        }
        response = requests.delete(delete_url, headers=ir_delete_headers)
        self.assertEqual(response.status_code, requests.codes.no_content)

        #####################################
        # Retrieve Encrypted PaymentRequest
        #####################################
        log.info("Retrieving PaymentRequest")

        sign_url = "%s/paymentprotocol/%s" % (self.get_server_url(), self.payment_id)
        msg_sig = BIP75FunctionalTest.sender_sk.sign(self.get_signing_data(sign_url, 'get'), hashfunc=sha256, sigencode=sigencode_der)
        get_message_headers = {
            'X-Identity': BIP75FunctionalTest.sender_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': msg_sig.encode('hex')
        }
        response = requests.get(sign_url, headers=get_message_headers)
        self.assertIsNotNone(response)

        self.assertIn('Content-Type', response.headers)
        self.assertEqual('application/json', response.headers.get('Content-Type'))

        received_epr = None
        for epm in response.json()['encrypted_protocol_messages']:
            _local_msg = self.parse_protocol_message(epm.decode('hex'))
            if _local_msg.message_type == ProtocolMessageType.Value('PAYMENT_REQUEST') and _local_msg.identifier == BIP75FunctionalTest.identifier:
                received_epr = _local_msg

        log.info('Received Encrypted PaymentRequest')

        self.assertEqual(BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der(), received_epr.receiver_public_key)
        self.assertEqual(BIP75FunctionalTest.sender_sk.get_verifying_key().to_der(), received_epr.sender_public_key)

        # Decrypt Response
        returned_paymentrequest = self.get_decrypted_protocol_message(
            message=received_epr,
            pubkey=VerifyingKey.from_der(received_epr.receiver_public_key),
            privkey=BIP75FunctionalTest.sender_sk
        )

        self.assertEqual(1, returned_paymentrequest.payment_details_version)
        self.assertEqual(pr.pki_type, returned_paymentrequest.pki_type)
        self.assertEqual(pr.pki_data, returned_paymentrequest.pki_data)
        self.assertEqual(pd.SerializeToString(), returned_paymentrequest.serialized_payment_details)
        self.assertEqual(pr.signature, returned_paymentrequest.signature)

        #######################################
        # Create / Submit Payment
        #######################################
        payment = Payment()
        payment.merchant_data = 'nodusttxs'.encode('hex')
        payment.transactions.append('btc_tx'.encode('hex'))
        out = payment.refund_to.add()
        out.script = 'myp2shaddress'.encode('hex')

        encrypted_payment = self.create_encrypted_protocol_message(
            message=payment,
            receiver_pubkey=VerifyingKey.from_der(received_epr.receiver_public_key),
            sender_pubkey=VerifyingKey.from_der(received_epr.sender_public_key),
            private_key=BIP75FunctionalTest.sender_sk,
            identifier=BIP75FunctionalTest.identifier
        )

        # Submit Payment
        sign_url = "%s/paymentprotocol/%s" % (self.get_server_url(), self.payment_id)
        msg_sig = BIP75FunctionalTest.sender_sk.sign(self.get_signing_data(sign_url, 'post', encrypted_payment.SerializeToString()), hashfunc=sha256, sigencode=sigencode_der)

        ep_req_headers = {
            'X-Identity': BIP75FunctionalTest.sender_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': msg_sig.encode('hex'),
            'Content-Type': 'application/bitcoin-encrypted-paymentprotocol-message',
            'Content-Transfer-Encoding': 'binary'
        }

        log.info("Submitting Payment using an EncryptedProtocolMessage")
        response = requests.post(sign_url, data=encrypted_payment.SerializeToString(), headers=ep_req_headers)
        log.info('Submit Payment Response: %s' % response.text)
        self.assertEqual(200, response.status_code)

        ##############################################################################
        # Delete PaymentRequest after the Payment was submitted successfully
        ##############################################################################
        delete_url = "%s/paymentprotocol/%s/%s/payment_request" % (self.get_server_url(), self.payment_id, received_eir.identifier.encode('hex'))
        msg_sig = BIP75FunctionalTest.receiver_sk.sign(self.get_signing_data(delete_url, 'delete'), hashfunc=sha256, sigencode=sigencode_der)

        ir_delete_headers = {
            'X-Identity': BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': msg_sig.encode('hex')
        }
        response = requests.delete(delete_url, headers=ir_delete_headers)
        self.assertEqual(response.status_code, requests.codes.no_content)

        ############################
        # Retrieve Payment
        ############################
        log.info("Retrieving Payment")

        sign_url = "%s/paymentprotocol/%s" % (self.get_server_url(), self.payment_id)
        msg_sig = BIP75FunctionalTest.receiver_sk.sign(self.get_signing_data(sign_url, 'get'), hashfunc=sha256, sigencode=sigencode_der)
        get_message_headers = {
            'X-Identity': BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': msg_sig.encode('hex')
        }

        response = requests.get(sign_url, headers=get_message_headers)
        self.assertIsNotNone(response)

        self.assertIn('Content-Type', response.headers)
        self.assertEqual('application/json', response.headers.get('Content-Type'))

        returned_ep = None
        for epm in response.json()['encrypted_protocol_messages']:
            _local_msg = self.parse_protocol_message(epm.decode('hex'))
            if _local_msg.message_type == ProtocolMessageType.Value('PAYMENT') and _local_msg.identifier == BIP75FunctionalTest.identifier:
                returned_ep = _local_msg

        self.assertEqual(BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der(), returned_ep.receiver_public_key)
        self.assertEqual(BIP75FunctionalTest.sender_sk.get_verifying_key().to_der(), returned_ep.sender_public_key)
        self.assertEqual(encrypted_payment.encrypted_message, returned_ep.encrypted_message)

        payment_msg = self.get_decrypted_protocol_message(
            message=returned_ep,
            pubkey=VerifyingKey.from_der(returned_ep.sender_public_key),
            privkey=BIP75FunctionalTest.receiver_sk
        )

        self.assertEqual('nodusttxs'.encode('hex'), payment_msg.merchant_data)
        self.assertEqual(1, len(payment_msg.transactions))
        self.assertEqual('btc_tx'.encode('hex'), payment_msg.transactions[0])


        #######################################
        # Create / Submit PaymentACK
        #######################################
        paymentack = PaymentACK()
        paymentack.payment.CopyFrom(payment_msg)
        paymentack.memo = 'Payment ACKed'

        encrypted_paymentack = self.create_encrypted_protocol_message(
            message=paymentack,
            receiver_pubkey=VerifyingKey.from_der(epr.receiver_public_key),
            sender_pubkey=VerifyingKey.from_der(epr.sender_public_key),
            private_key=BIP75FunctionalTest.receiver_sk,
            identifier=BIP75FunctionalTest.identifier
        )

        # Submit PaymentAck
        sign_url = "%s/paymentprotocol/%s" % (self.get_server_url(), self.payment_id)
        msg_sig = BIP75FunctionalTest.receiver_sk.sign(self.get_signing_data(sign_url, 'post', encrypted_paymentack.SerializeToString()), hashfunc=sha256, sigencode=sigencode_der)

        ep_req_headers = {
            'X-Identity': BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': msg_sig.encode('hex'),
            'Content-Type': 'application/bitcoin-encrypted-paymentprotocol-message',
            'Content-Transfer-Encoding': 'binary'
        }

        log.info("Submitting PaymentAck using an EncryptedProtocolMessage")
        response = requests.post(sign_url, data=encrypted_paymentack.SerializeToString(), headers=ep_req_headers)
        log.info('Submit PaymentAck Response: %s' % response.text)
        self.assertEqual(200, response.status_code)

        ##############################################################################
        # Delete Payment after the PaymentACK was submitted successfully
        ##############################################################################
        delete_url = "%s/address/%s/paymentprotocol/%s/payment" % (self.get_server_url(), self.addressimo_endpoint_id, received_eir.identifier.encode('hex'))
        msg_sig = BIP75FunctionalTest.receiver_sk.sign(self.get_signing_data(delete_url, 'delete'), hashfunc=sha256, sigencode=sigencode_der)

        ir_delete_headers = {
            'X-Identity': BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': msg_sig.encode('hex')
        }
        response = requests.delete(delete_url, headers=ir_delete_headers)
        self.assertEqual(response.status_code, requests.codes.no_content)

        ###############################
        # Retrieve PaymentAck
        ###############################
        log.info("Retrieving EncryptedPaymentAck")
        sign_url = "%s/paymentprotocol/%s" % (self.get_server_url(), self.payment_id)
        msg_sig = BIP75FunctionalTest.receiver_sk.sign(self.get_signing_data(sign_url, 'get'), hashfunc=sha256, sigencode=sigencode_der)
        get_message_headers = {
            'X-Identity': BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': msg_sig.encode('hex')
        }
        response = requests.get(sign_url, headers=get_message_headers)
        self.assertIsNotNone(response)

        self.assertIn('Content-Type', response.headers)
        self.assertEqual('application/json', response.headers.get('Content-Type'))

        returned_epa = None
        for epm in response.json()['encrypted_protocol_messages']:
            _local_msg = self.parse_protocol_message(epm.decode('hex'))
            if _local_msg.message_type == ProtocolMessageType.Value('PAYMENT_ACK') and _local_msg.identifier == BIP75FunctionalTest.identifier:
                returned_epa = _local_msg

        log.info('Received PaymentACK')

        self.assertEqual(BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der(), returned_ep.receiver_public_key)
        self.assertEqual(BIP75FunctionalTest.sender_sk.get_verifying_key().to_der(), returned_ep.sender_public_key)
        self.assertEqual(encrypted_paymentack.encrypted_message, returned_epa.encrypted_message)

        paymentack_msg = self.get_decrypted_protocol_message(
            message=returned_epa,
            pubkey=VerifyingKey.from_der(returned_epa.sender_public_key),
            privkey=BIP75FunctionalTest.receiver_sk
        )
        self.assertEqual(paymentack_msg, paymentack)

        ##############################################################################
        # Delete PaymentACK after the PaymentACK was retrieved successfully
        ##############################################################################
        delete_url = "%s/address/%s/paymentprotocol/%s/payment_ack" % (self.get_server_url(), self.addressimo_endpoint_id, received_eir.identifier.encode('hex'))
        msg_sig = BIP75FunctionalTest.receiver_sk.sign(self.get_signing_data(delete_url, 'delete'), hashfunc=sha256, sigencode=sigencode_der)

        ir_delete_headers = {
            'X-Identity': BIP75FunctionalTest.receiver_sk.get_verifying_key().to_der().encode('hex'),
            'X-Signature': msg_sig.encode('hex')
        }
        response = requests.delete(delete_url, headers=ir_delete_headers)
        self.assertEqual(response.status_code, requests.codes.no_content)

        ################################
        # Delete Addressimo Endpoint
        ################################
        self.cleanup_endpoint()

if __name__ == '__main__':

    unittest.main()