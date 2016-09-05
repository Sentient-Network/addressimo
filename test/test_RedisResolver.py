__author__ = 'frank'

# System Imports
import json
from mock import Mock, patch, MagicMock
from test import AddressimoTestCase

from addressimo.resolvers.RedisResolver import *

TEST_PUBKEY1 = 'ac79cd6b0ac5f2a6234996595cb2d91fceaa0b9d9a6495f12f1161c074587bd19ae86928bddea635c930c09ea9c7de1a6a9c468f9afd18fbaeed45d09564ded6'
TEST_PUBKEY2 = 'ac79c8e1c63bec45fd2a90b459c5c4143528bc61a5e44a4818af76cd553c3023be7ca81ebe37abe38b9c797e7fb030cd3d40192455088b485a03a3b7ea4892b5'

class TestGetPluginName(AddressimoTestCase):
    def test_get_plugin_name(self):

        ret_val = RedisResolver.get_plugin_name()
        self.assertEqual('REDIS', ret_val)


class TestGetAllKeys(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.Redis')

        self.mockRedis = self.patcher1.start()

        # Setup redis data
        self.mockRedis.from_url.return_value.keys.return_value = ['1', '2', '3']

        # Setup redis resolver
        self.rr = RedisResolver()

    def test_go_right(self):

        self.assertListEqual(['1', '2', '3'], self.rr.get_all_keys())


class TestGetIdObj(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.Redis')

        self.mockRedis = self.patcher1.start()

        # Setup redis data
        self.mockJSONData = {'bip70_enabled': True, 'last_generated_index': 10}
        self.mockRedis.from_url.return_value.get.return_value = json.dumps(self.mockJSONData)

        # Setup redis resolver
        self.rr = RedisResolver()

    def test_go_right(self):

        ret_obj = self.rr.get_id_obj('id')

        # Validate calls
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual('id', self.mockRedis.from_url.return_value.get.call_args[0][0])

        # Verify id_obj updated with Redis data
        self.assertTrue(ret_obj.bip70_enabled)
        self.assertEqual(10, ret_obj.last_generated_index)

    def test_no_results_for_id_obj(self):

        # Setup test case
        self.mockRedis.from_url.return_value.get.return_value = None

        ret_obj = self.rr.get_id_obj('id')

        # Validate calls
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual('id', self.mockRedis.from_url.return_value.get.call_args[0][0])

        # Verify id_obj is None
        self.assertIsNone(ret_obj)

    def test_exception_retrieving_id_obj(self):

        # Setup test case
        self.mockRedis.from_url.return_value.get.side_effect = Exception()

        ret_obj = self.rr.get_id_obj('id')

        # Validate calls
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual('id', self.mockRedis.from_url.return_value.get.call_args[0][0])

        # Verify id_obj is None
        self.assertIsNone(ret_obj)


class TestGetBranches(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.Redis')

        self.mockRedis = self.patcher1.start()

        # Setup redis return data
        self.mockRedis.from_url.return_value.hkeys.return_value = ['123', '456']

        # Setup redis resolver
        self.rr = RedisResolver()

    def test_go_right(self):

        ret_val = self.rr.get_branches(111)

        self.assertListEqual([123, 456], ret_val)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hkeys.call_count)
        self.assertEqual(111, self.mockRedis.from_url.return_value.hkeys.call_args[0][0])

    def test_no_branches_present(self):

        # Setup test case
        self.mockRedis.from_url.return_value.hkeys.return_value = None

        ret_val = self.rr.get_branches(111)

        self.assertListEqual([], ret_val)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hkeys.call_count)
        self.assertEqual(111, self.mockRedis.from_url.return_value.hkeys.call_args[0][0])

    def test_exception_retrieving_branches(self):

        # Setup test case
        self.mockRedis.from_url.return_value.hkeys.side_effect = Exception('Lookup failed')

        ret_val = self.rr.get_branches(111)

        self.assertListEqual([], ret_val)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hkeys.call_count)
        self.assertEqual(111, self.mockRedis.from_url.return_value.hkeys.call_args[0][0])


class TestGetLGIndex(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.Redis')

        self.mockRedis = self.patcher1.start()

        # Setup redis return data
        self.mockRedis.from_url.return_value.hget.return_value = '5'

        # Setup redis resolver
        self.rr = RedisResolver()

    def test_go_right(self):

        ret_val = self.rr.get_lg_index(111, 1234)

        self.assertEqual(5, ret_val)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hget.call_count)
        self.assertEqual((111, 1234), self.mockRedis.from_url.return_value.hget.call_args[0])

    def test_hget_returns_none(self):

        # Setup Test case
        self.mockRedis.from_url.return_value.hget.return_value = None

        ret_val = self.rr.get_lg_index(111, 1234)

        self.assertEqual(0, ret_val)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hget.call_count)
        self.assertEqual((111, 1234), self.mockRedis.from_url.return_value.hget.call_args[0])

    def test_exception_retrieving_lg_index(self):

        # Setup Test case
        self.mockRedis.from_url.return_value.hget.side_effect = Exception('Exception retrieving lg_index')

        ret_val = self.rr.get_lg_index(111, 1234)

        self.assertEqual(0, ret_val)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hget.call_count)
        self.assertEqual((111, 1234), self.mockRedis.from_url.return_value.hget.call_args[0])


class TestSetLGIndex(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.Redis')

        self.mockRedis = self.patcher1.start()

        # Setup redis resolver
        self.rr = RedisResolver()

    def test_go_right(self):

        ret_val = self.rr.set_lg_index(10, 123456, 7)

        self.assertIsNotNone(ret_val)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hset.call_count)
        self.assertEqual((10, 123456, 7), self.mockRedis.from_url.return_value.hset.call_args[0])

    def test_exception_saving_lg_index(self):

        # Setup Test case
        self.mockRedis.from_url.return_value.hset.side_effect = Exception('Exception saving lg_index')

        ret_val = self.rr.set_lg_index(10, 123456, 7)

        self.assertIsNone(ret_val)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hset.call_count)
        self.assertEqual((10, 123456, 7), self.mockRedis.from_url.return_value.hset.call_args[0])


class TestSave(AddressimoTestCase):

    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.Redis')
        self.patcher2 = patch('addressimo.resolvers.RedisResolver.RedisResolver.generate_unique_id')

        self.mockRedis = self.patcher1.start()
        self.mockGenerateUniqueId = self.patcher2.start()

        from addressimo.data import IdObject

        # Setup redis data
        self.mock_id_obj = IdObject('id')
        self.mock_id_obj.id = 'id'
        self.mock_id_obj.bip70_enabled = True
        self.mock_id_obj.last_generated_index = 10

        # Setup redis resolver
        self.rr = RedisResolver()

    def test_go_right(self):

        ret_val = self.rr.save(self.mock_id_obj)

        # Validate calls
        self.assertEqual(self.mockRedis.from_url.return_value.set.return_value, ret_val)
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.set.call_count)
        call_args = self.mockRedis.from_url.return_value.set.call_args[0]
        self.assertEqual(self.mock_id_obj.id, call_args[0])
        self.assertEqual(json.dumps(self.mock_id_obj), call_args[1])
        self.assertFalse(self.mockGenerateUniqueId.called)

    def test_exception_saving_redis_data(self):

        # Setup test case
        self.mockRedis.from_url.return_value.set.side_effect = Exception()

        self.assertRaises(Exception, self.rr.save, self.mock_id_obj)

        # Validate calls
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.set.call_count)
        call_args = self.mockRedis.from_url.return_value.set.call_args[0]
        self.assertEqual(self.mock_id_obj.id, call_args[0])
        self.assertEqual(json.dumps(self.mock_id_obj), call_args[1])


class TestDelete(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.Redis')

        self.mockRedis = self.patcher1.start()

        from addressimo.data import IdObject

        # Setup redis data
        self.mock_id_obj = IdObject('id')
        self.mock_id_obj.id = 'id'

        # Setup redis resolver
        self.rr = RedisResolver()

    def test_go_right(self):

        ret_val = self.rr.delete(self.mock_id_obj)

        # Validate calls
        self.assertEqual(self.mockRedis.from_url.return_value.delete.return_value, ret_val)
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.delete.call_count)
        call_args = self.mockRedis.from_url.return_value.delete.call_args[0]
        self.assertEqual(self.mock_id_obj.id, call_args[0])

    def test_exception_saving_redis_data(self):

        # Setup test case
        self.mockRedis.from_url.return_value.delete.side_effect = Exception()

        self.assertRaises(Exception, self.rr.delete, self.mock_id_obj)

        # Validate calls
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.delete.call_count)
        call_args = self.mockRedis.from_url.return_value.delete.call_args[0]
        self.assertEqual(self.mock_id_obj.id, call_args[0])

#################################################
# Payment Protocol Implementation (BIP75) Tests
#################################################
class TestGetPaymentProtocolMessages(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.resolvers.RedisResolver.b64decode')
        self.patcher2 = patch('addressimo.resolvers.RedisResolver.Redis')

        self.mockB64decode = self.patcher1.start()
        self.mockRedis = self.patcher2.start()

        self.mockTxMapClient = MagicMock()
        self.mockTxClient = MagicMock()

        # Setup Mock Redis Data
        self.mockTxMapClient.llen.return_value = 1
        self.mockTxMapClient.lrange.return_value = ['mapped_tx_id']
        self.mockTxClient.hgetall.return_value = {'key':'val', 'messages': json.dumps(['1', '2'])}

        self.rr = RedisResolver()
        self.rr.tx_map_client = self.mockTxMapClient
        self.rr.tx_client = self.mockTxClient

    def test_id_go_right(self):

        ret = self.rr.get_paymentprotocol_messages(id='id')

        self.assertEqual(1, self.mockTxMapClient.llen.call_count)
        self.assertEqual('id', self.mockTxMapClient.llen.call_args[0][0])
        self.assertEqual(1, self.mockTxMapClient.lrange.call_count)
        self.assertEqual('id', self.mockTxMapClient.lrange.call_args[0][0])
        self.assertEqual(0, self.mockTxMapClient.lrange.call_args[0][1])
        self.assertEqual(0, self.mockTxMapClient.lrange.call_args[0][2])

        self.assertEqual(1, self.mockTxClient.hgetall.call_count)
        self.assertEqual('mapped_tx_id', self.mockTxClient.hgetall.call_args[0][0])

        self.assertIsNotNone(ret)
        self.assertEqual(1, len(ret.keys()))
        self.assertIn('mapped_tx_id', ret)
        self.assertEqual('val', ret['mapped_tx_id']['key'])
        self.assertEqual([self.mockB64decode.return_value, self.mockB64decode.return_value], ret['mapped_tx_id']['messages'])

    def test_tx_id_go_right(self):

        ret = self.rr.get_paymentprotocol_messages(tx_id='tx_id')

        self.assertEqual(0, self.mockTxMapClient.llen.call_count)
        self.assertEqual(0, self.mockTxMapClient.lrange.call_count)

        self.assertEqual(1, self.mockTxClient.hgetall.call_count)
        self.assertEqual('tx_id', self.mockTxClient.hgetall.call_args[0][0])

        self.assertIsNotNone(ret)
        self.assertEqual(1, len(ret.keys()))
        self.assertIn('tx_id', ret)
        self.assertEqual('val', ret['tx_id']['key'])
        self.assertEqual([self.mockB64decode.return_value, self.mockB64decode.return_value], ret['tx_id']['messages'])

    def test_no_tx_ids(self):

        self.mockTxMapClient.llen.return_value = 0

        ret = self.rr.get_paymentprotocol_messages(id='id')

        self.assertEqual(1, self.mockTxMapClient.llen.call_count)
        self.assertEqual(0, self.mockTxMapClient.lrange.call_count)
        self.assertEqual(0, self.mockTxClient.hgetall.call_count)
        self.assertEqual({}, ret)

    def test_no_tx_data(self):

        self.mockTxClient.hgetall.return_value = None
        ret = self.rr.get_paymentprotocol_messages(id='id')
        self.assertEqual({}, ret)

    def test_no_messages(self):

        del self.mockTxClient.hgetall.return_value['messages']
        ret = self.rr.get_paymentprotocol_messages(id='id')
        self.assertEqual('val', ret['mapped_tx_id']['key'])
        self.assertEqual([], ret['mapped_tx_id']['messages'])

class TestAddPaymentProtocolMessage(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.resolvers.RedisResolver.b64encode')
        self.patcher2 = patch('addressimo.resolvers.RedisResolver.Redis')
        self.patcher3 = patch('addressimo.resolvers.RedisResolver.RedisResolver.generate_unique_id')
        self.patcher4 = patch('addressimo.resolvers.RedisResolver.datetime')

        self.mockB64encode = self.patcher1.start()
        self.mockRedis = self.patcher2.start()
        self.mockGenerateUniqueId = self.patcher3.start()
        self.mockDatetime = self.patcher4.start()

        self.mockTxMapClient = MagicMock()
        self.mockTxClient = MagicMock()

        # Setup Mock Redis Data
        self.mockTxMapClient.llen.return_value = 1
        self.mockTxMapClient.lrange.return_value = ['mapped_tx_id']
        self.mockTxClient.hgetall.return_value = {'key': 'val', 'messages': json.dumps(['1', '2'])}
        self.mockTxClient.hget.return_value = 'msg_identifier'

        self.rr = RedisResolver()
        self.rr.tx_map_client = self.mockTxMapClient
        self.rr.tx_client = self.mockTxClient

        self.mockGenerateUniqueId.return_value = 'unique_id'

        self.message = EncryptedProtocolMessage()
        self.message.version = 1
        self.message.status_code = 1
        self.message.message_type = ProtocolMessageType.Value('INVOICE_REQUEST')
        self.message.encrypted_message = 'deadbeef'
        self.message.receiver_public_key = 'deadbeef'
        self.message.sender_public_key = 'deadbeef'
        self.message.identifier = 'msg_identifier'
        self.message.nonce = 42

        self.non_encrypted_message = ProtocolMessage()
        self.non_encrypted_message.version = 1
        self.non_encrypted_message.status_code = 1
        self.non_encrypted_message.message_type = ProtocolMessageType.Value('INVOICE_REQUEST')
        self.non_encrypted_message.serialized_message = 'deadbeef'
        self.non_encrypted_message.identifier = 'msg_identifier'

        self.mockB64encode.return_value = 'base64encoded_result'
        self.mockDatetime.utcnow.return_value.strftime.return_value = 'utcnow'

    def test_go_right_tx_id_existing_tx(self):

        ret = self.rr.add_paymentprotocol_message(self.message, tx_id='tx_id')

        self.assertEqual('tx_id', ret)

        self.assertEqual(0, self.mockTxMapClient.llen.call_count)
        self.assertEqual(0, self.mockTxMapClient.lrange.call_count)

        self.assertEqual(1, self.mockTxClient.hget.call_count)
        self.assertEqual('tx_id', self.mockTxClient.hget.call_args[0][0])
        self.assertEqual('identifier', self.mockTxClient.hget.call_args[0][1])

        self.assertEqual(1, self.mockTxClient.hgetall.call_count)
        self.assertEqual('tx_id', self.mockTxClient.hgetall.call_args[0][0])

        self.assertEqual(1, self.mockB64encode.call_count)
        self.assertEqual(self.message.SerializeToString(), self.mockB64encode.call_args[0][0])

        self.assertEqual(3, len(json.loads(self.mockTxClient.hgetall.return_value['messages'])))
        self.assertIn('base64encoded_result', json.loads(self.mockTxClient.hgetall.return_value['messages']))
        self.assertEqual('utcnow', self.mockTxClient.hgetall.return_value['last_updated'])
        self.assertEqual(42, self.mockTxClient.hgetall.return_value['last_nonce'])

    def test_go_right_id_new_tx_invoicerequest(self):

        self.mockTxClient.hget.return_value = 'another_identifier'

        ret = self.rr.add_paymentprotocol_message(self.message, id='id')

        self.assertEqual('unique_id', ret)

        self.assertEqual(1, self.mockTxMapClient.llen.call_count)
        self.assertEqual('id', self.mockTxMapClient.llen.call_args[0][0])
        self.assertEqual(1, self.mockTxMapClient.lrange.call_count)

        self.assertEqual('id', self.mockTxMapClient.lrange.call_args[0][0])
        self.assertEqual(0, self.mockTxMapClient.lrange.call_args[0][1])
        self.assertEqual(0, self.mockTxMapClient.lrange.call_args[0][2])

        self.assertEqual(1, self.mockTxClient.hget.call_count)
        self.assertEqual('mapped_tx_id', self.mockTxClient.hget.call_args[0][0])
        self.assertEqual('identifier', self.mockTxClient.hget.call_args[0][1])

        self.assertEqual(0, self.mockTxClient.hgetall.call_count)

        self.assertEqual(1, self.mockB64encode.call_count)
        self.assertEqual(self.message.SerializeToString(), self.mockB64encode.call_args[0][0])

        self.assertEqual(1, self.mockGenerateUniqueId.call_count)
        self.assertEqual(1, self.mockTxClient.hmset.call_count)
        self.assertEqual('unique_id', self.mockTxClient.hmset.call_args[0][0])
        self.assertIn('base64encoded_result', json.loads(self.mockTxClient.hmset.call_args[0][1]['messages']))
        self.assertEqual('id', self.mockTxClient.hmset.call_args[0][1]['receiver'])
        self.assertEqual('msg_identifier', self.mockTxClient.hmset.call_args[0][1]['identifier'])
        self.assertEqual('utcnow', self.mockTxClient.hmset.call_args[0][1]['last_updated'])
        self.assertEqual(42, self.mockTxClient.hmset.call_args[0][1]['last_nonce'])

        self.assertEqual(1, self.mockTxMapClient.rpush.call_count)
        self.assertEqual('id', self.mockTxMapClient.rpush.call_args[0][0])
        self.assertEqual('unique_id', self.mockTxMapClient.rpush.call_args[0][1])

    def test_id_new_tx_paymentrequest(self):

        self.mockTxClient.hget.return_value = 'another_identifier'
        self.message.message_type = ProtocolMessageType.Value('PAYMENT_REQUEST')

        ret = self.rr.add_paymentprotocol_message(self.message, id='id')

        self.assertIsNone(ret)

        self.assertEqual(1, self.mockTxMapClient.llen.call_count)
        self.assertEqual('id', self.mockTxMapClient.llen.call_args[0][0])
        self.assertEqual(1, self.mockTxMapClient.lrange.call_count)

        self.assertEqual('id', self.mockTxMapClient.lrange.call_args[0][0])
        self.assertEqual(0, self.mockTxMapClient.lrange.call_args[0][1])
        self.assertEqual(0, self.mockTxMapClient.lrange.call_args[0][2])

        self.assertEqual(1, self.mockTxClient.hget.call_count)
        self.assertEqual('mapped_tx_id', self.mockTxClient.hget.call_args[0][0])
        self.assertEqual('identifier', self.mockTxClient.hget.call_args[0][1])

        self.assertEqual(0, self.mockB64encode.call_count)
        self.assertEqual(0, self.mockGenerateUniqueId.call_count)

    def test_id_new_tx_invoicerequest_non_encrypted(self):

        self.mockTxClient.hget.return_value = 'another_identifier'
        self.rr.add_paymentprotocol_message(self.non_encrypted_message, id='id')
        self.assertNotIn('last_nonce', self.mockTxClient.hmset.call_args[0][1])

    def test_tx_id_existing_tx_non_encrypted(self):

        self.rr.add_paymentprotocol_message(self.non_encrypted_message, tx_id='tx_id')
        self.assertNotIn('last_nonce', self.mockTxClient.hmset.call_args[0][1])

class TestDeletePaymentProtocolMessage(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.resolvers.RedisResolver.RedisResolver.get_paymentprotocol_messages')
        self.patcher2 = patch('addressimo.resolvers.RedisResolver.Redis')
        self.patcher3 = patch('addressimo.resolvers.RedisResolver.b64encode')

        self.mockGetPaymentProtocolMessages = self.patcher1.start()
        self.mockRedis = self.patcher2.start()
        self.mockB64Encode = self.patcher3.start()

        self.mockB64Encode.return_value = 'b64encoded'

        self.mockTxMapClient = MagicMock()
        self.mockTxClient = MagicMock()

        # Setup Mock Redis Data
        self.mockTxMapClient.llen.return_value = 1
        self.mockTxMapClient.lrange.return_value = ['mapped_tx_id']
        self.mockTxClient.hgetall.return_value = {'key': 'val', 'messages': json.dumps(['1', '2'])}
        self.mockTxClient.hget.return_value = 'msg_identifier'

        self.rr = RedisResolver()
        self.rr.tx_map_client = self.mockTxMapClient
        self.rr.tx_client = self.mockTxClient

        # Setup Protocol Messages
        self.message = EncryptedProtocolMessage()
        self.message.version = 1
        self.message.status_code = 1
        self.message.message_type = ProtocolMessageType.Value('PAYMENT_REQUEST')
        self.message.encrypted_message = 'deadbeef'
        self.message.receiver_public_key = 'deadbeef'
        self.message.sender_public_key = 'deadbeef'
        self.message.identifier = 'msg_identifier'
        self.message.nonce = 42

        self.non_encrypted_message = ProtocolMessage()
        self.non_encrypted_message.version = 1
        self.non_encrypted_message.status_code = 1
        self.non_encrypted_message.message_type = ProtocolMessageType.Value('INVOICE_REQUEST')
        self.non_encrypted_message.serialized_message = 'deadbeef'
        self.non_encrypted_message.identifier = 'msg_identifier'

        self.mockGetPaymentProtocolMessages.return_value = {
            'tx_id1': {
                'receiver': 'receiver_id',
                'messages': [self.non_encrypted_message.SerializeToString(), self.message.SerializeToString()]
            }
        }

    def test_go_right(self):

        ret = self.rr.delete_paymentprotocol_message('msg_identifier', 'invoice_request', id='id')

        self.assertTrue(ret)

        self.assertEqual(1, self.mockGetPaymentProtocolMessages.call_count)
        self.assertEqual('id', self.mockGetPaymentProtocolMessages.call_args[0][0])

        self.assertEqual(0, self.mockTxClient.delete.call_count)
        self.assertEqual(0, self.mockTxMapClient.lrem.call_count)

        self.assertEqual(1, self.mockB64Encode.call_count)

        self.assertEqual(1, self.mockTxClient.hmset.call_count)
        self.assertEqual('tx_id1', self.mockTxClient.hmset.call_args[0][0])
        self.assertEqual(1, len(json.loads(self.mockTxClient.hmset.call_args[0][1]['messages'])))
        self.assertEqual('b64encoded', json.loads(self.mockTxClient.hmset.call_args[0][1]['messages'])[0])

    def test_empty_tx_after_delete(self):

        self.mockGetPaymentProtocolMessages.return_value['tx_id1']['messages'] = [self.non_encrypted_message.SerializeToString()]

        ret = self.rr.delete_paymentprotocol_message('msg_identifier', 'invoice_request', id='id')

        self.assertTrue(ret)

        self.assertEqual(1, self.mockGetPaymentProtocolMessages.call_count)
        self.assertEqual('id', self.mockGetPaymentProtocolMessages.call_args[0][0])

        self.assertEqual(1, self.mockTxClient.delete.call_count)
        self.assertEqual('tx_id1', self.mockTxClient.delete.call_args[0][0])

        self.assertEqual(1, self.mockTxMapClient.lrem.call_count)
        self.assertEqual('id', self.mockTxMapClient.lrem.call_args[0][0])
        self.assertEqual('tx_id1', self.mockTxMapClient.lrem.call_args[0][1])
        self.assertEqual(0, self.mockTxMapClient.lrem.call_args[0][2])

        self.assertEqual(0, self.mockB64Encode.call_count)
        self.assertEqual(0, self.mockTxClient.hmset.call_count)

    def test_empty_tx_after_delete_passing_in_tx_id(self):

        self.mockGetPaymentProtocolMessages.return_value['tx_id1']['messages'] = [self.non_encrypted_message.SerializeToString()]

        ret = self.rr.delete_paymentprotocol_message('msg_identifier', 'invoice_request', tx_id='in_id')

        self.assertTrue(ret)

        self.assertEqual(1, self.mockGetPaymentProtocolMessages.call_count)
        self.assertEqual('in_id', self.mockGetPaymentProtocolMessages.call_args[0][1])

        self.assertEqual(1, self.mockTxClient.delete.call_count)
        self.assertEqual('tx_id1', self.mockTxClient.delete.call_args[0][0])

        self.assertEqual(1, self.mockTxMapClient.lrem.call_count)
        self.assertEqual('receiver_id', self.mockTxMapClient.lrem.call_args[0][0])
        self.assertEqual('tx_id1', self.mockTxMapClient.lrem.call_args[0][1])
        self.assertEqual(0, self.mockTxMapClient.lrem.call_args[0][2])

        self.assertEqual(0, self.mockB64Encode.call_count)
        self.assertEqual(0, self.mockTxClient.hmset.call_count)

    def test_not_updates(self):

        ret = self.rr.delete_paymentprotocol_message('msg_identifier', 'payment_ack', id='id')

        self.assertFalse(ret)

        self.assertEqual(1, self.mockGetPaymentProtocolMessages.call_count)
        self.assertEqual('id', self.mockGetPaymentProtocolMessages.call_args[0][0])

        self.assertEqual(0, self.mockTxClient.delete.call_count)
        self.assertEqual(0, self.mockTxMapClient.lrem.call_count)
        self.assertEqual(0, self.mockB64Encode.call_count)
        self.assertEqual(0, self.mockTxClient.hmset.call_count)


class TestCleanupStalePaymentProtocolMessages(AddressimoTestCase):

    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.RedisResolver.get_paymentprotocol_messages')
        self.patcher2 = patch('addressimo.resolvers.RedisResolver.Redis')
        self.patcher3 = patch('addressimo.resolvers.RedisResolver.datetime')

        self.mockGetPaymentProtocolMessages = self.patcher1.start()
        self.mockRedis = self.patcher2.start()
        self.mockDatetime = self.patcher3.start()

        self.mockDatetime.utcfromtimestamp.return_value = datetime(year=2016, month=1, day=15)
        self.mockDatetime.utcnow.return_value = datetime(year=2016, month=1, day=30)

        self.mockTxMapClient = MagicMock()
        self.mockTxClient = MagicMock()

        # Setup Mock Redis Data
        self.mockTxClient.scan_iter.return_value = ['tx_id1']
        self.mockTxClient.hgetall.return_value = {
            'last_updated': 'na',
            'receiver': 'receiver_id'
        }

        self.rr = RedisResolver()
        self.rr.tx_map_client = self.mockTxMapClient
        self.rr.tx_client = self.mockTxClient

    def test_go_right(self):

        ret = self.rr.cleanup_stale_paymentprotocol_messages()

        self.assertEqual(1, ret)

        self.assertEqual(1, self.mockTxClient.scan_iter.call_count)
        self.assertEqual(1, self.mockTxClient.hgetall.call_count)
        self.assertEqual('tx_id1', self.mockTxClient.hgetall.call_args[0][0])

        self.assertEqual(1, self.mockDatetime.utcfromtimestamp.call_count)

        self.assertEqual(1, self.mockTxClient.delete.call_count)
        self.assertEqual('tx_id1', self.mockTxClient.delete.call_args[0][0])

        self.assertEqual(1, self.mockTxMapClient.lrem.call_count)
        self.assertEqual('receiver_id', self.mockTxMapClient.lrem.call_args[0][0])
        self.assertEqual('tx_id1', self.mockTxMapClient.lrem.call_args[0][1])

    def test_tx_not_ready_for_deletion(self):

        self.mockDatetime.utcfromtimestamp.return_value = datetime(year=2016, month=1, day=29)

        ret = self.rr.cleanup_stale_paymentprotocol_messages()

        self.assertEqual(0, ret)

        self.assertEqual(1, self.mockTxClient.scan_iter.call_count)
        self.assertEqual(1, self.mockTxClient.hgetall.call_count)
        self.assertEqual('tx_id1', self.mockTxClient.hgetall.call_args[0][0])

        self.assertEqual(1, self.mockDatetime.utcfromtimestamp.call_count)

        self.assertEqual(0, self.mockTxClient.delete.call_count)

    def test_no_txs(self):

        self.mockTxClient.scan_iter.return_value = []

        ret = self.rr.cleanup_stale_paymentprotocol_messages()

        self.assertEqual(0, self.mockTxClient.hgetall.call_count)
        self.assertEqual(0, ret)

class TestGetTxLastNonce(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.resolvers.RedisResolver.RedisResolver.get_paymentprotocol_messages')
        self.patcher2 = patch('addressimo.resolvers.RedisResolver.Redis')

        self.mockGetPaymentProtocolMessages = self.patcher1.start()
        self.mockRedis = self.patcher2.start()

        self.mockGetPaymentProtocolMessages.return_value = {
            'tx_id1': {
                'identifier': 'msg_identifier',
                'last_nonce': 42
            }
        }

        self.rr = RedisResolver()

        self.message = ProtocolMessage()
        self.message.identifier = 'msg_identifier'

    def test_go_right(self):

        ret = self.rr.get_tx_last_nonce(self.message, 'id', 'tx_id')

        self.assertEqual(42, ret)

        self.assertEqual(1, self.mockGetPaymentProtocolMessages.call_count)
        self.assertEqual('id', self.mockGetPaymentProtocolMessages.call_args[0][0])
        self.assertEqual('tx_id', self.mockGetPaymentProtocolMessages.call_args[0][1])

    def test_no_matching_id(self):

        self.message.identifier = 'other_identifier'

        ret = self.rr.get_tx_last_nonce(self.message, 'id', 'tx_id')

        self.assertIsNone(ret)

        self.assertEqual(1, self.mockGetPaymentProtocolMessages.call_count)
        self.assertEqual('id', self.mockGetPaymentProtocolMessages.call_args[0][0])
        self.assertEqual('tx_id', self.mockGetPaymentProtocolMessages.call_args[0][1])

    def test_no_returned_tx_data(self):

        self.mockGetPaymentProtocolMessages.return_value = []

        ret = self.rr.get_tx_last_nonce(self.message, 'id', 'tx_id')

        self.assertIsNone(ret)

        self.assertEqual(1, self.mockGetPaymentProtocolMessages.call_count)
        self.assertEqual('id', self.mockGetPaymentProtocolMessages.call_args[0][0])
        self.assertEqual('tx_id', self.mockGetPaymentProtocolMessages.call_args[0][1])

class TestGetPaymentRequestMetaData(AddressimoTestCase):

    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.Redis')

        self.mockRedis = self.patcher1.start()

        self.mockRedis.from_url.return_value.hgetall.return_value = json.dumps({"key": "value"})

        # Setup redis resolver
        self.rr = RedisResolver()

    def test_go_right(self):

        ret_val = self.rr.get_payment_request_meta_data('uuid')

        self.assertDictEqual({'key': 'value'}, json.loads(ret_val))
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hgetall.call_count)
        self.assertEqual('uuid', self.mockRedis.from_url.return_value.hgetall.call_args[0][0])


class TestSetPaymentRequestMetaData(AddressimoTestCase):

    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.Redis')
        self.patcher3 = patch('addressimo.resolvers.RedisResolver.datetime')
        self.patcher4 = patch('addressimo.resolvers.RedisResolver.RedisResolver.generate_unique_id')

        self.mockRedis = self.patcher1.start()
        self.mockDatetime = self.patcher3.start()
        self.mockGenerateUniqueId = self.patcher4.start()

        self.mockRedis.from_url.return_value.hkeys.return_value = False
        self.mockGenerateUniqueId.return_value = 'abc123abc123'

        self.now = self.mockDatetime.utcnow.return_value = datetime.utcnow()

        # Setup redis resolver
        self.rr = RedisResolver()

    def test_go_right_one_iteration(self):

        ret_val = self.rr.set_payment_request_meta_data(int(self.now.strftime('%s')), 'wallet_addr', 'amount')

        # Validate return data
        self.assertEqual('abc123abc123', ret_val)

        # Validate call count
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hmset.call_count)
        self.assertEqual(1, self.mockGenerateUniqueId.call_count)

        # Validate Redis call data
        self.assertEqual('abc123abc123', self.mockRedis.from_url.return_value.hmset.call_args[0][0])
        self.assertDictEqual(
            {'expiration_date': int(self.now.strftime('%s')), 'payment_validation_data': '%s' % json.dumps({'wallet_addr': 'amount'})},
            self.mockRedis.from_url.return_value.hmset.call_args[0][1]
        )

    def test_exception_saving_to_redis(self):

        # Setup Test Case
        self.mockRedis.from_url.return_value.hmset.side_effect = Exception('Save Failed')

        self.assertRaises(
            Exception,
            self.rr.set_payment_request_meta_data,
            int(self.now.strftime('%s')),
            'wallet_addr',
            'amount'
        )

        # Validate call count
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hmset.call_count)

        # Validate Redis call data
        self.assertEqual('abc123abc123', self.mockRedis.from_url.return_value.hmset.call_args[0][0])
        self.assertDictEqual(
            {'expiration_date': int(self.now.strftime('%s')), 'payment_validation_data': '%s' % json.dumps({'wallet_addr': 'amount'})},
            self.mockRedis.from_url.return_value.hmset.call_args[0][1]
        )


class TestCleanupStalePaymentRequestMetaData(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.Redis')
        self.patcher2 = patch('addressimo.resolvers.RedisResolver.datetime', wraps=datetime)

        self.mockRedis = self.patcher1.start()
        self.mockDatetime = self.patcher2.start()

        self.now = self.mockDatetime.utcnow.return_value = datetime.utcnow()

        # Setup redis resolver
        self.rr = RedisResolver()

        # Setup test data
        self.mockRedis.from_url.return_value.keys.return_value = ['1']
        self.mockRedisData = {'expiration_date': (self.now - timedelta(days=1)).strftime('%s')}
        self.mockRedis.from_url.return_value.hgetall.return_value = self.mockRedisData

    def test_delete_one_key(self):

        self.rr.cleanup_stale_payment_request_meta_data()

        # Validate calls and counts
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.keys.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hgetall.call_count)
        self.assertEqual('1', self.mockRedis.from_url.return_value.hgetall.call_args[0][0])
        self.assertEqual(1, self.mockRedis.from_url.return_value.delete.call_count)
        self.assertEqual('1', self.mockRedis.from_url.return_value.delete.call_args[0][0])

    def test_delete_two_keys(self):

        # Setup test case
        self.mockRedis.from_url.return_value.keys.return_value = ['1', '2']

        self.rr.cleanup_stale_payment_request_meta_data()

        # Validate calls and counts
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.keys.call_count)
        self.assertEqual(2, self.mockRedis.from_url.return_value.hgetall.call_count)
        self.assertEqual('1', self.mockRedis.from_url.return_value.hgetall.call_args_list[0][0][0])
        self.assertEqual('2', self.mockRedis.from_url.return_value.hgetall.call_args_list[1][0][0])
        self.assertEqual(2, self.mockRedis.from_url.return_value.delete.call_count)
        self.assertEqual('1', self.mockRedis.from_url.return_value.delete.call_args_list[0][0][0])
        self.assertEqual('2', self.mockRedis.from_url.return_value.delete.call_args_list[1][0][0])

    def test_no_keys_to_delete(self):

        # Setup test case
        self.mockRedis.from_url.return_value.keys.return_value = []

        self.rr.cleanup_stale_payment_request_meta_data()

        # Validate calls and counts
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.keys.call_count)
        self.assertEqual(0, self.mockRedis.from_url.return_value.hgetall.call_count)
        self.assertEqual(0, self.mockRedis.from_url.return_value.delete.call_count)

    def test_one_key_not_expired(self):

        # Setup test case
        self.mockRedisData = {'expiration_date': (self.now + timedelta(days=1)).strftime('%s')}
        self.mockRedis.from_url.return_value.hgetall.return_value = self.mockRedisData

        self.rr.cleanup_stale_payment_request_meta_data()

        # Validate calls and counts
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.keys.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hgetall.call_count)
        self.assertEqual(0, self.mockRedis.from_url.return_value.delete.call_count)

    def test_exception_deleting_key(self):

        # Setup test case
        self.mockRedis.from_url.return_value.delete.side_effect = Exception('Delete failed')

        self.rr.cleanup_stale_payment_request_meta_data()

        # Validate calls and counts
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.keys.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hgetall.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.delete.call_count)


class TestSetPaymentMetaData(AddressimoTestCase):

    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.Redis')
        self.patcher2 = patch('addressimo.resolvers.RedisResolver.datetime')

        self.mockRedis = self.patcher1.start()
        self.mockDatetime = self.patcher2.start()

        self.now = self.mockDatetime.utcnow.return_value = datetime.utcnow()

        # Setup redis resolver
        self.rr = RedisResolver()

    def test_go_right(self):

        self.rr.set_payment_meta_data('tx_hash', 'memo', 'refund_address')

        # Validate call count
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hmset.call_count)

        # Validate Redis call data
        self.assertEqual('tx_hash', self.mockRedis.from_url.return_value.hmset.call_args[0][0])
        self.assertDictEqual(
            {'memo': 'memo', 'refund_to': 'refund_address', 'expiration_date': int(mktime((self.now + timedelta(days=61)).timetuple()))},
            self.mockRedis.from_url.return_value.hmset.call_args[0][1]
        )

    def test_exception_saving_to_redis(self):

        # Setup test case
        self.mockRedis.from_url.return_value.hmset.side_effect = Exception('Save Failed')

        self.assertRaises(Exception, self.rr.set_payment_meta_data, 'tx_hash', 'memo', 'refund_address')

        # Validate call count
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hmset.call_count)

        # Validate Redis call data
        self.assertEqual('tx_hash', self.mockRedis.from_url.return_value.hmset.call_args[0][0])
        self.assertDictEqual(
            {'memo': 'memo', 'refund_to': 'refund_address', 'expiration_date': int(mktime((self.now + timedelta(days=61)).timetuple()))},
            self.mockRedis.from_url.return_value.hmset.call_args[0][1]
        )


class TestCleanupStalePaymentMetaData(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.RedisResolver.Redis')
        self.patcher2 = patch('addressimo.resolvers.RedisResolver.datetime', wraps=datetime)

        self.mockRedis = self.patcher1.start()
        self.mockDatetime = self.patcher2.start()

        self.now = self.mockDatetime.utcnow.return_value = datetime.utcnow()

        # Setup redis resolver
        self.rr = RedisResolver()

        # Setup test data
        self.mockRedis.from_url.return_value.keys.return_value = ['1']
        self.mockRedisData = {'expiration_date': (self.now - timedelta(days=1)).strftime('%s')}
        self.mockRedis.from_url.return_value.hgetall.return_value = self.mockRedisData

    def test_delete_one_key(self):

        self.rr.cleanup_stale_payment_meta_data()

        # Validate calls and counts
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.keys.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hgetall.call_count)
        self.assertEqual('1', self.mockRedis.from_url.return_value.hgetall.call_args[0][0])
        self.assertEqual(1, self.mockRedis.from_url.return_value.delete.call_count)
        self.assertEqual('1', self.mockRedis.from_url.return_value.delete.call_args[0][0])

    def test_delete_two_keys(self):

        # Setup test case
        self.mockRedis.from_url.return_value.keys.return_value = ['1', '2']

        self.rr.cleanup_stale_payment_meta_data()

        # Validate calls and counts
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.keys.call_count)
        self.assertEqual(2, self.mockRedis.from_url.return_value.hgetall.call_count)
        self.assertEqual('1', self.mockRedis.from_url.return_value.hgetall.call_args_list[0][0][0])
        self.assertEqual('2', self.mockRedis.from_url.return_value.hgetall.call_args_list[1][0][0])
        self.assertEqual(2, self.mockRedis.from_url.return_value.delete.call_count)
        self.assertEqual('1', self.mockRedis.from_url.return_value.delete.call_args_list[0][0][0])
        self.assertEqual('2', self.mockRedis.from_url.return_value.delete.call_args_list[1][0][0])

    def test_no_keys_to_delete(self):

        # Setup test case
        self.mockRedis.from_url.return_value.keys.return_value = []

        self.rr.cleanup_stale_payment_meta_data()

        # Validate calls and counts
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.keys.call_count)
        self.assertEqual(0, self.mockRedis.from_url.return_value.hgetall.call_count)
        self.assertEqual(0, self.mockRedis.from_url.return_value.delete.call_count)

    def test_one_key_not_expired(self):

        # Setup test case
        self.mockRedisData = {'expiration_date': (self.now + timedelta(days=1)).strftime('%s')}
        self.mockRedis.from_url.return_value.hgetall.return_value = self.mockRedisData

        self.rr.cleanup_stale_payment_meta_data()

        # Validate calls and counts
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.keys.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hgetall.call_count)
        self.assertEqual(0, self.mockRedis.from_url.return_value.delete.call_count)

    def test_exception_deleting_key(self):

        # Setup test case
        self.mockRedis.from_url.return_value.delete.side_effect = Exception('Delete failed')

        self.rr.cleanup_stale_payment_meta_data()

        # Validate calls and counts
        self.assertEqual(3, self.mockRedis.from_url.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.keys.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.hgetall.call_count)
        self.assertEqual(1, self.mockRedis.from_url.return_value.delete.call_count)
