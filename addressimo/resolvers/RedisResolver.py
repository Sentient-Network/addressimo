__author__ = 'Matt David'

import json
import time
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from hashlib import sha256
from time import mktime
from redis import Redis
from uuid import uuid4

from BaseResolver import BaseResolver
from addressimo.config import config
from addressimo.data import IdObject
from addressimo.util import LogUtil, CustomJSONEncoder
from addressimo.paymentprotocol.paymentrequest_pb2 import ProtocolMessage, EncryptedProtocolMessage, ProtocolMessageType

log = LogUtil.setup_logging()


class RedisResolver(BaseResolver):
    @classmethod
    def get_plugin_name(cls):
        return 'REDIS'

    @classmethod
    def generate_unique_id(cls, redis_conn, uuid_multiple=1):
        while True:
            id = ''.join([uuid4().hex for _ in range(uuid_multiple)])
            try:
                if not redis_conn.exists(id):
                    return id
            except:
                log.warn("Unable to Generate New, Unused ID [REDIS: %s]" % redis_conn.info())
                return None

    def __init__(self):

        self.tx_client = Redis.from_url(config.redis_tx_uri)
        self.tx_map_client = Redis.from_url(config.redis_tx_map_uri)

    def get_all_keys(self):
        redis_client = Redis.from_url(config.redis_id_obj_uri)
        return redis_client.keys('*')

    def get_id_obj(self, id):

        redis_client = Redis.from_url(config.redis_id_obj_uri)
        try:
            result = redis_client.get(id)
            if not result:
                log.info('Unable to Get id obj data [ID: %s]' % id)
                return None

        except Exception as e:
            log.info('Unable to Get id obj data [ID: %s]: %s' % (id, str(e)))
            return None

        id_obj = IdObject(id)
        for key, value in json.loads(result).items():
            id_obj[key] = value
        return id_obj

    def get_branches(self, id):

        redis_client = Redis.from_url(config.redis_address_branch_uri)

        try:
            result = redis_client.hkeys(id)

            if not result:
                log.info('No branches are present [ID: %s]' % id)
                return []

            result = map(int, result)
        except Exception as e:
            log.error('Exception retrieving branches [ID: %s]: %s' % (id, str(e)))
            return []

        return result

    def get_lg_index(self, id, branch):

        lg_index = 0
        redis_client = Redis.from_url(config.redis_address_branch_uri)

        try:
            lg_index = redis_client.hget(id, branch)
        except Exception as e:
            log.error('Exception retrieving lg_index from Redis [ID: %s | Branch: %s]: %s' % (id, branch, str(e)))

        return int(lg_index) if lg_index else 0

    def set_lg_index(self, id, branch, index):

        redis_client = Redis.from_url(config.redis_address_branch_uri)

        try:
            result = redis_client.hset(id, branch, index)
        except Exception as e:
            log.error('Exception setting lg_index in Redis [ID: %s | Branch: %s] %s' % (id, branch, str(e)))
            return None

        return result

    def save(self, id_obj):

        redis_client = Redis.from_url(config.redis_id_obj_uri)
        if not id_obj.id:
            id_obj.id = RedisResolver.generate_unique_id(redis_client, 1)

        try:
            result = redis_client.set(id_obj.id, json.dumps(id_obj, cls=CustomJSONEncoder))
            log.info('Saved IdObject to Redis [ID: %s]' % id_obj.id)
            return result
        except Exception as e:
            log.info('Unable to Save IdObject to Redis [ID: %s]: %s' % (id, str(e)))
            raise

    def delete(self, id_obj):

        redis_client = Redis.from_url(config.redis_id_obj_uri)

        try:
            result = redis_client.delete(id_obj.id)
            log.info('Deleted IdObject to Redis [ID: %s]' % id_obj.id)
            return result
        except Exception as e:
            log.info('Unable to Delete IdObject to Redis [ID: %s]: %s' % (id_obj.id, str(e)))
            raise

    #########################################
    # Payment Protocol Data Handling
    #########################################
    def get_paymentprotocol_messages(self, id=None, tx_id=None):

        txs_data = {}
        tx_ids = [tx_id]
        if id:
            tx_count = self.tx_map_client.llen(id)
            if not tx_count:
                return txs_data

            tx_ids = self.tx_map_client.lrange(id, 0, tx_count-1)

        for transaction_id in tx_ids:
            tx = self.tx_client.hgetall(transaction_id)
            if not tx:
                continue

            decoded_messages = [b64decode(x) for x in json.loads(tx.get('messages', '[]'))]
            tx['messages'] = decoded_messages
            txs_data[transaction_id] = tx

        return txs_data

    def add_paymentprotocol_message(self, message, id=None, tx_id=None):

        possible_tx_ids = [tx_id]
        if id:
            possible_tx_id_count = self.tx_map_client.llen(id)
            possible_tx_ids = self.tx_map_client.lrange(id, 0, possible_tx_id_count - 1)

        found_tx = found_tx_id = None
        for possible_tx_id in possible_tx_ids:
            if message.identifier == self.tx_client.hget(possible_tx_id, 'identifier'):
                found_tx = self.tx_client.hgetall(possible_tx_id)
                found_tx_id = possible_tx_id
                break

        # Create New TX
        if not found_tx and id and message.message_type == ProtocolMessageType.Value('INVOICE_REQUEST'):
            new_data = {
                'messages': json.dumps([b64encode(message.SerializeToString())]),
                'receiver': id,
                'identifier': message.identifier,
                'last_updated': datetime.utcnow().strftime('%s'),
            }
            if isinstance(message, EncryptedProtocolMessage):
                new_data['last_nonce'] = message.nonce

            new_id = RedisResolver.generate_unique_id(self.tx_client, 3)
            self.tx_client.hmset(new_id, new_data)
            self.tx_map_client.rpush(id, new_id)
            return new_id
        elif not found_tx:
            return None

        found_tx['messages'] = json.loads(found_tx['messages'])
        found_tx['messages'].append(b64encode(message.SerializeToString()))
        found_tx['messages'] = json.dumps(found_tx['messages'])
        found_tx['last_updated'] = datetime.utcnow().strftime('%s')

        if isinstance(message, EncryptedProtocolMessage):
            found_tx['last_nonce'] = message.nonce

        self.tx_client.hmset(found_tx_id, found_tx)
        return found_tx_id

    def delete_paymentprotocol_message(self, tx_identifier, type, id=None, tx_id=None):

        messages = self.get_paymentprotocol_messages(id, tx_id)

        for tx_id, msg in messages.iteritems():

            msg_updated = False
            for pp_message in msg.get('messages', []):

                try:
                    protobuf_message = EncryptedProtocolMessage()
                    protobuf_message.ParseFromString(pp_message)
                    protobuf_message.SerializeToString() # Verify this is an EncryptedProtocolMessage
                except:
                    try:
                        protobuf_message = ProtocolMessage()
                        protobuf_message.ParseFromString(pp_message)
                        protobuf_message.SerializeToString() # Verify this is an ProtocolMessage
                    except:
                        log.error('Unable to Parse Protobuf Message [ID: %s | TX_ID: %s]' % (id, tx_id))
                        continue

                if type.upper() == ProtocolMessageType.Name(protobuf_message.message_type) and tx_identifier == protobuf_message.identifier:
                    msg['messages'] = [x for x in msg.get('messages', []) if x != pp_message]
                    msg_updated = True
                    break

            if not msg_updated:
                continue

            if not msg.get('messages', []):
                self.tx_client.delete(tx_id)
                receiver_id = id if id else msg.get('receiver', '')
                self.tx_map_client.lrem(receiver_id, tx_id, 0)
            else:
                msg['messages'] = json.dumps([b64encode(x) for x in msg.get('messages', [])])
                self.tx_client.hmset(tx_id, msg)

            return True

        return False

    def cleanup_stale_paymentprotocol_messages(self):

        delete_count = 0

        for tx_id in self.tx_client.scan_iter():
            tx = self.tx_client.hgetall(tx_id)
            last_updated = datetime.utcfromtimestamp(tx.get('last_updated', ''))
            if last_updated > datetime.utcnow() - timedelta(days=config.paymentprotocol_message_expiration_days):
                continue

            # Delete the TX
            delete_count += 1
            self.tx_client.delete(tx_id)

            # Delete TX ID from TX Receiver Map
            self.tx_map_client.lrem(tx.get('receiver'), tx_id)

        return delete_count

    def get_tx_last_nonce(self, message, id=None, tx_id=None):

        txs_data = self.get_paymentprotocol_messages(id, tx_id)
        if not txs_data:
            return None

        for tx_id, data in txs_data.items():
            if message.identifier == data['identifier']:
                return int(data.get('last_nonce'))

        return None

    # Payment Data Handling
    def get_payment_request_meta_data(self, uuid):

        redis_client = Redis.from_url(config.redis_pr_store)

        return redis_client.hgetall(uuid)

    def set_payment_request_meta_data(self, expiration_date, wallet_addr, amount):

        redis_client = Redis.from_url(config.redis_pr_store)
        payment_url_uuid = RedisResolver.generate_unique_id(redis_client, 2)

        payment_addresses = {
            wallet_addr: amount
        }

        try:
            redis_client.hmset(payment_url_uuid, {
                'expiration_date': expiration_date,
                'payment_validation_data': json.dumps(payment_addresses)
            })

        except Exception as e:
            log.info('Exception Saving PaymentRequest Meta Data: %s' % str(e))
            raise

        return payment_url_uuid

    def cleanup_stale_payment_request_meta_data(self):

        redis_client = Redis.from_url(config.redis_pr_store)

        payment_request_keys = redis_client.keys()
        log.info('Found %d Payment Request Meta Data Keys' % len(payment_request_keys))

        for key in payment_request_keys:
            try:
                payment_request = redis_client.hgetall(key)
                if datetime.utcnow() > datetime.fromtimestamp(int(payment_request.get('expiration_date'))):
                    log.info('Deleting Stale Payment Request [UUID: %s]' % key)
                    redis_client.delete(key)
            except Exception as e:
                log.error('Exception Occurred Cleaning Up Stale Payment Request Meta Data [UUID: %s]: %s' % (key, str(e)))

    def set_payment_meta_data(self, tx_hash, memo, refund_address):

        redis_client = Redis.from_url(config.redis_payment_store)

        try:
            redis_client.hmset(tx_hash, {
                'memo': memo,
                'refund_to': refund_address,
                'expiration_date': int(
                    mktime((datetime.utcnow() + timedelta(days=config.bip70_payment_expiration_days)).timetuple())
                )
            })

        except Exception as e:
            log.info('Exception Saving Payment Meta Data: %s' % str(e))
            raise

    def cleanup_stale_payment_meta_data(self):

        redis_client = Redis.from_url(config.redis_payment_store)

        payment_keys = redis_client.keys()
        log.info('Found %d Payment Meta Data Keys' % len(payment_keys))

        for key in payment_keys:
            try:
                payment = redis_client.hgetall(key)
                if datetime.utcnow() > datetime.fromtimestamp(int(payment.get('expiration_date'))):
                    log.info('Deleting Stale Payment [UUID: %s]' % key)
                    redis_client.delete(key)
            except Exception as e:
                log.error('Exception Occurred Cleaning Up Stale Payment Meta Data [UUID: %s]: %s' % (key, str(e)))