__author__ = 'mdavid'

import logging
import time

from flask import Flask, Response, request
from flask_cors import CORS

from addressimo.config import config
from addressimo.paymentprotocol import *
from addressimo.plugin import PluginManager
from addressimo.resolvers import resolve, return_used_branches
from addressimo.storeforward import StoreForward
from addressimo.util import create_json_response

log = logging.getLogger(__name__)

app = Flask(__name__)
app.config.update(
    DEBUG=True,
    TESTING=True,
    RATELIMIT_STORAGE_URL=config.redis_ratelimit_uri,
    RATELIMIT_HEADERS_ENABLED=False
)

CORS(app)

# ###########################################
# Setup Pre-Request Processing
# ###########################################
@app.before_request
def before_request():

    # Handle our pre-flight OPTIONS check
    if request.method == 'OPTIONS':
        return create_json_response()

# ###########################################
# Setup Rate Limiting
# ###########################################
try:
    from flask_limiter import Limiter
    limiter = Limiter(app, global_limits=["20 per minute"])

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return create_json_response(success=False, message="ratelimit exceeded", status=429)

    @limiter.request_filter
    def ip_whitelist():
        return request.remote_addr == "127.0.0.1"

except ImportError:
    log.warn('Rate limiting not available. To add rate limiting, install the Flask-Limiter module, install Redis, and configure Redis in config.')

######################
# Register Plugins
######################
PluginManager.register_plugins()

# ###########################################
# Status Testing Route (for Load Balancing, etc)
@app.route('/index.html', methods=['GET', 'OPTIONS', 'HEAD', 'POST'])
def index():
    return Response("UP", status=200, mimetype='text/html')

@app.route('/time', methods=['GET'])
@limiter.limit("60 per minute")
def get_current_time():
    return create_json_response(
            message='current time in microseconds (utc)',
            data={'utime': int(time.time() * 1000 * 1000)}
    )

@app.route('/address/<id>/resolve', methods=['GET'])
@limiter.limit("60 per minute")
def resolve_id(id):
    return resolve(id)

@app.route('/address/<id>/resolve', methods=['POST'])
@limiter.limit("10 per minute")
def submit_invoicerequest(id):
    return submit_paymentprotocol_message(id=id, ignore_pubkey_verify=True)

@app.route('/address/<id>/branches', methods=['GET'])
@limiter.limit("10 per minute")
def get_used_branches(id):
    return return_used_branches(id)

@app.route('/sf', methods=['POST'])
@limiter.limit("10 per minute")
def register_sf_endpoint():
    return StoreForward.register()

@app.route('/address/<id>/sf', methods=['PUT'])
@limiter.limit("10 per minute")
def add_sf_paymentrequests(id):
    return StoreForward.add()

@app.route('/address/<id>/sf', methods=['DELETE'])
@limiter.limit("10 per minute")
def remove_sf_endpoint(id):
    return StoreForward.delete()

@app.route('/address/<id>/sf', methods=['GET'])
@limiter.limit("10 per minute")
def sf_getcount(id):
    return StoreForward.get_count()


# BIP75 Payment Protocol Endpoints
@app.route('/address', methods=['POST'])
@limiter.limit("2 per minute")
def register_bip75_endpoint():
    return StoreForward.register(paymentprotocol_only=True)

@app.route('/address/<id>/paymentprotocol', methods=['GET'])
@limiter.limit("10 per minute")
def get_pp_messages(id):
    return get_paymentprotocol_messages(id=id)

@app.route('/address/<id>/paymentprotocol', methods=['POST'])
@limiter.limit("10 per minute")
def submit_pp_message(id):
    return submit_paymentprotocol_message(id=id)

@app.route('/address/<id>/paymentprotocol/<identifier>/<message_type>', methods=['DELETE'])
@limiter.limit("10 per minute")
def delete_pp_messag(id, identifier, message_type):
    return delete_paymentprotocol_message(identifier, message_type, id=id)

@app.route('/paymentprotocol/<tx_id>', methods=['GET'])
@limiter.limit("10 per minute")
def get_pp_tx_messages(tx_id):
    return get_paymentprotocol_messages(tx_id=tx_id, ignore_pubkey_verify=True)

@app.route('/paymentprotocol/<tx_id>', methods=['POST'])
@limiter.limit("10 per minute")
def submit_pp_tx_message(tx_id):
    return submit_paymentprotocol_message(tx_id=tx_id, ignore_pubkey_verify=True)

@app.route('/paymentprotocol/<tx_id>/<identifier>/<message_type>', methods=['DELETE'])
@limiter.limit("10 per minute")
def delete_pp_tx_message(tx_id, identifier, message_type):
    return delete_paymentprotocol_message(identifier, message_type, tx_id=tx_id)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)