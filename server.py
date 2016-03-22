__author__ = 'mdavid'

import logging
import time

from flask import Flask, Response, request

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
def submit_ir(id):
    return submit_invoicerequest(id)

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

@app.route('/address/<id>/invoicerequests', methods=['GET'])
@limiter.limit("10 per minute")
def get_invoice_requests(id):
    return get_queued_invoice_requests(id)

@app.route('/address/<id>/invoicerequests', methods=['POST'])
@limiter.limit("10 per minute")
def submit_epr(id):
    return submit_encrypted_paymentrequest(id)

@app.route('/encryptedpaymentrequest/<id>', methods=['GET'])
@limiter.limit("10 per minute")
def get_epr(id):
    return get_encrypted_paymentrequest(id)

@app.route('/payment/<id>', methods=['GET'])
@limiter.limit("10 per minute")
def retrieve_payment(id):
    return get_encrypted_payment(id)

@app.route('/payment/<id>', methods=['POST'])
@limiter.limit("10 per minute")
def submit_payment(id):
    return process_payment(id)

@app.route('/paymentack/<id>', methods=['GET'])
@limiter.limit("10 per minute")
def retrieve_paymentack(id):
    return get_encrypted_paymentack(id)

@app.route('/paymentack/<id>', methods=['POST'])
@limiter.limit("10 per minute")
def submit_paymentack(id):
    return process_encrypted_paymentack(id)

@app.route('/payment/<id>/refund/<tx>', methods=['GET'])
@limiter.limit("10 per minute")
def retrieve_refund_address(id, tx):
    return retrieve_refund_address(id, tx)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)