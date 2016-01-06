__author__ = 'mdavid'

import logging
import time

from flask import Flask, Response, request

from addressimo.config import config
from addressimo.paymentrequest.ir import IR
from addressimo.paymentrequest.payment import Payments
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
def submit_pr_request(id):
    return IR.submit_invoicerequest(id)

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
    return IR.get_queued_invoice_requests(id)

@app.route('/address/<id>/invoicerequests', methods=['POST'])
@limiter.limit("10 per minute")
def submit_return_pr(id):
    return IR.submit_return_paymentrequest(id)

@app.route('/returnpaymentrequest/<id>', methods=['GET'])
@limiter.limit("10 per minute")
def get_return_pr(id):
    return IR.get_return_paymentrequest(id)

@app.route('/payment/<id>', methods=['POST'])
@limiter.limit("10 per minute")
def process_payment(id):
    return Payments.process_payment(id)

@app.route('/payment/<id>/refund/<tx>', methods=['GET'])
@limiter.limit("10 per minute")
def retrieve_refund_address(id, tx):
    return Payments.retrieve_refund_address(id, tx)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)