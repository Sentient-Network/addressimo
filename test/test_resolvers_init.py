__author__ = 'frank'

# System Imports
from mock import Mock, patch
from test import AddressimoTestCase

from addressimo.resolvers import *

class TestResolve(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.redis_conn')
        self.patcher2 = patch('addressimo.resolvers.cache_up_to_date')
        self.patcher3 = patch('addressimo.resolvers.create_json_response')
        self.patcher4 = patch('addressimo.resolvers.PluginManager')
        self.patcher5 = patch('addressimo.resolvers.get_unused_presigned_payment_request')
        self.patcher6 = patch('addressimo.resolvers.get_unused_bip32_address')
        self.patcher7 = patch('addressimo.resolvers.create_payment_request_response')
        self.patcher8 = patch('addressimo.resolvers.create_wallet_address_response')
        self.patcher9 = patch('addressimo.resolvers.request')
        self.patcher10 = patch('addressimo.resolvers.Response')
        self.patcher11 = patch('addressimo.resolvers.create_bip72_response')
        self.patcher12 = patch('addressimo.resolvers.get_bip70_amount')

        self.mockRedis = self.patcher1.start()
        self.mockCacheUpToDate = self.patcher2.start()
        self.mockCreateJSONResponse = self.patcher3.start()
        self.mockPluginManager = self.patcher4.start()
        self.mockGetUnusedPresignedPR = self.patcher5.start()
        self.mockGetUnusedBip32Addr = self.patcher6.start()
        self.mockCreatePRResponse = self.patcher7.start()
        self.mockCreateWalletAddrResponse = self.patcher8.start()
        self.mockRequest = self.patcher9.start()
        self.mockResponse = self.patcher10.start()
        self.mockCreateBip72Response = self.patcher11.start()
        self.mockGetBip70Amount = self.patcher12.start()

        # Setup id_obj for bip32 go right
        self.mock_id_obj = Mock()
        self.mock_id_obj.presigned_payment_requests = []
        self.mock_id_obj.presigned_only = False
        self.mock_id_obj.paymentprotocol_only = False
        self.mockPluginManager.get_plugin.return_value.get_id_obj.return_value = self.mock_id_obj

        self.mockGetBip70Amount.return_value = 0

    def test_go_right_bip32(self):

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(0, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(1, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(1, self.mockCreateBip72Response.call_count)

        # Validate PluginManager call args
        self.assertEqual(('RESOLVER', config.resolver_type), self.mockPluginManager.get_plugin.call_args[0])
        self.assertEqual('id', self.mockPluginManager.get_plugin.return_value.get_id_obj.call_args[0][0])

        # Validate get_unused_bip32_address call args
        self.assertEqual(self.mock_id_obj, self.mockGetUnusedBip32Addr.call_args[0][0])

        # Validate create_wallet_address_response call args
        self.assertEqual(self.mockGetUnusedBip32Addr.return_value, self.mockCreateBip72Response.call_args[0][0])
        self.assertEqual(0, self.mockCreateBip72Response.call_args[0][1])

    def test_sf_only_non_presigned(self):

        config.store_and_forward_only = True

        resolve('id')

        # Validate all calls
        self.assertEqual(0, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateBip72Response.call_count)

        # Validate PluginManager call args
        self.assertEqual(('RESOLVER', config.resolver_type), self.mockPluginManager.get_plugin.call_args[0])
        self.assertEqual('id', self.mockPluginManager.get_plugin.return_value.get_id_obj.call_args[0][0])

        # Validate Error Response
        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual('Endpoint Unavaiable, This is a Store & Forward ONLY Service', self.mockCreateJSONResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJSONResponse.call_args[0][2])

        config.store_and_forward_only = False

    def test_go_right_generate_payment_request(self):

        # Setup test case
        self.mockRequest.args = {'bip70': 'true'}
        self.mock_id_obj.bip70_enabled = True
        self.mock_id_obj.bip70_static_amount = 56900

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(0, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(1, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(1, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate PluginManager call args
        self.assertEqual(('RESOLVER', config.resolver_type), self.mockPluginManager.get_plugin.call_args[0])
        self.assertEqual('id', self.mockPluginManager.get_plugin.return_value.get_id_obj.call_args[0][0])

        # Validate get_unused_bip32_address call args
        self.assertEqual(self.mock_id_obj, self.mockGetUnusedBip32Addr.call_args[0][0])

        # Validate create_payment_request_response call args
        call_args = self.mockCreatePRResponse.call_args[0]
        self.assertEqual(self.mockGetUnusedBip32Addr.return_value, call_args[0])
        self.assertEqual(0, call_args[1])
        self.assertEqual(self.mock_id_obj, call_args[2])

    def test_go_right_generate_payment_request_accept_header(self):

        # Setup test case
        self.mockRequest.args = {}
        self.mockRequest.headers = {
            'accept': 'application/json, application/bitcoin-paymentrequest, text/plain, text/html'
        }
        self.mock_id_obj.bip70_enabled = True
        self.mock_id_obj.bip70_static_amount = 56900

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(0, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(1, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(1, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate PluginManager call args
        self.assertEqual(('RESOLVER', config.resolver_type), self.mockPluginManager.get_plugin.call_args[0])
        self.assertEqual('id', self.mockPluginManager.get_plugin.return_value.get_id_obj.call_args[0][0])

        # Validate get_unused_bip32_address call args
        self.assertEqual(self.mock_id_obj, self.mockGetUnusedBip32Addr.call_args[0][0])

        # Validate create_payment_request_response call args
        call_args = self.mockCreatePRResponse.call_args[0]
        self.assertEqual(self.mockGetUnusedBip32Addr.return_value, call_args[0])
        self.assertEqual(0, call_args[1])
        self.assertEqual(self.mock_id_obj, call_args[2])

    def test_go_right_presigned_payment_request(self):

        # Setup test case
        self.mock_id_obj.presigned_payment_requests = ['PR1']
        self.mock_id_obj.bip70_enabled = True
        self.mock_id_obj.bip32_enabled = False
        self.mockRequest.args = {'bip70': 'true'}

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(0, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(1, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate PluginManager call args
        self.assertEqual(('RESOLVER', config.resolver_type), self.mockPluginManager.get_plugin.call_args[0])
        self.assertEqual('id', self.mockPluginManager.get_plugin.return_value.get_id_obj.call_args[0][0])

        # Validate get_unused_presigned_payment_request call args
        self.assertEqual(self.mock_id_obj, self.mockGetUnusedPresignedPR.call_args[0][0])

        # Validate Response
        call_args = self.mockResponse.call_args[1]
        self.assertEqual('application/bitcoin-paymentrequest', call_args.get('content_type'))
        self.assertDictEqual({'Content-Transfer-Encoding': 'binary', 'Access-Control-Allow-Origin': '*'}, call_args.get('headers'))
        self.assertEqual(self.mockGetUnusedPresignedPR.return_value, call_args.get('response'))
        self.assertEqual(200, call_args.get('status'))

    def test_go_right_presigned_payment_request_sf_only(self):

        config.store_and_forward_only = True

        # Setup test case
        self.mock_id_obj.presigned_payment_requests = ['PR1']
        self.mock_id_obj.bip70_enabled = True
        self.mock_id_obj.bip32_enabled = False
        self.mockRequest.args = {'bip70': 'true'}

        resolve('id')

        # Validate all calls
        self.assertEqual(0, self.mockCacheUpToDate.call_count)
        self.assertEqual(0, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(1, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate PluginManager call args
        self.assertEqual(('RESOLVER', config.resolver_type), self.mockPluginManager.get_plugin.call_args[0])
        self.assertEqual('id', self.mockPluginManager.get_plugin.return_value.get_id_obj.call_args[0][0])

        # Validate get_unused_presigned_payment_request call args
        self.assertEqual(self.mock_id_obj, self.mockGetUnusedPresignedPR.call_args[0][0])

        # Validate Response
        call_args = self.mockResponse.call_args[1]
        self.assertEqual('application/bitcoin-paymentrequest', call_args.get('content_type'))
        self.assertDictEqual({'Content-Transfer-Encoding': 'binary', 'Access-Control-Allow-Origin': '*'}, call_args.get('headers'))
        self.assertEqual(self.mockGetUnusedPresignedPR.return_value, call_args.get('response'))
        self.assertEqual(200, call_args.get('status'))

        config.store_and_forward_only = False

    def test_presigned_payment_request_non_bip70_args_request(self):

        # Setup test case
        self.mock_id_obj.presigned_payment_requests = ['PR1']
        self.mock_id_obj.bip70_enabled = True
        self.mock_id_obj.bip32_enabled = False
        self.mockRequest.args = {}

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(0, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockCreateBip72Response.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(1, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate PluginManager call args
        self.assertEqual(('RESOLVER', config.resolver_type), self.mockPluginManager.get_plugin.call_args[0])
        self.assertEqual('id', self.mockPluginManager.get_plugin.return_value.get_id_obj.call_args[0][0])

        # Validate get_unused_presigned_payment_request call args
        self.assertEqual(self.mock_id_obj, self.mockGetUnusedPresignedPR.call_args[0][0])

        # Validate Response
        self.assertIsNone(self.mockCreateBip72Response.call_args[0][0])
        self.assertIsNone(self.mockCreateBip72Response.call_args[0][1])
        self.assertEqual('https://%s/address/id/resolve?bip70=true' % config.site_url, self.mockCreateBip72Response.call_args[0][2])

    def test_presigned_payment_request_non_bip70_args_request_no_requests_only(self):

        # Setup test case
        self.mock_id_obj.presigned_payment_requests = []
        self.mock_id_obj.bip70_enabled = True
        self.mock_id_obj.bip32_enabled = False
        self.mock_id_obj.presigned_only = True
        self.mockRequest.args = {}

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockCreateBip72Response.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate PluginManager call args
        self.assertEqual(('RESOLVER', config.resolver_type), self.mockPluginManager.get_plugin.call_args[0])
        self.assertEqual('id', self.mockPluginManager.get_plugin.return_value.get_id_obj.call_args[0][0])

        # Validate Response
        call_args = self.mockCreateJSONResponse.call_args[0]
        self.assertFalse(call_args[0])
        self.assertEqual('No PaymentRequests available for this ID', call_args[1])
        self.assertEqual(404, call_args[2])

    def test_presigned_payment_request_non_bip70_args_request_no_valid(self):

        # Setup test case
        self.mock_id_obj.presigned_payment_requests = []
        self.mock_id_obj.bip70_enabled = True
        self.mock_id_obj.bip32_enabled = False
        self.mock_id_obj.presigned_only = True
        self.mockRequest.args = {}

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockCreateBip72Response.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate PluginManager call args
        self.assertEqual(('RESOLVER', config.resolver_type), self.mockPluginManager.get_plugin.call_args[0])
        self.assertEqual('id', self.mockPluginManager.get_plugin.return_value.get_id_obj.call_args[0][0])

        # Validate Response
        call_args = self.mockCreateJSONResponse.call_args[0]
        self.assertFalse(call_args[0])
        self.assertEqual('No PaymentRequests available for this ID', call_args[1])
        self.assertEqual(404, call_args[2])

    def test_go_right_static_wallet_address(self):

        # Setup test case
        self.mock_id_obj.bip32_enabled = False

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(0, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(1, self.mockCreateBip72Response.call_count)

        # Validate PluginManager call args
        self.assertEqual(('RESOLVER', config.resolver_type), self.mockPluginManager.get_plugin.call_args[0])
        self.assertEqual('id', self.mockPluginManager.get_plugin.return_value.get_id_obj.call_args[0][0])

        # Validate create_wallet_address_response call args
        self.assertEqual(self.mock_id_obj.wallet_address, self.mockCreateBip72Response.call_args[0][0])
        self.assertEqual(0, self.mockCreateBip72Response.call_args[0][1])

    def test_cache_not_up_to_date(self):

        # Setup test case
        self.mockCacheUpToDate.return_value = False

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate JSON response
        call_args = self.mockCreateJSONResponse.call_args[0]
        self.assertFalse(call_args[0])
        self.assertEqual('Address cache not up to date. Please try again later.', call_args[1])
        self.assertEqual(500, call_args[2])

    def test_exception_instantiating_resolver(self):

        # Setup test case
        self.mockPluginManager.get_plugin.return_value.get_id_obj.side_effect = Exception('Could not load plugin')

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate JSON response
        call_args = self.mockCreateJSONResponse.call_args[0]
        self.assertFalse(call_args[0])
        self.assertEqual('Exception occurred when retrieving id_obj from database', call_args[1])
        self.assertEqual(500, call_args[2])

    def test_id_object_is_none(self):

        # Setup test case
        self.mockPluginManager.get_plugin.return_value.get_id_obj.return_value = None

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate JSON response
        call_args = self.mockCreateJSONResponse.call_args[0]
        self.assertFalse(call_args[0])
        self.assertEqual('Unable to retrieve id_obj from database', call_args[1])
        self.assertEqual(404, call_args[2])

    def test_id_endpoint_paymentprotocol_only(self):

        # Setup test case
        self.mock_id_obj.paymentprotocol_only = True

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate JSON response
        call_args = self.mockCreateJSONResponse.call_args[0]
        self.assertFalse(call_args[0])
        self.assertEqual('Endpoint Requires a valid POST to create a PaymentRequest Request', call_args[1])
        self.assertEqual(405, call_args[2])
        self.assertEqual({'Allow':'POST'}, self.mockCreateJSONResponse.call_args[1]['headers'])

    def test_presigned_payment_requests_all_invalid(self):

        # Setup test case
        self.mockRequest.args = {'bip70': 'true'}
        self.mock_id_obj.presigned_payment_requests = True
        self.mock_id_obj.bip32_enabled = False
        self.mock_id_obj.bip70_enabled = True
        self.mockGetUnusedPresignedPR.return_value = None

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(1, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate JSON response
        call_args = self.mockCreateJSONResponse.call_args[0]
        self.assertFalse(call_args[0])
        self.assertEqual('No PaymentRequests available for this ID', call_args[1])
        self.assertEqual(404, call_args[2])

    def test_presigned_payment_requests_list_empty(self):

        # Setup test case
        self.mock_id_obj.bip32_enabled = False
        self.mock_id_obj.bip70_enabled = True
        self.mock_id_obj.presigned_only = True
        self.mockRequest.args = {'bip70': 'true'}

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate JSON response
        call_args = self.mockCreateJSONResponse.call_args[0]
        self.assertFalse(call_args[0])
        self.assertEqual('No PaymentRequests available for this ID', call_args[1])
        self.assertEqual(404, call_args[2])

    def test_bip32_disabled_static_wallet_address_empty(self):

        # Setup test case
        self.mock_id_obj.bip32_enabled = False
        self.mock_id_obj.wallet_address = False

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(0, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate JSON response
        call_args = self.mockCreateJSONResponse.call_args[0]
        self.assertFalse(call_args[0])
        self.assertEqual('Unable to retrieve wallet_address', call_args[1])
        self.assertEqual(400, call_args[2])

    def test_exception_generating_bip32_address(self):

        # Setup test case
        self.mockGetUnusedBip32Addr.side_effect = Exception('Cannot obtain address')

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(1, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate JSON response
        call_args = self.mockCreateJSONResponse.call_args[0]
        self.assertFalse(call_args[0])
        self.assertEqual('Unable to retrieve wallet_address', call_args[1])
        self.assertEqual(500, call_args[2])

    def test_bip70_request_but_disabled(self):

        # Setup test case
        self.mockRequest.args = {'bip70': 'true'}
        self.mock_id_obj.bip70_enabled = False

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(1, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(0, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate JSON response
        call_args = self.mockCreateJSONResponse.call_args[0]
        self.assertFalse(call_args[0])
        self.assertEqual('Required bip70_enabled value is missing or disabled', call_args[1])
        self.assertEqual(400, call_args[2])

    def test_bip70_exception_generating_payment_request(self):

        # Setup test case
        self.mockRequest.args = {'bip70': 'true'}
        self.mockCreatePRResponse.side_effect = Exception('PR creation failed')

        resolve('id')

        # Validate all calls
        self.assertEqual(1, self.mockCacheUpToDate.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_id_obj.call_count)
        self.assertEqual(0, self.mockGetUnusedPresignedPR.call_count)
        self.assertEqual(1, self.mockGetUnusedBip32Addr.call_count)
        self.assertEqual(1, self.mockCreatePRResponse.call_count)
        self.assertEqual(0, self.mockCreateWalletAddrResponse.call_count)

        # Validate JSON response
        call_args = self.mockCreateJSONResponse.call_args[0]
        self.assertFalse(call_args[0])
        self.assertEqual('Unable to create payment request', call_args[1])
        self.assertEqual(500, call_args[2])

class TestGetBip70Amount(AddressimoTestCase):

    def setUp(self):

        self.patcher1 = patch('addressimo.resolvers.request')

        self.mockRequest = self.patcher1.start()
        self.mockRequest.args = {}

        self.mockIdObj = Mock()
        self.mockIdObj.bip70_static_amount = None

    def test_static_amount(self):

        ret_val = get_bip70_amount(self.mockIdObj)
        self.assertEqual(0, ret_val)

    def test_preconfigured_amount(self):

        self.mockIdObj.bip70_static_amount = 1000
        ret_val = get_bip70_amount(self.mockIdObj)
        self.assertEqual(1000, ret_val)

    def test_args_amount(self):

        self.mockRequest.args = {'amount': '75'}
        ret_val = get_bip70_amount(self.mockIdObj)
        self.assertEqual(75, ret_val)

class TestGetUnusedBip32Address(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.generate_bip32_address_from_extended_pubkey')
        self.patcher2 = patch('addressimo.resolvers.PluginManager')
        self.patcher3 = patch('addressimo.resolvers.redis_conn')
        self.patcher4 = patch('addressimo.resolvers.derive_branch')

        self.mockGenerateBip32Address = self.patcher1.start()
        self.mockPluginManager = self.patcher2.start()
        self.mockRedis = self.patcher3.start()
        self.mockDeriveBranch = self.patcher4.start()

        # Setup id_obj data
        self.mock_id_obj = Mock()
        self.mock_id_obj.master_public_key = 'mykey'

        # Redis setup to denote address not in use
        self.mockRedis.get.return_value = False

        # Set get_lg_index return value to simplify testing and validation
        self.mockLgIndex = self.mockPluginManager.get_plugin.return_value.get_lg_index.return_value = 4

    def test_go_right_one_iteration(self):

        ret_val = get_unused_bip32_address(self.mock_id_obj)

        # Validate Return Value
        self.assertEqual(self.mockGenerateBip32Address.return_value, ret_val)

        # Validate call count and call args
        self.assertEqual(1, self.mockDeriveBranch.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_lg_index.call_count)
        self.assertEqual(1, self.mockRedis.get.call_count)

        # Validate call arguments for bip32 address generation
        self.assertEqual(1, self.mockGenerateBip32Address.call_count)
        call_args = self.mockGenerateBip32Address.call_args_list[0][0]
        self.assertEqual(self.mock_id_obj.master_public_key, call_args[0])
        self.assertEqual(self.mockDeriveBranch.return_value, call_args[1])
        self.assertEqual(4, call_args[2])

        # Validate call arguments saving lg_index to redis
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.set_lg_index.call_count)
        self.assertEqual(self.mock_id_obj.id, self.mockPluginManager.get_plugin.return_value.set_lg_index.call_args[0][0])
        self.assertEqual(self.mockDeriveBranch.return_value, self.mockPluginManager.get_plugin.return_value.set_lg_index.call_args[0][1])
        self.assertEqual(4, self.mockPluginManager.get_plugin.return_value.set_lg_index.call_args[0][2])

    def test_go_right_two_iterations(self):

        # Setup Test Case
        self.mockRedis.get.side_effect = [True, False]

        ret_val = get_unused_bip32_address(self.mock_id_obj)

        # Validate Return Value
        self.assertEqual(self.mockGenerateBip32Address.return_value, ret_val)

        # Validate call count and call args
        self.assertEqual(1, self.mockDeriveBranch.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.get_lg_index.call_count)
        self.assertEqual(2, self.mockRedis.get.call_count)

        # Validate call arguments for bip32 address generation
        self.assertEqual(2, self.mockGenerateBip32Address.call_count)
        call_args = self.mockGenerateBip32Address.call_args_list
        self.assertEqual(self.mock_id_obj.master_public_key, call_args[0][0][0])
        self.assertEqual(self.mockDeriveBranch.return_value, call_args[0][0][1])
        self.assertEqual(4, call_args[0][0][2])
        self.assertEqual(self.mock_id_obj.master_public_key, call_args[1][0][0])
        self.assertEqual(self.mockDeriveBranch.return_value, call_args[1][0][1])
        self.assertEqual(5, call_args[1][0][2])

        # Validate call arguments saving lg_index to redis
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.set_lg_index.call_count)
        self.assertEqual(self.mock_id_obj.id, self.mockPluginManager.get_plugin.return_value.set_lg_index.call_args[0][0])
        self.assertEqual(self.mockDeriveBranch.return_value, self.mockPluginManager.get_plugin.return_value.set_lg_index.call_args[0][1])
        self.assertEqual(5, self.mockPluginManager.get_plugin.return_value.set_lg_index.call_args[0][2])

    def test_master_public_key_missing(self):

        # Setup Test Case
        self.mock_id_obj.master_public_key = None

        self.assertRaisesRegexp(
            ValueError,
            'Master public key missing. Unable to generate bip32 address.',
            get_unused_bip32_address,
            self.mock_id_obj
        )

        # Validate call count and call args
        self.assertEqual(0, self.mockRedis.get.call_count)
        self.assertEqual(0, self.mockGenerateBip32Address.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.save.call_count)

class TestCreatePaymentRequestResponse(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.generate_payment_request')
        self.patcher2 = patch('addressimo.resolvers.Response')
        self.patcher3 = patch('addressimo.resolvers.PluginManager')
        self.patcher4 = patch('addressimo.resolvers.create_json_response')

        self.mockGeneratePR = self.patcher1.start()
        self.mockResponse = self.patcher2.start()
        self.mockPluginManager = self.patcher3.start()
        self.mockCreateJSONResponse = self.patcher4.start()

        # Setup id_obj data
        self.mock_id_obj = Mock()
        self.mock_id_obj.x509_cert = 'myx509cert'
        self.mock_id_obj.expires = 'expires'
        self.mock_id_obj.memo = 'memo'
        self.mock_id_obj.payment_url = 'pay_url'
        self.mock_id_obj.merchant_data = 'merchant_data'

        self.mock_id_obj.get_expires.return_value = self.mock_id_obj.expires

        # Mock payment_url_uuid response
        self.mockPluginManager.get_plugin.return_value.set_payment_request_meta_data.return_value = 'pay_url_uuid'

    def test_go_right_with_payment_url(self):

        create_payment_request_response('wallet_addr', 1000, self.mock_id_obj)

        self.assertEqual(1, self.mockGeneratePR.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.set_id_obj.call_count)
        self.assertEqual(0, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockResponse.call_count)

        # Validate generate_payment_request call args
        call_args = self.mockGeneratePR.call_args[0]
        self.assertEqual('wallet_addr', call_args[0])
        self.assertEqual(self.mock_id_obj.x509_cert, call_args[1])
        self.assertEqual(self.mock_id_obj.expires, call_args[2])
        self.assertEqual(self.mockPluginManager.get_plugin.return_value, call_args[3])
        self.assertEqual(1000, call_args[4])
        self.assertEqual(self.mock_id_obj.memo, call_args[5])
        self.assertEqual(self.mock_id_obj.payment_url, call_args[6])
        self.assertEqual(self.mock_id_obj.merchant_data, call_args[7])

        # Validate Response call args
        call_args = self.mockResponse.call_args[1]
        self.assertEqual('application/bitcoin-paymentrequest', call_args['content_type'])
        self.assertDictEqual({'Access-Control-Allow-Origin': '*', 'Content-Transfer-Encoding': 'binary'}, call_args['headers'])
        self.assertEqual(self.mockGeneratePR.return_value, call_args['response'])
        self.assertEqual(200, call_args['status'])

    def test_go_right_without_payment_url(self):

        # Setup test case
        self.mock_id_obj.payment_url = None

        create_payment_request_response('wallet_addr', 1000, self.mock_id_obj)

        self.assertEqual(1, self.mockGeneratePR.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.set_id_obj.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.set_payment_request_meta_data.call_count)
        self.assertEqual(0, self.mockCreateJSONResponse.call_count)
        self.assertEqual(1, self.mockResponse.call_count)

        # Validate set_payment_request_meta_data call args
        call_args = self.mockPluginManager.get_plugin.return_value.set_payment_request_meta_data.call_args[0]
        self.assertEqual(self.mock_id_obj.get_expires(), call_args[0])
        self.assertEqual('wallet_addr', call_args[1])
        self.assertEqual(1000 * 100000000, call_args[2])

        # Validate generate_payment_request call args
        call_args = self.mockGeneratePR.call_args[0]
        self.assertEqual('wallet_addr', call_args[0])
        self.assertEqual(self.mock_id_obj.x509_cert, call_args[1])
        self.assertEqual(self.mock_id_obj.expires, call_args[2])
        self.assertEqual(self.mockPluginManager.get_plugin.return_value, call_args[3])
        self.assertEqual(1000, call_args[4])
        self.assertEqual(self.mock_id_obj.memo, call_args[5])
        self.assertEqual('https://addressimo.netki.com/payment/pay_url_uuid', call_args[6])
        self.assertEqual('pay_url_uuid', call_args[7])

        # Validate Response call args
        call_args = self.mockResponse.call_args[1]
        self.assertEqual('application/bitcoin-paymentrequest', call_args['content_type'])
        self.assertDictEqual({'Access-Control-Allow-Origin': '*', 'Content-Transfer-Encoding': 'binary'}, call_args['headers'])
        self.assertEqual(self.mockGeneratePR.return_value, call_args['response'])
        self.assertEqual(200, call_args['status'])

    def test_missing_x509_cert(self):

        # Setup test case
        self.mock_id_obj.x509_cert = None

        self.assertRaisesRegexp(
            ValueError,
            'id_obj missing x509_cert',
            create_payment_request_response,
            'wallet_addr',
            1000,
            self.mock_id_obj
        )

        self.assertEqual(0, self.mockGeneratePR.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.set_id_obj.call_count)
        self.assertEqual(0, self.mockPluginManager.get_plugin.return_value.set_payment_request_meta_data.call_count)
        self.assertEqual(0, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)

    def test_exception_saving_payment_meta_data(self):

        # Setup test case
        self.mock_id_obj.payment_url = None
        self.mockPluginManager.get_plugin.return_value.set_payment_request_meta_data.side_effect = Exception()

        create_payment_request_response('wallet_addr', 1000, self.mock_id_obj)

        self.assertEqual(0, self.mockGeneratePR.call_count)
        self.assertEqual(2, self.mockPluginManager.get_plugin.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.set_id_obj.call_count)
        self.assertEqual(1, self.mockPluginManager.get_plugin.return_value.set_payment_request_meta_data.call_count)
        self.assertEqual(1, self.mockCreateJSONResponse.call_count)
        self.assertEqual(0, self.mockResponse.call_count)

class TestReturnUsedBranches(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.create_json_response')
        self.patcher2 = patch('addressimo.resolvers.PluginManager')
        self.patcher3 = patch('addressimo.resolvers.request')

        self.mockCreateJSONResponse = self.patcher1.start()
        self.mockPluginManager = self.patcher2.start()
        self.mockRequest = self.patcher3.start()

        # Set return value for get_branches to use in response validation
        self.mockPluginManager.get_plugin.return_value.get_branches.return_value = [123, 456]

        #################################################################
        # Mock to Pass @requires_valid_signature & @requires_public_key
        self.patcher100 = patch('addressimo.util.get_id')
        self.patcher101 = patch('addressimo.util.VerifyingKey')
        self.patcher102 = patch('addressimo.util.request')
        self.patcher103 = patch('addressimo.util.from_sec')

        self.mockGetId = self.patcher100.start()
        self.mockVerifyingKey = self.patcher101.start()
        self.mockUtilRequest = self.patcher102.start()
        self.mockFromSec = self.patcher103.start()

        self.mockRequest.headers = {
            'x-signature': 'sigF'.encode('hex'),
            'x-identity': 'ac79cd6b0ac5f2a6234996595cb2d91fceaa0b9d9a6495f12f1161c074587bd19ae86928bddea635c930c09ea9c7de1a6a9c468f9afd18fbaeed45d09564ded6'
        }

        self.mockVerifyingKey.from_der.return_value.verify.return_value = True
        self.mockFromSec.return_value = None
        self.mockUtilRequest.url = 'https://%s/path' % config.site_url
        self.mockUtilRequest.path = '/path'

        config.admin_public_key = 'ac79cd6b0ac5f2a6234996595cb2d91fceaa0b9d9a6495f12f1161c074587bd19ae86928bddea635c930c09ea9c7de1a6a9c468f9afd18fbaeed45d09564ded6'

    def test_go_right(self):

        return_used_branches(1)

        self.assertDictEqual({'branches': [123, 456]}, self.mockCreateJSONResponse.call_args[1].get('data'))

    def test_admin_public_key_missing(self):

        # Setup Test case
        config.admin_public_key = None

        return_used_branches(1)

        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual('ID Not Recognized', self.mockCreateJSONResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJSONResponse.call_args[0][2])

    def test_x_identity_header_does_not_match_admin_public_key(self):

        # Setup Test case
        config.admin_public_key = 'does not match'

        return_used_branches(1)

        self.assertFalse(self.mockCreateJSONResponse.call_args[0][0])
        self.assertEqual('ID Not Recognized', self.mockCreateJSONResponse.call_args[0][1])
        self.assertEqual(404, self.mockCreateJSONResponse.call_args[0][2])

class TestCreateWalletAddressResponse(AddressimoTestCase):
    def setUp(self):
        self.patcher1 = patch('addressimo.resolvers.create_json_response')

        self.mockCreateJSONResponse = self.patcher1.start()

    def test_go_right(self):

        create_wallet_address_response('wallet_addr')

        self.assertEqual(1, self.mockCreateJSONResponse.call_count)

        # Validate JSON response
        call_args = self.mockCreateJSONResponse.call_args[1]
        self.assertDictEqual({'wallet_address': 'wallet_addr'}, call_args['data'])
