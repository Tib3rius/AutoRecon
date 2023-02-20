from autorecon.plugins import ServiceScan

class RPCClient(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "rpcclient"
		self.tags = ['default', 'safe', 'rpc']

	def configure(self):
		self.match_service_name(['^msrpc', '^rpcbind', '^erpc'])

	def manual(self, service, plugin_was_run):
		service.add_manual_command('RPC Client:', 'rpcclient -p {port} -U "" {address}')
