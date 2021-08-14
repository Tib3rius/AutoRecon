from autorecon import ServiceScan

class NmapMSRPC(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap MSRPC"
		self.tags = ['default', 'rpc']

	def configure(self):
		self.match_service_name(['^msrpc', '^rpcbind', '^erpc'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,msrpc-enum,rpc-grind,rpcinfo" -oN "{scandir}/{protocol}_{port}_rpc_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_rpc_nmap.xml" {address}')

class RPCClient(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "rpcclient"
		self.tags = ['default', 'rpc']

	def configure(self):
		self.match_service_name(['^msrpc', '^rpcbind', '^erpc'])

	def manual(self, service, plugin_was_run):
		service.add_manual_command('RPC Client:', 'rpcclient -p {port} -U "" {address}')
