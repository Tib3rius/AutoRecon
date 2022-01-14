from autorecon.plugins import ServiceScan

class NmapRPC(ServiceScan):

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
		self.tags = ['default', 'safe', 'rpc']

	def configure(self):
		self.match_service_name(['^msrpc', '^rpcbind', '^erpc'])

	def manual(self, service, plugin_was_run):
		service.add_manual_command('RPC Client:', 'rpcclient -p {port} -U "" {address}')

class RPCDump(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'rpcdump'
		self.tags = ['default', 'safe', 'rpc']

	def configure(self):
		self.match_service_name(['^msrpc', '^rpcbind', '^erpc', '^ncacn_http$'])
		self.match_port('tcp', [135, 139, 443, 445, 593])

	async def run(self, service):
		if service.protocol == 'tcp':
			await service.execute('impacket-rpcdump -port {port} {address}', outfile='{protocol}_{port}_rpc_rpcdump.txt')

class GetArch(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'get-arch'
		self.tags = ['default', 'safe', 'rpc']

	def configure(self):
		self.match_service_name(['^msrpc'])
		self.match_port('tcp', 135)
		self.add_pattern(' is ((32|64)-bit)', description='Identified Architecture: {match}')

	async def run(self, service):
		await service.execute('getArch.py -target {address}', outfile='{protocol}_{port}_rpc_architecture.txt')
