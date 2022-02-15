from autorecon.plugins import ServiceScan

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
