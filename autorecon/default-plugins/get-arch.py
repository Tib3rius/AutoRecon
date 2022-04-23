from autorecon.plugins import ServiceScan

class GetArch(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'get-arch'
		self.tags = ['default', 'safe', 'rpc']

	def configure(self):
		self.match_service_name(['^msrpc'])
		self.match_port('tcp', 135)
		self.add_pattern(' is ((32|64)-bit)', description='Identified Architecture: {match1}')

	async def run(self, service):
		await service.execute('impacket-getArch -target {address}', outfile='{protocol}_{port}_rpc_architecture.txt')
