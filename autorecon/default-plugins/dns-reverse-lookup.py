from autorecon.plugins import ServiceScan

class DNSReverseLookup(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'DNS Reverse Lookup'
		self.tags = ['default', 'safe', 'dns']

	def configure(self):
		self.match_service_name('^domain')

	async def run(self, service):
		await service.execute('dig -p {port} -x {address} @{address}', outfile='{protocol}_{port}_dns_reverse-lookup.txt')
