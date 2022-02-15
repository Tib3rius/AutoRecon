from autorecon.plugins import ServiceScan

class DNSZoneTransfer(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'DNS Zone Transfer'
		self.tags = ['default', 'safe', 'dns']

	def configure(self):
		self.match_service_name('^domain')

	async def run(self, service):
		if self.get_global('domain'):
			await service.execute('dig AXFR -p {port} @{address} ' + self.get_global('domain'), outfile='{protocol}_{port}_dns_zone-transfer-domain.txt')
		if service.target.type == 'hostname':
			await service.execute('dig AXFR -p {port} @{address} {address}', outfile='{protocol}_{port}_dns_zone-transfer-hostname.txt')
		await service.execute('dig AXFR -p {port} @{address}', outfile='{protocol}_{port}_dns_zone-transfer.txt')
