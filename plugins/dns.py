from autorecon import ServiceScan

class DNS(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "DNS"
		self.tags = ['default', 'dns']

	def configure(self):
		self.match_service_name('^domain')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_dns_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_dns_nmap.xml" {address}')

class ZoneTransfer(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Zone Transfer"
		self.tags = ['default', 'dns']

	def configure(self):
		self.match_service_name('^domain')
		self.add_option('domain', help='The domain name to perform a zone transfer on.')

	async def run(self, service):
		if self.get_option('domain') is None:
			await service.execute('dig AXFR -p {port} @{address}', outfile='{protocol}_{port}_dns_zone-transfer.txt')
		else:
			await service.execute('dig AXFR ' + self.get_option('domain') + ' -p {port} @{address}', outfile='{protocol}_{port}_dns_zone-transfer.txt')
