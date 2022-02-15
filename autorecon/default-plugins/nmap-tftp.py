from autorecon.plugins import ServiceScan

class NmapTFTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap TFTP'
		self.tags = ['default', 'safe', 'tftp']

	def configure(self):
		self.match_service_name('^tftp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,tftp-enum" -oN "{scandir}/{protocol}_{port}_tftp-nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_tftp_nmap.xml" {address}')
