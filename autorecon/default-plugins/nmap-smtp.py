from autorecon.plugins import ServiceScan

class NmapSMTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap SMTP"
		self.tags = ['default', 'safe', 'smtp', 'email']

	def configure(self):
		self.match_service_name('^smtp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(smtp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_smtp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_smtp_nmap.xml" {address}')
