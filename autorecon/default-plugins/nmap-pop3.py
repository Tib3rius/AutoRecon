from autorecon.plugins import ServiceScan

class NmapPOP3(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap POP3"
		self.tags = ['default', 'safe', 'pop3', 'email']

	def configure(self):
		self.match_service_name('^pop3')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(pop3* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_pop3_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_pop3_nmap.xml" {address}')
