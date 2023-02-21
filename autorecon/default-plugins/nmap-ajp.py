from autorecon.plugins import ServiceScan

class NmapAJP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap AJP'
		self.tags = ['default', 'safe', 'ajp']

	def configure(self):
		self.match_service_name(['^ajp13'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(ajp-* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_ajp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_ajp_nmap.xml" {address}')
