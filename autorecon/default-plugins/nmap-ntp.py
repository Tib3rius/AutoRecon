from autorecon.plugins import ServiceScan

class NmapNTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap NTP"
		self.tags = ['default', 'safe', 'ntp']

	def configure(self):
		self.match_service_name('^ntp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(ntp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_ntp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_ntp_nmap.xml" {address}')
