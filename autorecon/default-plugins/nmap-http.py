from autorecon.plugins import ServiceScan

class NmapHTTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap HTTP"
		self.tags = ['default', 'safe', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)
		self.add_pattern('Server: ([^\n]+)', description='Identified HTTP Server: {match1}')
		self.add_pattern('WebDAV is ENABLED', description='WebDAV is enabled')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oN "{scandir}/{protocol}_{port}_{http_scheme}_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_{http_scheme}_nmap.xml" {address}')
