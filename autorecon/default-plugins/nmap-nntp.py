from autorecon.plugins import ServiceScan

class NmapNNTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap NNTP"
		self.tags = ['default', 'safe', 'nntp']

	def configure(self):
		self.match_service_name('^nntp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,nntp-ntlm-info" -oN "{scandir}/{protocol}_{port}_nntp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_nntp_nmap.xml" {address}')
