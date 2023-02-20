from autorecon.plugins import ServiceScan

class NmapTelnet(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap Telnet'
		self.tags = ['default', 'safe', 'telnet']

	def configure(self):
		self.match_service_name('^telnet')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,telnet-encryption,telnet-ntlm-info" -oN "{scandir}/{protocol}_{port}_telnet-nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_telnet_nmap.xml" {address}')
