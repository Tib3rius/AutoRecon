from autorecon import ServiceScan

class NmapSIP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap SIP"
		self.tags = ['default', 'sip']

	def configure(self):
		self.match_service_name('^asterisk')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,sip-enum-users,sip-methods" -oN "{scandir}/{protocol}_{port}_sip_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_sip_nmap.xml" {address}')

class SIPVicious(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "SIPVicious"
		self.tags = ['default', 'sip']

	def configure(self):
		self.match_service_name('^asterisk')

	def manual(self):
		self.add_manual_command('svwar:', 'svwar -D -m INVITE -p {port} {address}')
