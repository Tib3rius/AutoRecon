from autorecon.plugins import ServiceScan

class NmapSSH(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap SSH"
		self.tags = ['default', 'safe', 'ssh']

	def configure(self):
		self.match_service_name('^ssh')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods" -oN "{scandir}/{protocol}_{port}_ssh_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_ssh_nmap.xml" {address}')
