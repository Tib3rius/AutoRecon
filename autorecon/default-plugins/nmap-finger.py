from autorecon.plugins import ServiceScan

class NmapFinger(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap finger"
		self.tags = ['default', 'safe', 'finger']

	def configure(self):
		self.match_service_name('^finger')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,finger" -oN "{scandir}/{protocol}_{port}_finger_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_finger_nmap.xml" {address}')
