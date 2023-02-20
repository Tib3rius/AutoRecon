from autorecon.plugins import ServiceScan

class NmapRsync(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap Rsync'
		self.tags = ['default', 'safe', 'rsync']

	def configure(self):
		self.match_service_name('^rsync')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(rsync* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_rsync_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_rsync_nmap.xml" {address}')
