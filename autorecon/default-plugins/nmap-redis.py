from autorecon.plugins import ServiceScan

class NmapRedis(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap Redis'
		self.tags = ['default', 'safe', 'redis']

	def configure(self):
		self.match_service_name('^redis$')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,redis-info" -oN "{scandir}/{protocol}_{port}_redis_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_redis_nmap.xml" {address}')
