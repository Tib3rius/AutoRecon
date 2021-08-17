from autorecon import ServiceScan, error
from shutil import which

class NmapRedis(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap Redis'
		self.tags = ['default', 'redis']

	def configure(self):
		self.match_service_name('^redis$')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,redis-info" -oN "{scandir}/{protocol}_{port}_redis_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_redis_nmap.xml" {address}')

class RedisCli(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Redis Cli'
		self.tags = ['default', 'redis']

	def configure(self):
		self.match_service_name('^redis$')

	async def run(self, service):
		if which('redis-cli') is not None:
			_, stdout, _ = await service.execute('redis-cli -p {port} -h {address} INFO', outfile='{protocol}_{port}_redis_info.txt')
			if not (await stdout.readline()).startswith('NOAUTH Authentication required'):
				await service.execute('redis-cli -p {port} -h {address} CONFIG GET \'*\'', outfile='{protocol}_{port}_redis_config.txt')
				await service.execute('redis-cli -p {port} -h {address} CLIENT LIST', outfile='{protocol}_{port}_redis_client-list.txt')
		else:
			error('The redis-cli program could not be found. Make sure it is installed. (On Kali, run: sudo apt install redis-tools)')
