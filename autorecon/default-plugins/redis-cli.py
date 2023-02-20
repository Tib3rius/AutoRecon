from autorecon.plugins import ServiceScan
from shutil import which

class RedisCli(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Redis Cli'
		self.tags = ['default', 'safe', 'redis']

	def configure(self):
		self.match_service_name('^redis$')

	def check(self):
		if which('redis-cli') is None:
			self.error('The redis-cli program could not be found. Make sure it is installed. (On Kali, run: sudo apt install redis-tools)')
			return False

	async def run(self, service):
		if which('redis-cli') is not None:
			_, stdout, _ = await service.execute('redis-cli -p {port} -h {address} INFO', outfile='{protocol}_{port}_redis_info.txt')
			if not (await stdout.readline()).startswith('NOAUTH Authentication required'):
				await service.execute('redis-cli -p {port} -h {address} CONFIG GET \'*\'', outfile='{protocol}_{port}_redis_config.txt')
				await service.execute('redis-cli -p {port} -h {address} CLIENT LIST', outfile='{protocol}_{port}_redis_client-list.txt')
