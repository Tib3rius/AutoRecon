from autorecon.plugins import ServiceScan
from shutil import which

class OracleScanner(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Oracle Scanner"
		self.tags = ['default', 'safe', 'databases']

	def configure(self):
		self.match_service_name('^oracle')

	def check(self):
		if which('oscanner') is None:
			self.error('The oscanner program could not be found. Make sure it is installed. (On Kali, run: sudo apt install oscanner)')
			return False

	async def run(self, service):
		await service.execute('oscanner -v -s {address} -P {port} 2>&1', outfile='{protocol}_{port}_oracle_scanner.txt')
