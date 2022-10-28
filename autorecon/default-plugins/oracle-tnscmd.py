from autorecon.plugins import ServiceScan
from shutil import which

class OracleTNScmd(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Oracle TNScmd"
		self.tags = ['default', 'safe', 'databases']

	def configure(self):
		self.match_service_name('^oracle')

	def check(self):
		if which('tnscmd10g') is None:
			self.error('The tnscmd10g program could not be found. Make sure it is installed. (On Kali, run: sudo apt install tnscmd10g)')
			return False

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			await service.execute('tnscmd10g ping -h {address} -p {port} 2>&1', outfile='{protocol}_{port}_oracle_tnscmd_ping.txt')
			await service.execute('tnscmd10g version -h {address} -p {port} 2>&1', outfile='{protocol}_{port}_oracle_tnscmd_version.txt')
