from autorecon.plugins import ServiceScan
from shutil import which

class DnsRecon(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "DnsRecon Default Scan"
		self.slug = 'dnsrecon'
		self.priority = 0
		self.tags = ['default', 'safe', 'dns']

	def configure(self):
		self.match_service_name('^domain')

	def check(self):
		if which('dnsrecon') is None:
			self.error('The program dnsrecon could not be found. Make sure it is installed. (On Kali, run: sudo apt install dnsrecon)')
			return False

	def manual(self, service, plugin_was_run):
		service.add_manual_command('Use dnsrecon to automatically query data from the DNS server. You must specify the target domain name.', [
			'dnsrecon -n {address} -d <DOMAIN-NAME> 2>&1 | tee {scandir}/{protocol}_{port}_dnsrecon_default_manual.txt'
		])

	async def run(self, service):
		if self.get_global('domain'):
			await service.execute('dnsrecon -n {address} -d ' + self.get_global('domain') + ' 2>&1', outfile='{protocol}_{port}_dnsrecon_default.txt')
		else:
			service.error('A domain name was not specified in the command line options (--global.domain). If you know the domain name, look in the _manual_commands.txt file for the dnsrecon command.')
