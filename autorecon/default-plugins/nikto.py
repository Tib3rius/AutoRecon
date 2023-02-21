from autorecon.plugins import ServiceScan

class Nikto(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'nikto'
		self.tags = ['default', 'safe', 'long', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			await service.execute('nikto -ask=no -Tuning=x4567890ac -nointeractive -host {http_scheme}://{address}:{port} 2>&1 | tee "{scandir}/{protocol}_{port}_{http_scheme}_nikto.txt"')

	def manual(self, service, plugin_was_run):
		if service.target.ipversion == 'IPv4' and not plugin_was_run:
			service.add_manual_command('(nikto) old but generally reliable web server enumeration tool:', 'nikto -ask=no -h {http_scheme}://{address}:{port} 2>&1 | tee "{scandir}/{protocol}_{port}_{http_scheme}_nikto.txt"')
