from autorecon.plugins import ServiceScan

class Nikto(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'nikto'
		self.tags = ['default', 'safe', 'long', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	def manual(self, service, plugin_was_run):
		if service.target.ipversion == 'IPv4':
			service.add_manual_command('(nikto) old but generally reliable web server enumeration tool:', 'nikto -ask=no -h {http_scheme}://{address}:{port} 2>&1 | tee "{scandir}/{protocol}_{port}_{http_scheme}_nikto.txt"')
