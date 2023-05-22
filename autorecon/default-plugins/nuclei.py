from autorecon.plugins import ServiceScan

class Nikto(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'nuclei'
		self.tags = ['default', 'safe', 'long', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			await service.execute('nuclei -target {http_scheme}://{address}:{port} -scan-all-ips -automatic-scan 2>&1 | tee "{scandir}/{protocol}_{port}_{http_scheme}_nuclei.txt"')

	def manual(self, service, plugin_was_run):
		if service.target.ipversion == 'IPv4' and not plugin_was_run:
			service.add_manual_command('(nuclei) powerful & highly configurable web server enumeration tool from projectdiscovery.io:', 'nuclei -target {http_scheme}://{address}:{port} -scan-all-ips -automatic-scan 2>&1 | tee "{scandir}/{protocol}_{port}_{http_scheme}_nuclei.txt"')
