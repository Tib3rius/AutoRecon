from autorecon.plugins import ServiceScan
from autorecon.io import fformat

class CurlKnownSecurity(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Known Security"
		self.tags = ['default', 'safe', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	async def run(self, service):
		if service.protocol == 'tcp':
			process, stdout, _ = await service.execute('curl -sSikf {http_scheme}://{addressv6}:{port}/.well-known/security.txt', future_outfile='{protocol}_{port}_{http_scheme}_known-security.txt')

			lines = await stdout.readlines()

			if process.returncode == 0 and lines:
				filename = fformat('{scandir}/{protocol}_{port}_{http_scheme}_known-security.txt')
				with open(filename, mode='wt', encoding='utf8') as robots:
					robots.write('\n'.join(lines))
			else:
				service.info('{bblue}[' + fformat('{tag}') + ']{rst} There did not appear to be a .well-known/security.txt file in the webroot (/).')
