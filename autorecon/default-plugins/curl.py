from autorecon.plugins import ServiceScan

class Curl(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Curl"
		self.tags = ['default', 'safe', 'http']

	def configure(self):
		self.add_option("path", default="/", help="The path on the web server to curl. Default: %(default)s")
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)
		self.add_pattern('(?i)powered[ -]by[^\n]+')

	async def run(self, service):
		if service.protocol == 'tcp':
			await service.execute('curl -sSik {http_scheme}://{addressv6}:{port}' + self.get_option('path'), outfile='{protocol}_{port}_{http_scheme}_curl.html')
