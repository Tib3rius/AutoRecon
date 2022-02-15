from autorecon.plugins import ServiceScan

class WhatWeb(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "whatweb"
		self.tags = ['default', 'safe', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	async def run(self, service):
		if service.protocol == 'tcp' and service.target.ipversion == 'IPv4':
			await service.execute('whatweb --color=never --no-errors -a 3 -v {http_scheme}://{address}:{port} 2>&1', outfile='{protocol}_{port}_{http_scheme}_whatweb.txt')
