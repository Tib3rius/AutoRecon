from autorecon.plugins import ServiceScan
from shutil import which

class WkHTMLToImage(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "wkhtmltoimage"
		self.tags = ['default', 'safe', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	def check(self):
		if which('wkhtmltoimage') is None:
			self.error('The wkhtmltoimage program could not be found. Make sure it is installed. (On Kali, run: sudo apt install wkhtmltopdf)')
			return False

	async def run(self, service):
		if which('wkhtmltoimage') is not None:
			if service.protocol == 'tcp':
				await service.execute('wkhtmltoimage --format png {http_scheme}://{addressv6}:{port}/ {scandir}/{protocol}_{port}_{http_scheme}_screenshot.png')
