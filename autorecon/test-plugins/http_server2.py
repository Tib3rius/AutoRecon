from autorecon.plugins import ServiceScan


class DirectoryListing(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Directory Listing"
		self.tags = ['default', 'safe', 'http', 'test']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)
		self.add_pattern('<h1>Directory listing for', description='Directory Listing enabled',
						 plugin_names=["Directory Listing Verify"])

	async def run(self, service):
		await service.execute('curl {http_scheme}://{addressv6}:{port}')


class DirectoryListingVerify(ServiceScan):
	"""
	this is a useless plugin that is only run, if directory listing was found.
	"""
	def __init__(self):
		super().__init__()
		self.name = "Directory Listing verify"
		self.tags = ['default', 'safe', 'http', 'test']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	async def run(self, service):
		await service.execute('curl {http_scheme}://{addressv6}:{port}/?id=1')

	def get_previous_plugin_names(self):
		return ["Directory Listing"]
