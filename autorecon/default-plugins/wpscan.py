from autorecon.plugins import ServiceScan

class WPScan(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'WPScan'
		self.tags = ['default', 'safe', 'http']

	def configure(self):
		self.add_option('api-token', help='An API Token from wpvulndb.com to help search for more vulnerabilities.')
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	def manual(self, service, plugin_was_run):
		api_token = ''
		if self.get_option('api-token'):
			api_token = ' --api-token ' + self.get_option('api-token')

		service.add_manual_command('(wpscan) WordPress Security Scanner (useful if WordPress is found):', 'wpscan --url {http_scheme}://{addressv6}:{port}/ --no-update -e vp,vt,tt,cb,dbe,u,m --plugins-detection aggressive --plugins-version-detection aggressive -f cli-no-color' + api_token + ' 2>&1 | tee "{scandir}/{protocol}_{port}_{http_scheme}_wpscan.txt"')
