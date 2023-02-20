from autorecon.plugins import ServiceScan

class SIPVicious(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "SIPVicious"
		self.tags = ['default', 'safe', 'sip']

	def configure(self):
		self.match_service_name(['^asterisk', '^sip'])

	def manual(self, service, plugin_was_run):
		if service.target.ipversion == 'IPv4':
			service.add_manual_command('svwar:', 'svwar -D -m INVITE -p {port} {address}')
