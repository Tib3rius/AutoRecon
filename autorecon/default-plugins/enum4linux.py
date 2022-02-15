from autorecon.plugins import ServiceScan

class Enum4Linux(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Enum4Linux"
		self.tags = ['default', 'safe', 'active-directory']

	def configure(self):
		self.match_service_name(['^ldap', '^smb', '^microsoft\-ds', '^netbios'])
		self.match_port('tcp', [139, 389, 445])
		self.match_port('udp', 137)
		self.run_once(True)

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			await service.execute('enum4linux -a -M -l -d {address} 2>&1', outfile='enum4linux.txt')
