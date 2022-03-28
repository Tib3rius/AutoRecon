from autorecon.plugins import ServiceScan

class OneSixtyOne(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "OneSixtyOne"
		self.tags = ['default', 'safe', 'snmp']

	def configure(self):
		self.match_service_name('^snmp')
		self.match_port('udp', 161)
		self.run_once(True)
		self.add_option('community-strings', default='/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt', help='The file containing a list of community strings to try. Default: %(default)s')

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			await service.execute('onesixtyone -c ' + self.get_option('community-strings') + ' -dd {address} 2>&1', outfile='{protocol}_{port}_snmp_onesixtyone.txt')
