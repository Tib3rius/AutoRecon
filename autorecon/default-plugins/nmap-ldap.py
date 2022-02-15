from autorecon.plugins import ServiceScan

class NmapLDAP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap LDAP"
		self.tags = ['default', 'safe', 'ldap', 'active-directory']

	def configure(self):
		self.match_service_name('^ldap')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_ldap_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_ldap_nmap.xml" {address}')
