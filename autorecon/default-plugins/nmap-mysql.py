from autorecon.plugins import ServiceScan

class NmapMYSQL(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap MYSQL"
		self.tags = ['default', 'safe', 'databases']

	def configure(self):
		self.match_service_name('^mysql')

	def manual(self, service, plugin_was_run):
		if service.target.ipversion == 'IPv4':
			service.add_manual_command('(sqsh) interactive database shell:', 'sqsh -U <username> -P <password> -S {address}:{port}')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_mysql_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_mysql_nmap.xml" {address}')
