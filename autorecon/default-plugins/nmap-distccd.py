from autorecon.plugins import ServiceScan

class NmapDistccd(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap distccd"
		self.tags = ['default', 'safe', 'distccd']

	def configure(self):
		self.match_service_name('^distccd')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,distcc-cve2004-2687" --script-args="distcc-cve2004-2687.cmd=id" -oN "{scandir}/{protocol}_{port}_distcc_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_distcc_nmap.xml" {address}')
