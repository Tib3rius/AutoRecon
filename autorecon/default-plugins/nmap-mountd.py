from autorecon.plugins import ServiceScan

class NmapMountd(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap Mountd"
		self.tags = ['default', 'safe', 'nfs']

	def configure(self):
		self.match_service_name('^mountd')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,nfs* and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_mountd_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_mountd_nmap.xml" {address}')
