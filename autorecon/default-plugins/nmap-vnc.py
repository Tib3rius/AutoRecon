from autorecon.plugins import ServiceScan

class NmapVNC(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap VNC'
		self.tags = ['default', 'safe', 'vnc']

	def configure(self):
		self.match_service_name('^vnc')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(vnc* or realvnc* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_vnc_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_vnc_nmap.xml" {address}')
