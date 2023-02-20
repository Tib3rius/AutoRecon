from autorecon.plugins import ServiceScan

class NmapIrc(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap IRC'
		self.tags = ['default', 'safe', 'irc']

	def configure(self):
		self.match_service_name('^irc')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -oN "{scandir}/{protocol}_{port}_irc_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_irc_nmap.xml" -p {port} {address}')
