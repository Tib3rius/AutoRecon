from autorecon.plugins import PortScan
from autorecon.config import config

class QuickTCPPortScan(PortScan):

	def __init__(self):
		super().__init__()
		self.name = 'Top TCP Ports'
		self.description = 'Performs an Nmap scan of the top 1000 TCP ports.'
		self.type = 'tcp'
		self.tags = ['default', 'default-port-scan']
		self.priority = 0

	async def run(self, target):
		if target.ports: # Don't run this plugin if there are custom ports.
			return []

		if config['proxychains']:
			traceroute_os = ''
		else:
			traceroute_os = ' -A --osscan-guess'

		process, stdout, stderr = await target.execute('nmap {nmap_extra} -sV -sC --version-all' + traceroute_os + ' -oN "{scandir}/_quick_tcp_nmap.txt" -oX "{scandir}/xml/_quick_tcp_nmap.xml" {address}', blocking=False)
		services = await target.extract_services(stdout)
		await process.wait()
		return services
