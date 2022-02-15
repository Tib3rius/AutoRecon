from autorecon.plugins import PortScan
from autorecon.config import config
import re

class AllTCPPortScan(PortScan):

	def __init__(self):
		super().__init__()
		self.name = 'All TCP Ports'
		self.description = 'Performs an Nmap scan of all TCP ports.'
		self.type = 'tcp'
		self.specific_ports = True
		self.tags = ['default', 'default-port-scan', 'long']

	async def run(self, target):
		if config['proxychains']:
			traceroute_os = ''
		else:
			traceroute_os = ' -A --osscan-guess'

		if target.ports:
			if target.ports['tcp']:
				process, stdout, stderr = await target.execute('nmap {nmap_extra} -sV -sC --version-all' + traceroute_os + ' -p ' + target.ports['tcp'] + ' -oN "{scandir}/_full_tcp_nmap.txt" -oX "{scandir}/xml/_full_tcp_nmap.xml" {address}', blocking=False)
			else:
				return []
		else:
			process, stdout, stderr = await target.execute('nmap {nmap_extra} -sV -sC --version-all' + traceroute_os + ' -p- -oN "{scandir}/_full_tcp_nmap.txt" -oX "{scandir}/xml/_full_tcp_nmap.xml" {address}', blocking=False)
		services = []
		while True:
			line = await stdout.readline()
			if line is not None:
				match = re.search('^Discovered open port ([0-9]+)/tcp', line)
				if match:
					target.info('Discovered open port {bmagenta}tcp/' + match.group(1) + '{rst} on {byellow}' + target.address + '{rst}', verbosity=1)
				service = target.extract_service(line)
				if service:
					services.append(service)
			else:
				break
		await process.wait()
		return services
