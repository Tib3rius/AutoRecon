from autorecon.plugins import PortScan
from autorecon.config import config
import os, re

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

class Top100UDPPortScan(PortScan):

	def __init__(self):
		super().__init__()
		self.name = 'Top 100 UDP Ports'
		self.description = 'Performs an Nmap scan of the top 100 UDP ports.'
		self.type = 'udp'
		self.specific_ports = True
		self.tags = ['default', 'default-port-scan', 'long']

	async def run(self, target):
		# Only run UDP scan if user is root.
		if os.getuid() == 0:
			if target.ports:
				if target.ports['udp']:
					process, stdout, stderr = await target.execute('nmap {nmap_extra} -sU -A --osscan-guess -p ' + target.ports['udp'] + ' -oN "{scandir}/_custom_ports_udp_nmap.txt" -oX "{scandir}/xml/_custom_ports_udp_nmap.xml" {address}', blocking=False)
				else:
					return []
			else:
				process, stdout, stderr = await target.execute('nmap {nmap_extra} -sU -A --top-ports 100 -oN "{scandir}/_top_100_udp_nmap.txt" -oX "{scandir}/xml/_top_100_udp_nmap.xml" {address}', blocking=False)
			services = []
			while True:
				line = await stdout.readline()
				if line is not None:
					match = re.search('^Discovered open port ([0-9]+)/udp', line)
					if match:
						target.info('Discovered open port {bmagenta}udp/' + match.group(1) + '{rst} on {byellow}' + target.address + '{rst}', verbosity=1)
					service = target.extract_service(line)
					if service:
						services.append(service)
				else:
					break
			await process.wait()
			return services
		else:
			target.error('UDP scan requires AutoRecon be run with root privileges.')
