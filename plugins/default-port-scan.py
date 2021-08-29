from autorecon import PortScan, error
import os

class QuickTCPPortScan(PortScan):

	def __init__(self):
		super().__init__()
		self.name = "Top TCP Ports"
		self.type = 'tcp'
		self.tags = ["default", "default-port-scan"]
		self.priority = 0

	async def run(self, target):
		if target.ports:
			if target.ports['tcp']:
				process, stdout, stderr = await target.execute('nmap {nmap_extra} -A --osscan-guess --version-all -p ' + target.ports['tcp'] + ' -oN "{scandir}/_custom_ports_tcp_nmap.txt" -oX "{scandir}/xml/_custom_ports_tcp_nmap.xml" {address}', blocking=False)
			else:
				return []
		else:
			process, stdout, stderr = await target.execute('nmap {nmap_extra} -A --osscan-guess --version-all -oN "{scandir}/_quick_tcp_nmap.txt" -oX "{scandir}/xml/_quick_tcp_nmap.xml" {address}', blocking=False)
		services = await target.extract_services(stdout)
		await process.wait()
		return services

class AllTCPPortScan(PortScan):

	def __init__(self):
		super().__init__()
		self.name = "All TCP Ports"
		self.type = 'tcp'
		self.tags = ["default", "default-port-scan", "long"]

	async def run(self, target):
		if target.ports: # Don't run this plugin if there are custom ports.
			return []
		process, stdout, stderr = await target.execute('nmap {nmap_extra} -A --osscan-guess --version-all -p- -oN "{scandir}/_full_tcp_nmap.txt" -oX "{scandir}/xml/_full_tcp_nmap.xml" {address}', blocking=False)
		services = await target.extract_services(stdout)
		await process.wait()
		return services

class Top100UDPPortScan(PortScan):

	def __init__(self):
		super().__init__()
		self.name = "Top 100 UDP Ports"
		self.type = 'udp'
		self.tags = ["default", "default-port-scan", "long"]

	async def run(self, target):
		# Only run UDP scan if user is root.
		if os.getuid() == 0:
			if target.ports:
				if target.ports['udp']:
					process, stdout, stderr = await target.execute('nmap {nmap_extra} -sU -A --version-all -p ' + target.ports['udp'] + ' -oN "{scandir}/_custom_ports_udp_nmap.txt" -oX "{scandir}/xml/_custom_ports_udp_nmap.xml" {address}', blocking=False)
				else:
					return []
			else:
				process, stdout, stderr = await target.execute('nmap {nmap_extra} -sU -A --version-all --top-ports 100 -oN "{scandir}/_top_100_udp_nmap.txt" -oX "{scandir}/xml/_top_100_udp_nmap.xml" {address}', blocking=False)
			services = await target.extract_services(stdout)
			await process.wait()
			return services
		else:
			error('UDP scan requires AutoRecon be run with root privileges.')
