from autorecon import ServiceScan, error
from shutil import which

class NmapMSRPC(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap MSRPC"
		self.tags = ['default', 'rpc']

	def configure(self):
		self.match_service_name(['^msrpc', '^rpcbind', '^erpc'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,msrpc-enum,rpc-grind,rpcinfo" -oN "{scandir}/{protocol}_{port}_rpc_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_rpc_nmap.xml" {address}')

class RPCClient(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "rpcclient"
		self.tags = ['default', 'rpc']

	def configure(self):
		self.match_service_name(['^msrpc', '^rpcbind', '^erpc'])

	def manual(self, service, plugin_was_run):
		service.add_manual_command('RPC Client:', 'rpcclient -p {port} -U "" {address}')

class RPCDump(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'rpcdump'
		self.tags = ['default', 'rpc']

	def configure(self):
		self.match_service_name(['^msrpc', '^rpcbind', '^erpc'])

	async def run(self, service):
		if which('impacket-rpcdump') is not None:
			if service.protocol == 'tcp':
				await service.execute('impacket-rpcdump -port {port} {address}', outfile='{protocol}_{port}_rpc_rpcdump.txt')
		else:
			error('The impacket-rpcdump program could not be found. Make sure it is installed. (On Kali, run: sudo apt install impacket-scripts)')
