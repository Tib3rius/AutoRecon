from autorecon.plugins import ServiceScan

class Showmount(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "showmount"
		self.tags = ['default', 'safe', 'nfs']

	def configure(self):
		self.match_service_name(['^nfs', '^rpcbind'])

	async def run(self, service):
		await service.execute('showmount -e {address} 2>&1', outfile='{protocol}_{port}_showmount.txt')
