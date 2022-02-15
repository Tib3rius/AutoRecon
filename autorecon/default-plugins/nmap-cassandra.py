from autorecon.plugins import ServiceScan

class NmapCassandra(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap Cassandra"
		self.tags = ['default', 'safe', 'cassandra']

	def configure(self):
		self.match_service_name('^apani1')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(cassandra* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_cassandra_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_cassandra_nmap.xml" {address}')
