from autorecon.plugins import ServiceScan

class RsyncList(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Rsync List Files'
		self.tags = ['default', 'safe', 'rsync']

	def configure(self):
		self.match_service_name('^rsync')

	async def run(self, service):
		await service.execute('rsync -av --list-only rsync://{addressv6}:{port}', outfile='{protocol}_{port}_rsync_file_list.txt')
