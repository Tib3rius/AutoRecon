from autorecon.plugins import ServiceScan

class OracleODAT(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Oracle ODAT"
		self.tags = ['default', 'safe', 'databases']

	def configure(self):
		self.match_service_name('^oracle')

	def manual(self, service, plugin_was_run):
		service.add_manual_commands('Install ODAT (https://github.com/quentinhardy/odat) and run the following commands:', [
			'python odat.py tnscmd -s {address} -p {port} --ping',
			'python odat.py tnscmd -s {address} -p {port} --version',
			'python odat.py tnscmd -s {address} -p {port} --status',
			'python odat.py sidguesser -s {address} -p {port}',
			'python odat.py passwordguesser -s {address} -p {port} -d <sid> --accounts-file accounts/accounts_multiple.txt',
			'python odat.py tnspoison -s {address} -p {port} -d <sid> --test-module'
		])
