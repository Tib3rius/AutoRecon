from autorecon.plugins import ServiceScan

class LDAPSearch(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'LDAP Search'
		self.tags = ['default', 'safe', 'ldap', 'active-directory']

	def configure(self):
		self.match_service_name('^ldap')

	def manual(self, service, plugin_was_run):
		service.add_manual_command('ldapsearch command (modify before running):', [
			'ldapsearch -x -D "<username>" -w "<password>" -H ldap://{address}:{port} -b "dc=example,dc=com" -s sub "(objectclass=*)" 2>&1 | tee > "{scandir}/{protocol}_{port}_ldap_all-entries.txt"'
		])
