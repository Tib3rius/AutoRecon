from autorecon.plugins import ServiceScan

class OraclePatator(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Oracle Patator"
		self.tags = ['default', 'databases']

	def configure(self):
		self.match_service_name('^oracle')

	def manual(self, service, plugin_was_run):
		service.add_manual_command('Install Oracle Instant Client (https://github.com/rapid7/metasploit-framework/wiki/How-to-get-Oracle-Support-working-with-Kali-Linux) and then bruteforce with patator:', 'patator oracle_login host={address} port={port} user=COMBO00 password=COMBO01 0=/usr/share/seclists/Passwords/Default-Credentials/oracle-betterdefaultpasslist.txt -x ignore:code=ORA-01017 -x ignore:code=ORA-28000')
