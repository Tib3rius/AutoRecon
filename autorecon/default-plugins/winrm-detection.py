from autorecon.plugins import ServiceScan
from autorecon.io import fformat

class WinRMDetection(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'WinRM Detection'
		self.tags = ['default', 'safe', 'winrm']

	def configure(self):
		self.match_service_name('^wsman')
		self.match_service('tcp', [5985, 5986], '^http')

	async def run(self, service):
		filename = fformat('{scandir}/{protocol}_{port}_winrm-detection.txt')
		with open(filename, mode='wt', encoding='utf8') as winrm:
			winrm.write('WinRM was possibly detected running on ' + service.protocol + ' port ' + str(service.port) + '.\nCheck _manual_commands.txt for manual commands you can run against this service.')

	def manual(self, service, plugin_was_run):
		service.add_manual_commands('Bruteforce logins:', [
			'crackmapexec winrm {address} -d \'' + self.get_global('domain', default='<domain>') + '\' -u \'' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '\' -p \'' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '\''
		])

		service.add_manual_commands('Check login (requires credentials):', [
			'crackmapexec winrm {address} -d \'' + self.get_global('domain', default='<domain>') + '\' -u \'<username>\' -p \'<password>\''
		])

		service.add_manual_commands('Evil WinRM (gem install evil-winrm):', [
			'evil-winrm -u \'<user>\' -p \'<password>\' -i {address}',
			'evil-winrm -u \'<user>\' -H \'<hash>\' -i {address}'
		])
