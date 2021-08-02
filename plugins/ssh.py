from autorecon import ServiceScan

class NmapSSH(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap SSH"
		self.tags = ['default', 'ssh']

	def configure(self):
		self.match_service_name('^ssh')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods" -oN "{scandir}/{protocol}_{port}_ssh_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_ssh_nmap.xml" {address}')

class BruteforceSSH(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Bruteforce SSH"
		self.tags = ['default', 'ssh']

	def configure(self):
		self.match_service_name('ssh')

	def manual(self):
		self.add_manual_command('Bruteforce logins:', [
			'hydra -L "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -P "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '" -e nsr -s {port} -o "{scandir}/{protocol}_{port}_ssh_hydra.txt" ssh://{address}',
			'medusa -U "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -P "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '" -e ns -n {port} -O "{scandir}/{protocol}_{port}_ssh_medusa.txt" -M ssh -h {address}'
		])
