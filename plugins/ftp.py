from autorecon import ServiceScan

class NmapFTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap FTP'
		self.tags = ['default', 'ftp']

	def configure(self):
		self.match_service_name(['^ftp', '^ftp\-data'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_ftp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_ftp_nmap.xml" {address}')

class BruteforceFTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Bruteforce FTP"
		self.tags = ['default', 'ftp']

	def configure(self):
		self.match_service_name(['^ftp', '^ftp\-data'])

	def manual(self, service, plugin_was_run):
		service.add_manual_commands('Bruteforce logins:', [
			'hydra -L "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -P "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '" -e nsr -s {port} -o "{scandir}/{protocol}_{port}_ftp_hydra.txt" ftp://{address}',
			'medusa -U "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -P "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '" -e ns -n {port} -O "{scandir}/{protocol}_{port}_ftp_medusa.txt" -M ftp -h {address}'
		])
