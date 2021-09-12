from autorecon.plugins import ServiceScan

class NmapRDP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap RDP"
		self.tags = ['default', 'safe', 'rdp']

	def configure(self):
		self.match_service_name(['^rdp', '^ms\-wbt\-server', '^ms\-term\-serv'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(rdp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_rdp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_rdp_nmap.xml" {address}')

class BruteforceRDP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Bruteforce RDP"
		self.tags = ['default', 'rdp']

	def configure(self):
		self.match_service_name(['^rdp', '^ms\-wbt\-server', '^ms\-term\-serv'])

	def manual(self, service, plugin_was_run):
		service.add_manual_commands('Bruteforce logins:', [
			'hydra -L "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -P "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '" -e nsr -s {port} -o "{scandir}/{protocol}_{port}_rdp_hydra.txt" rdp://{addressv6}',
			'medusa -U "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -P "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '" -e ns -n {port} -O "{scandir}/{protocol}_{port}_rdp_medusa.txt" -M rdp -h {addressv6}'
		])
