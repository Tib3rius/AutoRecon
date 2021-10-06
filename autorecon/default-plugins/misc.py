from autorecon.plugins import ServiceScan
from autorecon.io import fformat

class NmapCassandra(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap Cassandra"
		self.tags = ['default', 'safe', 'cassandra']

	def configure(self):
		self.match_service_name('^apani1')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(cassandra* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_cassandra_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_cassandra_nmap.xml" {address}')

class NmapCUPS(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap CUPS"
		self.tags = ['default', 'safe', 'cups']

	def configure(self):
		self.match_service_name('^ipp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(cups* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_cups_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_cups_nmap.xml" {address}')

class NmapDistccd(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap distccd"
		self.tags = ['default', 'safe', 'distccd']

	def configure(self):
		self.match_service_name('^distccd')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,distcc-cve2004-2687" --script-args="distcc-cve2004-2687.cmd=id" -oN "{scandir}/{protocol}_{port}_distcc_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_distcc_nmap.xml" {address}')

class NmapFinger(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap finger"
		self.tags = ['default', 'safe', 'finger']

	def configure(self):
		self.match_service_name('^finger')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,finger" -oN "{scandir}/{protocol}_{port}_finger_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_finger_nmap.xml" {address}')

class NmapIMAP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap IMAP"
		self.tags = ['default', 'safe', 'imap', 'email']

	def configure(self):
		self.match_service_name('^imap')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(imap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_imap_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_imap_nmap.xml" {address}')

class NmapIrc(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap IRC'
		self.tags = ['default', 'safe', 'irc']

	def configure(self):
		self.match_service_name('^irc')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -oN "{scandir}/{protocol}_{port}_irc_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_irc_nmap.xml" -p {port} {address}')

class NmapNNTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap NNTP"
		self.tags = ['default', 'safe', 'nntp']

	def configure(self):
		self.match_service_name('^nntp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,nntp-ntlm-info" -oN "{scandir}/{protocol}_{port}_nntp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_nntp_nmap.xml" {address}')

class NmapNTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap NTP"
		self.tags = ['default', 'safe', 'ntp']

	def configure(self):
		self.match_service_name('^ntp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(ntp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_ntp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_ntp_nmap.xml" {address}')

class NmapPOP3(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap POP3"
		self.tags = ['default', 'safe', 'pop3', 'email']

	def configure(self):
		self.match_service_name('^pop3')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(pop3* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_pop3_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_pop3_nmap.xml" {address}')

class NmapRMI(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap RMI"
		self.tags = ['default', 'safe', 'rmi']

	def configure(self):
		self.match_service_name(['^java\-rmi', '^rmiregistry'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,rmi-vuln-classloader,rmi-dumpregistry" -oN "{scandir}/{protocol}_{port}_rmi_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_rmi_nmap.xml" {address}')

class NmapTelnet(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap Telnet'
		self.tags = ['default', 'safe', 'telnet']

	def configure(self):
		self.match_service_name('^telnet')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,telnet-encryption,telnet-ntlm-info" -oN "{scandir}/{protocol}_{port}_telnet-nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_telnet_nmap.xml" {address}')

class NmapTFTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap TFTP'
		self.tags = ['default', 'safe', 'tftp']

	def configure(self):
		self.match_service_name('^tftp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,tftp-enum" -oN "{scandir}/{protocol}_{port}_tftp-nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_tftp_nmap.xml" {address}')

class NmapVNC(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap VNC'
		self.tags = ['default', 'safe', 'vnc']

	def configure(self):
		self.match_service_name('^vnc')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(vnc* or realvnc* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_vnc_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_vnc_nmap.xml" {address}')

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
			'crackmapexec winrm {address} -d ' + self.get_global('domain', default='<domain>') + ' -u ' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + ' -p ' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt')
		])

		service.add_manual_commands('Check login (requires credentials):', [
			'crackmapexec winrm {address} -d ' + self.get_global('domain', default='<domain>') + ' -u <username> -p <password> -x "whoami"'
		])

		service.add_manual_commands('Evil WinRM (gem install evil-winrm):', [
			'evil-winrm -u <user> -p <password> -i {address}',
			'evil-winrm -u <user> -H <hash> -i {address}'
		])
