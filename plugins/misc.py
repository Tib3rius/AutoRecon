from autorecon import ServiceScan

class NmapCassandra(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap Cassandra"
		self.tags = ['default', 'cassandra']

	def configure(self):
		self.match_service_name('^apani1')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(cassandra* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_cassandra_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_cassandra_nmap.xml" {address}')

class NmapCUPS(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap CUPS"
		self.tags = ['default', 'cups']

	def configure(self):
		self.match_service_name('^ipp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(cups* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_cups_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_cups_nmap.xml" {address}')

class NmapDistccd(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap distccd"
		self.tags = ['default', 'distccd']

	def configure(self):
		self.match_service_name('^distccd')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,distcc-cve2004-2687" --script-args="distcc-cve2004-2687.cmd=id" -oN "{scandir}/{protocol}_{port}_distcc_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_distcc_nmap.xml" {address}')

class NmapFinger(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap finger"
		self.tags = ['default', 'finger']

	def configure(self):
		self.match_service_name('^finger')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,finger" -oN "{scandir}/{protocol}_{port}_finger_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_finger_nmap.xml" {address}')

class NmapIMAP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap IMAP"
		self.tags = ['default', 'imap', 'email']

	def configure(self):
		self.match_service_name('^imap')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(imap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_imap_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_imap_nmap.xml" {address}')

class NmapNNTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap NNTP"
		self.tags = ['default', 'nntp']

	def configure(self):
		self.match_service_name('^nntp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,nntp-ntlm-info" -oN "{scandir}/{protocol}_{port}_nntp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_nntp_nmap.xml" {address}')

class NmapPOP3(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap POP3"
		self.tags = ['default', 'pop3', 'email']

	def configure(self):
		self.match_service_name('^pop3')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(pop3* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_pop3_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_pop3_nmap.xml" {address}')

class NmapRMI(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap RMI"
		self.tags = ['default', 'rmi']

	def configure(self):
		self.match_service_name(['^java\-rmi', '^rmiregistry'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,rmi-vuln-classloader,rmi-dumpregistry" -oN "{scandir}/{protocol}_{port}_rmi_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_rmi_nmap.xml" {address}')

class NmapSMTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap SMTP"
		self.tags = ['default', 'smtp', 'email']

	def configure(self):
		self.match_service_name('^smtp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(smtp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_smtp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_smtp_nmap.xml" {address}')

class SMTPUserEnum(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'SMTP-User-Enum'
		self.tags = ['default', 'smtp', 'email']

	def configure(self):
		self.match_service_name('^smtp')

	async def run(self, service):
		await service.execute('hydra smtp-enum://{address}:{port}/vrfy -L "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" 2>&1', outfile='{protocol}_{port}_smtp_user-enum_hydra_vrfy.txt')
		await service.execute('hydra smtp-enum://{address}:{port}/expn -L "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" 2>&1', outfile='{protocol}_{port}_smtp_user-enum_hydra_expn.txt')

	def manual(self):
		self.add_manual_command('Try User Enumeration using "RCPT TO". Replace <TARGET-DOMAIN> with the target\'s domain name:', [
			'hydra smtp-enum://{address}:{port}/rcpt -L "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -o "{scandir}/{protocol}_{port}_smtp_user-enum_hydra_rcpt.txt" -p <TARGET-DOMAIN>'
		])


class NmapTelnet(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap Telnet'
		self.tags = ['default', 'telnet']

	def configure(self):
		self.match_service_name('^telnet')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,telnet-encryption,telnet-ntlm-info" -oN "{scandir}/{protocol}_{port}_telnet-nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_telnet_nmap.xml" {address}')

class NmapTFTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap TFTP'
		self.tags = ['default', 'tftp']

	def configure(self):
		self.match_service_name('^tftp')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,tftp-enum" -oN "{scandir}/{protocol}_{port}_tftp-nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_tftp_nmap.xml" {address}')

class NmapVNC(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap VNC'
		self.tags = ['default', 'vnc']

	def configure(self):
		self.match_service_name('^vnc')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(vnc* or realvnc* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_vnc_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_vnc_nmap.xml" {address}')
