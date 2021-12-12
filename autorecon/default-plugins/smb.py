from autorecon.plugins import ServiceScan

class NmapSMB(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap SMB"
		self.tags = ['default', 'safe', 'smb', 'active-directory']

	def configure(self):
		self.match_service_name(['^smb', '^microsoft\-ds', '^netbios'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_smb_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_nmap.xml" {address}')

class SMBVuln(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "SMB Vulnerabilities"
		self.tags = ['unsafe', 'smb', 'active-directory']

	def configure(self):
		self.match_service_name(['^smb', '^microsoft\-ds', '^netbios'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="smb-vuln-ms06-025" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_smb_ms06-025.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_ms06-025.xml" {address}')
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="smb-vuln-ms07-029" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_smb_ms07-029.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_ms07-029.xml" {address}')
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="smb-vuln-ms08-067" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_smb_ms08-067.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_ms08-067.xml" {address}')

	def manual(self, service, plugin_was_run):
		if not plugin_was_run: # Only suggest these if they weren't run.
			service.add_manual_commands('Nmap scans for SMB vulnerabilities that could potentially cause a DoS if scanned (according to Nmap). Be careful:', [
				'nmap {nmap_extra} -sV -p {port} --script="smb-vuln-ms06-025" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_smb_ms06-025.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_ms06-025.xml" {address}',
				'nmap {nmap_extra} -sV -p {port} --script="smb-vuln-ms07-029" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_smb_ms07-029.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_ms07-029.xml" {address}',
				'nmap {nmap_extra} -sV -p {port} --script="smb-vuln-ms08-067" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_smb_ms08-067.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_ms08-067.xml" {address}'
			])

class Enum4Linux(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Enum4Linux"
		self.tags = ['default', 'safe', 'active-directory']

	def configure(self):
		self.match_service_name(['^ldap', '^smb', '^microsoft\-ds', '^netbios'])
		self.match_port('tcp', [139, 389, 445])
		self.match_port('udp', 137)
		self.run_once(True)

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			await service.execute('enum4linux -a -M -l -d {address} 2>&1', outfile='enum4linux.txt')

class NBTScan(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "nbtscan"
		self.tags = ['default', 'safe', 'netbios', 'active-directory']

	def configure(self):
		self.match_service_name(['^smb', '^microsoft\-ds', '^netbios'])
		self.match_port('udp', 137)
		self.run_once(True)

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			await service.execute('nbtscan -rvh {address} 2>&1', outfile='nbtscan.txt')

class SMBClient(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "SMBClient"
		self.tags = ['default', 'safe', 'smb', 'active-directory']

	def configure(self):
		self.match_service_name(['^smb', '^microsoft\-ds', '^netbios'])
		self.match_port('tcp', [139, 445])
		self.run_once(True)

	async def run(self, service):
		await service.execute('smbclient -L //{address} -N -I {address} 2>&1', outfile='smbclient.txt')

class SMBMap(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "SMBMap"
		self.tags = ['default', 'safe', 'smb', 'active-directory']

	def configure(self):
		self.match_service_name(['^smb', '^microsoft\-ds', '^netbios'])

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			await service.execute('smbmap -H {address} -P {port} 2>&1', outfile='smbmap-share-permissions.txt')
			await service.execute('smbmap -u null -p "" -H {address} -P {port} 2>&1', outfile='smbmap-share-permissions.txt')
			await service.execute('smbmap -H {address} -P {port} -R 2>&1', outfile='smbmap-list-contents.txt')
			await service.execute('smbmap -u null -p "" -H {address} -P {port} -R 2>&1', outfile='smbmap-list-contents.txt')
			await service.execute('smbmap -H {address} -P {port} -x "ipconfig /all" 2>&1', outfile='smbmap-execute-command.txt')
			await service.execute('smbmap -u null -p "" -H {address} -P {port} -x "ipconfig /all" 2>&1', outfile='smbmap-execute-command.txt')
