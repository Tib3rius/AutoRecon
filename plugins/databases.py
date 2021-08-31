from autorecon import ServiceScan

class NmapMongoDB(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap MongoDB"
		self.tags = ['default', 'safe', 'databases']

	def configure(self):
		self.match_service_name('^mongod')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(mongodb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_mongodb_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_mongodb_nmap.xml" {address}')

class NmapMSSQL(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap MSSQL"
		self.tags = ['default', 'safe', 'databases']

	def configure(self):
		self.match_service_name(['^mssql', '^ms\-sql'])

	def manual(self, service, plugin_was_run):
		if service.target.ipversion == 'IPv4':
			service.add_manual_command('(sqsh) interactive database shell:', 'sqsh -U <username> -P <password> -S {address}:{port}')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(ms-sql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="mssql.instance-port={port},mssql.username=sa,mssql.password=sa" -oN "{scandir}/{protocol}_{port}_mssql_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_mssql_nmap.xml" {address}')

class NmapMYSQL(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap MYSQL"
		self.tags = ['default', 'safe', 'databases']

	def configure(self):
		self.match_service_name('^mysql')

	def manual(self, service, plugin_was_run):
		if service.target.ipversion == 'IPv4':
			service.add_manual_command('(sqsh) interactive database shell:', 'sqsh -U <username> -P <password> -S {address}:{port}')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_mysql_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_mysql_nmap.xml" {address}')

class NmapOracle(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap Oracle"
		self.tags = ['default', 'safe', 'databases']

	def configure(self):
		self.match_service_name('^oracle')

	def manual(self, service, plugin_was_run):
		service.add_manual_command('Brute-force SIDs using Nmap:', 'nmap {nmap_extra} -sV -p {port} --script="banner,oracle-sid-brute" -oN "{scandir}/{protocol}_{port}_oracle_sid-brute_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_oracle_sid-brute_nmap.xml" {address}')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(oracle* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_oracle_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_oracle_nmap.xml" {address}')

class OracleTNScmd(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Oracle TNScmd"
		self.tags = ['default', 'safe', 'databases']

	def configure(self):
		self.match_service_name('^oracle')

	async def run(self, service):
		if service.target.ipversion == 'IPv4':
			await service.execute('tnscmd10g ping -h {address} -p {port} 2>&1', outfile='{protocol}_{port}_oracle_tnscmd_ping.txt')
			await service.execute('tnscmd10g version -h {address} -p {port} 2>&1', outfile='{protocol}_{port}_oracle_tnscmd_version.txt')

class OracleScanner(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Oracle Scanner"
		self.tags = ['default', 'safe', 'databases']

	def configure(self):
		self.match_service_name('^oracle')

	async def run(self, service):
		await service.execute('oscanner -v -s {address} -P {port} 2>&1', outfile='{protocol}_{port}_oracle_scanner.txt')

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

class OraclePatator(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Oracle Patator"
		self.tags = ['default', 'databases']

	def configure(self):
		self.match_service_name('^oracle')

	def manual(self, service, plugin_was_run):
		service.add_manual_command('Install Oracle Instant Client (https://github.com/rapid7/metasploit-framework/wiki/How-to-get-Oracle-Support-working-with-Kali-Linux) and then bruteforce with patator:', 'patator oracle_login host={address} port={port} user=COMBO00 password=COMBO01 0=/usr/share/seclists/Passwords/Default-Credentials/oracle-betterdefaultpasslist.txt -x ignore:code=ORA-01017 -x ignore:code=ORA-28000')
