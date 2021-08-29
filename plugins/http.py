from autorecon import ServiceScan, error, info, fformat
from shutil import which
import os

class NmapHTTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap HTTP"
		self.tags = ['default', 'safe', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)
		self.add_pattern('Server: ([^\n]+)', description='Identified HTTP Server: {match}')
		self.add_pattern('WebDAV is ENABLED', description='WebDAV is enabled')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oN "{scandir}/{protocol}_{port}_{http_scheme}_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_{http_scheme}_nmap.xml" {address}')

class BruteforceHTTP(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Bruteforce HTTP"
		self.tags = ['default', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	def manual(self, service, plugin_was_run):
		service.add_manual_commands('Credential bruteforcing commands (don\'t run these without modifying them):', [
			'hydra -L "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -P "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '" -e nsr -s {port} -o "{scandir}/{protocol}_{port}_{http_scheme}_auth_hydra.txt" {http_scheme}-get://{address}/path/to/auth/area',
			'medusa -U "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -P "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '" -e ns -n {port} -O "{scandir}/{protocol}_{port}_{http_scheme}_auth_medusa.txt" -M http -h {address} -m DIR:/path/to/auth/area',
			'hydra -L "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -P "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '" -e nsr -s {port} -o "{scandir}/{protocol}_{port}_{http_scheme}_form_hydra.txt" {http_scheme}-post-form://{address}/path/to/login.php:username=^USER^&password=^PASS^:invalid-login-message',
			'medusa -U "' + self.get_global('username_wordlist', default='/usr/share/seclists/Usernames/top-usernames-shortlist.txt') + '" -P "' + self.get_global('password_wordlist', default='/usr/share/seclists/Passwords/darkweb2017-top100.txt') + '" -e ns -n {port} -O "{scandir}/{protocol}_{port}_{http_scheme}_form_medusa.txt" -M web-form -h {address} -m FORM:/path/to/login.php -m FORM-DATA:"post?username=&password=" -m DENY-SIGNAL:"invalid login message"'
		])

class Curl(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Curl"
		self.tags = ['default', 'safe', 'http']

	def configure(self):
		self.add_option("path", default="/", help="The path on the web server to curl. Default: %(default)s")
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)
		self.add_pattern('(?i)Powered by [^\n]+')

	async def run(self, service):
		if service.protocol == 'tcp':
			await service.execute('curl -sSik {http_scheme}://{address}:{port}' + self.get_option('path'), outfile='{protocol}_{port}_{http_scheme}_curl.html')

class CurlRobots(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Curl Robots"
		self.tags = ['default', 'safe', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	async def run(self, service):
		if service.protocol == 'tcp':
			_, stdout, _ = await service.execute('curl -sSikf {http_scheme}://{address}:{port}/robots.txt')
			lines = await stdout.readlines()

			if lines:
				filename = fformat('{scandir}/{protocol}_{port}_{http_scheme}_curl-robots.txt')
				with open(filename, mode='wt', encoding='utf8') as robots:
					robots.write('\n'.join(lines))
			else:
				info('{bblue}[' + fformat('{tag}') + ']{rst} There did not appear to be a robots.txt file in the webroot (/).')

class DirBuster(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Directory Buster"
		self.slug = 'dirbuster'
		self.priority = 0
		self.tags = ['default', 'safe', 'long', 'http']

	def configure(self):
		self.add_choice_option('tool', default='feroxbuster', choices=['feroxbuster', 'gobuster', 'dirsearch', 'ffuf', 'dirb'], help='The tool to use for directory busting. Default: %(default)s')
		self.add_list_option('wordlist', default=['/usr/share/seclists/Discovery/Web-Content/common.txt'], help='The wordlist(s) to use when directory busting. Separate multiple wordlists with spaces. Default: %(default)s')
		self.add_option('threads', default=10, help='The number of threads to use when directory busting. Default: %(default)s')
		self.add_option('ext', default='txt,html,php,asp,aspx,jsp', help='The extensions you wish to fuzz (no dot, comma separated). Default: %(default)s')
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	async def run(self, service):
		dot_extensions = ','.join(['.' + x for x in self.get_option('ext').split(',')])
		for wordlist in self.get_option('wordlist'):
			name = os.path.splitext(os.path.basename(wordlist))[0]
			if self.get_option('tool') == 'feroxbuster':
				await service.execute('feroxbuster -u {http_scheme}://{address}:{port}/ -t ' + str(self.get_option('threads')) + ' -w ' + wordlist + ' -x ' + self.get_option('ext') + ' -v -k -n -q -o "{scandir}/{protocol}_{port}_{http_scheme}_feroxbuster_' + name + '.txt"')
			elif self.get_option('tool') == 'gobuster':
				await service.execute('gobuster dir -u {http_scheme}://{address}:{port}/ -t ' + str(self.get_option('threads')) + ' -w ' + wordlist + ' -e -k -x "' + self.get_option('ext') + '" -z -o "{scandir}/{protocol}_{port}_{http_scheme}_gobuster_' + name + '.txt"')
			elif self.get_option('tool') == 'dirsearch':
				await service.execute('dirsearch -u {http_scheme}://{address}:{port}/ -t ' + str(self.get_option('threads')) + ' -e ' + self.get_option('ext') + ' -f -q -w ' + wordlist + ' --format=plain -o "{scandir}/{protocol}_{port}_{http_scheme}_dirsearch_' + name + '.txt"')
			elif self.get_option('tool') == 'ffuf':
				await service.execute('ffuf -u {http_scheme}://{address}:{port}/FUZZ -t ' + str(self.get_option('threads')) + ' -w ' + wordlist + ' -e "' + dot_extensions + '" -v -noninteractive | tee {scandir}/{protocol}_{port}_{http_scheme}_ffuf_' + name + '.txt')
			elif self.get_option('tool') == 'dirb':
				await service.execute('dirb {http_scheme}://{address}:{port}/ ' + wordlist + ' -l -r -S -X ",' + dot_extensions + '" -o "{scandir}/{protocol}_{port}_{http_scheme}_dirb_' + name + '.txt"')

	def manual(self, service, plugin_was_run):
		service.add_manual_command('(feroxbuster) Multi-threaded recursive directory/file enumeration for web servers using various wordlists:', [
			'feroxbuster -u {http_scheme}://{address}:{port} -t ' + str(self.get_option('threads')) + ' -w /usr/share/seclists/Discovery/Web-Content/big.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -o {scandir}/{protocol}_{port}_{http_scheme}_feroxbuster_big.txt',
			'feroxbuster -u {http_scheme}://{address}:{port} -t ' + str(self.get_option('threads')) + ' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -o {scandir}/{protocol}_{port}_{http_scheme}_feroxbuster_dirbuster.txt'
		])

		service.add_manual_command('(gobuster v3) Multi-threaded directory/file enumeration for web servers using various wordlists:', [
			'gobuster dir -u {http_scheme}://{address}:{port}/ -t ' + str(self.get_option('threads')) + ' -w /usr/share/seclists/Discovery/Web-Content/big.txt -e -k -x "txt,html,php,asp,aspx,jsp" -z -o "{scandir}/{protocol}_{port}_{http_scheme}_gobuster_big.txt"',
			'gobuster dir -u {http_scheme}://{address}:{port}/ -t ' + str(self.get_option('threads')) + ' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -x "txt,html,php,asp,aspx,jsp" -z -o "{scandir}/{protocol}_{port}_{http_scheme}_gobuster_dirbuster.txt"'
		])

		service.add_manual_command('(dirsearch) Multi-threaded recursive directory/file enumeration for web servers using various wordlists:', [
			'dirsearch -u {http_scheme}://{address}:{port}/ -t ' + str(self.get_option('threads')) + ' -r -e txt,html,php,asp,aspx,jsp -f -w /usr/share/seclists/Discovery/Web-Content/big.txt --format=plain --output="{scandir}/{protocol}_{port}_{http_scheme}_dirsearch_big.txt"',
			'dirsearch -u {http_scheme}://{address}:{port}/ -t ' + str(self.get_option('threads')) + ' -r -e txt,html,php,asp,aspx,jsp -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --format=plain --output="{scandir}/{protocol}_{port}_{http_scheme}_dirsearch_dirbuster.txt"'
		])

		service.add_manual_command('(dirb) Recursive directory/file enumeration for web servers using various wordlists:', [
			'dirb {http_scheme}://{address}:{port}/ /usr/share/seclists/Discovery/Web-Content/big.txt -l -r -S -X ",.txt,.html,.php,.asp,.aspx,.jsp" -o "{scandir}/{protocol}_{port}_{http_scheme}_dirb_big.txt"',
			'dirb {http_scheme}://{address}:{port}/ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -r -S -X ",.txt,.html,.php,.asp,.aspx,.jsp" -o "{scandir}/{protocol}_{port}_{http_scheme}_dirb_dirbuster.txt"'
		])

		service.add_manual_command('(gobuster v1 & v2) Multi-threaded directory/file enumeration for web servers using various wordlists:', [
			'gobuster -u {http_scheme}://{address}:{port}/ -t ' + str(self.get_option('threads')) + ' -w /usr/share/seclists/Discovery/Web-Content/big.txt -e -k -l -x "txt,html,php,asp,aspx,jsp" -o "{scandir}/{protocol}_{port}_{http_scheme}_gobuster_big.txt"',
			'gobuster -u {http_scheme}://{address}:{port}/ -t ' + str(self.get_option('threads')) + ' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -l -x "txt,html,php,asp,aspx,jsp" -o "{scandir}/{protocol}_{port}_{http_scheme}_gobuster_dirbuster.txt"'
		])

class Nikto(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'nikto'
		self.tags = ['default', 'safe', 'long', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	def manual(self, service, plugin_was_run):
		service.add_manual_command('(nikto) old but generally reliable web server enumeration tool:', 'nikto -ask=no -h {http_scheme}://{address}:{port} 2>&1 | tee "{scandir}/{protocol}_{port}_{http_scheme}_nikto.txt"')

class WhatWeb(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "whatweb"
		self.tags = ['default', 'safe', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	async def run(self, service):
		if service.protocol == 'tcp':
			await service.execute('whatweb --color=never --no-errors -a 3 -v {http_scheme}://{address}:{port} 2>&1', outfile='{protocol}_{port}_{http_scheme}_whatweb.txt')

class WkHTMLToImage(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "wkhtmltoimage"
		self.tags = ['default', 'safe', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	async def run(self, service):
		if which('wkhtmltoimage') is not None:
			if service.protocol == 'tcp':
				await service.execute('wkhtmltoimage --format png {http_scheme}://{address}:{port}/ {scandir}/{protocol}_{port}_{http_scheme}_screenshot.png')
		else:
			error('The wkhtmltoimage program could not be found. Make sure it is installed. (On Kali, run: sudo apt install wkhtmltopdf)')

class WPScan(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'WPScan'
		self.tags = ['default', 'safe', 'http']

	def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	def manual(self, service, plugin_was_run):
		service.add_manual_command('(wpscan) WordPress Security Scanner (useful if WordPress is found):', 'wpscan --url {http_scheme}://{address}:{port}/ --no-update -e vp,vt,tt,cb,dbe,u,m --plugins-detection aggressive --plugins-version-detection aggressive -f cli-no-color 2>&1 | tee "{scandir}/{protocol}_{port}_{http_scheme}_wpscan.txt"')
