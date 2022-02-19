from autorecon.plugins import ServiceScan
from autorecon.config import config
from shutil import which
import os

class DirBuster(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Directory Buster"
		self.slug = 'dirbuster'
		self.priority = 0
		self.tags = ['default', 'safe', 'long', 'http']

	def configure(self):
		self.add_choice_option('tool', default='feroxbuster', choices=['feroxbuster', 'gobuster', 'dirsearch', 'ffuf', 'dirb'], help='The tool to use for directory busting. Default: %(default)s')
		self.add_list_option('wordlist', default=[os.path.join(config['config_dir'], 'wordlists', 'dirbuster.txt')], help='The wordlist(s) to use when directory busting. Separate multiple wordlists with spaces. Default: %(default)s')
		self.add_option('threads', default=10, help='The number of threads to use when directory busting. Default: %(default)s')
		self.add_option('ext', default='txt,html,php,asp,aspx,jsp', help='The extensions you wish to fuzz (no dot, comma separated). Default: %(default)s')
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	def check(self):
		tool = self.get_option('tool')
		if tool == 'feroxbuster':
			if which('feroxbuster') is None:
				self.error('The feroxbuster program could not be found. Make sure it is installed. (On Kali, run: sudo apt install feroxbuster)')
		elif tool == 'gobuster':
			if which('gobuster') is None:
				self.error('The gobuster program could not be found. Make sure it is installed. (On Kali, run: sudo apt install gobuster)')
		elif tool == 'dirsearch':
			if which('dirsearch') is None:
				self.error('The dirsearch program could not be found. Make sure it is installed. (On Kali, run: sudo apt install dirsearch)')

	async def run(self, service):
		dot_extensions = ','.join(['.' + x for x in self.get_option('ext').split(',')])
		for wordlist in self.get_option('wordlist'):
			name = os.path.splitext(os.path.basename(wordlist))[0]
			if self.get_option('tool') == 'feroxbuster':
				await service.execute('feroxbuster -u {http_scheme}://{addressv6}:{port}/ -t ' + str(self.get_option('threads')) + ' -w ' + wordlist + ' -x "' + self.get_option('ext') + '" -v -k -n -q -e -o "{scandir}/{protocol}_{port}_{http_scheme}_feroxbuster_' + name + '.txt"')
			elif self.get_option('tool') == 'gobuster':
				await service.execute('gobuster dir -u {http_scheme}://{addressv6}:{port}/ -t ' + str(self.get_option('threads')) + ' -w ' + wordlist + ' -e -k -x "' + self.get_option('ext') + '" -z -o "{scandir}/{protocol}_{port}_{http_scheme}_gobuster_' + name + '.txt"')
			elif self.get_option('tool') == 'dirsearch':
				if service.target.ipversion == 'IPv6':
					service.error('dirsearch does not support IPv6.')
				else:
					await service.execute('dirsearch -u {http_scheme}://{address}:{port}/ -t ' + str(self.get_option('threads')) + ' -e "' + self.get_option('ext') + '" -f -q -w ' + wordlist + ' --format=plain -o "{scandir}/{protocol}_{port}_{http_scheme}_dirsearch_' + name + '.txt"')
			elif self.get_option('tool') == 'ffuf':
				await service.execute('ffuf -u {http_scheme}://{addressv6}:{port}/FUZZ -t ' + str(self.get_option('threads')) + ' -w ' + wordlist + ' -e "' + dot_extensions + '" -v -noninteractive | tee {scandir}/{protocol}_{port}_{http_scheme}_ffuf_' + name + '.txt')
			elif self.get_option('tool') == 'dirb':
				await service.execute('dirb {http_scheme}://{addressv6}:{port}/ ' + wordlist + ' -l -r -S -X ",' + dot_extensions + '" -o "{scandir}/{protocol}_{port}_{http_scheme}_dirb_' + name + '.txt"')

	def manual(self, service, plugin_was_run):
		dot_extensions = ','.join(['.' + x for x in self.get_option('ext').split(',')])
		if self.get_option('tool') == 'feroxbuster':
			service.add_manual_command('(feroxbuster) Multi-threaded recursive directory/file enumeration for web servers using various wordlists:', [
				'feroxbuster -u {http_scheme}://{addressv6}:{port} -t ' + str(self.get_option('threads')) + ' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "' + self.get_option('ext') + '" -v -k -n -e -o {scandir}/{protocol}_{port}_{http_scheme}_feroxbuster_dirbuster.txt'
			])
		elif self.get_option('tool') == 'gobuster':
			service.add_manual_command('(gobuster v3) Multi-threaded directory/file enumeration for web servers using various wordlists:', [
				'gobuster dir -u {http_scheme}://{addressv6}:{port}/ -t ' + str(self.get_option('threads')) + ' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -k -x "' + self.get_option('ext') + '" -o "{scandir}/{protocol}_{port}_{http_scheme}_gobuster_dirbuster.txt"'
			])
		elif self.get_option('tool') == 'dirsearch':
			if service.target.ipversion == 'IPv4':
				service.add_manual_command('(dirsearch) Multi-threaded recursive directory/file enumeration for web servers using various wordlists:', [
					'dirsearch -u {http_scheme}://{address}:{port}/ -t ' + str(self.get_option('threads')) + ' -e "' + self.get_option('ext') + '" -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --format=plain --output="{scandir}/{protocol}_{port}_{http_scheme}_dirsearch_dirbuster.txt"'
				])
		elif self.get_option('tool') == 'ffuf':
			service.add_manual_command('(ffuf) Multi-threaded recursive directory/file enumeration for web servers using various wordlists:', [
				'ffuf -u {http_scheme}://{addressv6}:{port}/FUZZ -t ' + str(self.get_option('threads')) + ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e "' + dot_extensions + '" -v -noninteractive | tee {scandir}/{protocol}_{port}_{http_scheme}_ffuf_dirbuster.txt'
			])
		elif self.get_option('tool') == 'dirb':
			service.add_manual_command('(dirb) Recursive directory/file enumeration for web servers using various wordlists:', [
				'dirb {http_scheme}://{addressv6}:{port}/ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -r -X ",' + dot_extensions + '" -o "{scandir}/{protocol}_{port}_{http_scheme}_dirb_dirbuster.txt"'
			])
