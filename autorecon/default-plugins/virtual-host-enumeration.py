from autorecon.plugins import ServiceScan
from shutil import which
import os, requests, random, string, urllib3
urllib3.disable_warnings()

class VirtualHost(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Virtual Host Enumeration'
		self.slug = 'vhost-enum'
		self.tags = ['default', 'safe', 'http', 'long']

	def configure(self):
		self.add_option('hostname', help='The hostname to use as the base host (e.g. example.com) for virtual host enumeration. Default: %(default)s')
		self.add_list_option('wordlist', default=['/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt'], help='The wordlist(s) to use when enumerating virtual hosts. Separate multiple wordlists with spaces. Default: %(default)s')
		self.add_option('threads', default=10, help='The number of threads to use when enumerating virtual hosts. Default: %(default)s')
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)

	async def run(self, service):
		hostnames = []
		if self.get_option('hostname'):
			hostnames.append(self.get_option('hostname'))
		if service.target.type == 'hostname' and service.target.address not in hostnames:
			hostnames.append(service.target.address)
		if self.get_global('domain') and self.get_global('domain') not in hostnames:
			hostnames.append(self.get_global('domain'))

		if len(hostnames) > 0:
			for wordlist in self.get_option('wordlist'):
				name = os.path.splitext(os.path.basename(wordlist))[0]
				for hostname in hostnames:
					wildcard = requests.get(('https' if service.secure else 'http') + '://' + service.target.address + ':' + str(service.port) + '/', headers={'Host':''.join(random.choice(string.ascii_letters) for i in range(20)) + '.' + hostname}, verify=False)

					size = str(len(wildcard.content))
					await service.execute('ffuf -u {http_scheme}://' + hostname + ':{port}/ -t ' + str(self.get_option('threads')) + ' -w ' + wordlist + ' -H "Host: FUZZ.' + hostname + '" -mc all -fs ' + size + ' -r -noninteractive -s | tee "{scandir}/{protocol}_{port}_{http_scheme}_' + hostname + '_vhosts_' + name + '.txt"')
		else:
			service.info('The target was not a hostname, nor was a hostname provided as an option. Skipping virtual host enumeration.')
