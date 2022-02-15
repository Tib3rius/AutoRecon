from autorecon.plugins import ServiceScan
import os

class SubdomainEnumeration(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Subdomain Enumeration"
		self.slug = "subdomain-enum"
		self.tags = ['default', 'safe', 'long', 'dns']

	def configure(self):
		self.add_option('domain', help='The domain to use as the base domain (e.g. example.com) for subdomain enumeration. Default: %(default)s')
		self.add_list_option('wordlist', default=['/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt'], help='The wordlist(s) to use when enumerating subdomains. Separate multiple wordlists with spaces. Default: %(default)s')
		self.add_option('threads', default=10, help='The number of threads to use when enumerating subdomains. Default: %(default)s')
		self.match_service_name('^domain')

	async def run(self, service):
		domains = []

		if self.get_option('domain'):
			domains.append(self.get_option('domain'))
		if service.target.type == 'hostname' and service.target.address not in domains:
			domains.append(service.target.address)
		if self.get_global('domain') and self.get_global('domain') not in domains:
			domains.append(self.get_global('domain'))

		if len(domains) > 0:
			for wordlist in self.get_option('wordlist'):
				name = os.path.splitext(os.path.basename(wordlist))[0]
				for domain in domains:
					await service.execute('gobuster dns -d ' + domain + ' -r {addressv6} -w ' + wordlist + ' -o "{scandir}/{protocol}_{port}_' + domain + '_subdomains_' + name + '.txt"')
		else:
			service.info('The target was not a domain, nor was a domain provided as an option. Skipping subdomain enumeration.')
