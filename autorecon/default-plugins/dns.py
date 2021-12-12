from autorecon.plugins import ServiceScan
from autorecon.io import error
from shutil import which

class NmapDNS(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap DNS'
		self.tags = ['default', 'safe', 'dns']

	def configure(self):
		self.match_service_name('^domain')

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_dns_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_dns_nmap.xml" {address}')

class DNSZoneTransfer(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'DNS Zone Transfer'
		self.tags = ['default', 'safe', 'dns']

	def configure(self):
		self.match_service_name('^domain')

	async def run(self, service):
		if self.get_global('domain'):
			await service.execute('dig AXFR -p {port} @{address} ' + self.get_global('domain'), outfile='{protocol}_{port}_dns_zone-transfer-domain.txt')
		if service.target.type == 'hostname':
			await service.execute('dig AXFR -p {port} @{address} {address}', outfile='{protocol}_{port}_dns_zone-transfer-hostname.txt')
		await service.execute('dig AXFR -p {port} @{address}', outfile='{protocol}_{port}_dns_zone-transfer.txt')

class DNSReverseLookup(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'DNS Reverse Lookup'
		self.tags = ['default', 'safe', 'dns']

	def configure(self):
		self.match_service_name('^domain')

	async def run(self, service):
		await service.execute('dig -p {port} -x {address} @{address}', outfile='{protocol}_{port}_dns_reverse-lookup.txt')

class NmapMulticastDNS(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Nmap Multicast DNS'
		self.tags = ['default', 'safe', 'dns']

	def configure(self):
		self.match_service_name(['^mdns', '^zeroconf'])

	async def run(self, service):
		await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_multicastdns_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_multicastdns_nmap.xml" {address}')


class DnsReconDefault(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "DnsRecon Default Scan"
        self.slug = 'dnsrecon'
        self.priority = 0
        self.tags = ['default', 'safe', 'dns']

    def configure(self):
        self.match_service_name('^domain')

    def check(self):
        if which('dnsrecon') is None:
            error('The program dnsrecon could not be found. Make sure it is installed. (On Kali, run: sudo apt install dnsrecon)')

    def manual(self, service, plugin_was_run):
        service.add_manual_command('Use dnsrecon to automatically query data from the DNS server. You must specify the target domain name.', [
            'dnsrecon -n {address} -d <DOMAIN-NAME> 2>&1 | tee {scandir}/{protocol}_{port}_dnsrecon_default_manual.txt'
        ])

    async def run(self, service):
        if self.get_global('domain'):
            await service.execute('dnsrecon -n {address} -d ' + self.get_global('domain') + ' 2>&1', outfile='{protocol}_{port}_dnsrecon_default.txt')
        else:
            error('A domain name was not specified in the command line options (--global.domain). If you know the domain name, look in the _manual_commands.txt file for the dnsrecon command.')

class DnsReconSubdomainBruteforce(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "DnsRecon Bruteforce Subdomains"
        self.slug = 'dnsrecon-brute'
        self.priority = 0
        self.tags = ['default', 'safe', 'long', 'dns']

    def configure(self):
        self.match_service_name('^domain')

    def check(self):
        if which('dnsrecon') is None:
            error('The program dnsrecon could not be found. Make sure it is installed. (On Kali, run: sudo apt install dnsrecon)')

    def manual(self, service, plugin_was_run):
        domain_name = '<DOMAIN-NAME>'
        if self.get_global('domain'):
            domain_name = self.get_global('domain')
        service.add_manual_command('Use dnsrecon to bruteforce subdomains of a DNS domain.', [
            'dnsrecon -n {address} -d ' + domain_name + ' -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t brt 2>&1 | tee {scandir}/{protocol}_{port}_dnsrecon_subdomain_bruteforce.txt',
        ])
