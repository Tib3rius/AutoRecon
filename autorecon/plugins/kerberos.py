from autorecon.plugins import ServiceScan

class NmapKerberos(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = "Nmap Kerberos"
		self.tags = ['default', 'safe', 'kerberos', 'active-directory']

	def configure(self):
		self.match_service_name(['^kerberos', '^kpasswd'])

	async def run(self, service):
		if self.get_global('domain') and self.get_global('username-wordlist'):
			await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,krb5-enum-users" --script-args krb5-enum-users.realm="' + self.get_global('domain') + '",userdb="' + self.get_global('username-wordlist') + '" -oN "{scandir}/{protocol}_{port}_kerberos_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_kerberos_nmap.xml" {address}')
		else:
			await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,krb5-enum-users" -oN "{scandir}/{protocol}_{port}_kerberos_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_kerberos_nmap.xml" {address}')
