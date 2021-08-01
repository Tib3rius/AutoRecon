from autorecon import ServiceScan

class NmapKerberos(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Nmap Kerberos"
        self.tags = ['default', 'kerberos', 'active-directory']

    def configure(self):
        self.add_service_match(['^kerberos', '^kpasswd'])

    async def run(self, service):
        await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,krb5-enum-users" -oN "{scandir}/{protocol}_{port}_kerberos_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_kerberos_nmap.xml" {address}')
