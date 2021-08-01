from autorecon import ServiceScan

class NmapFTP(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = 'Nmap FTP'
        self.tags = ['default', 'ftp']

    def configure(self):
        self.add_service_match(['^ftp', '^ftp\-data'])

    async def run(self, service):
        await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_ftp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_ftp_nmap.xml" {address}')

class BruteforceFTP(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Bruteforce FTP"
        self.tags = ['default', 'ftp']

    def configure(self):
        self.add_service_match(['^ftp', '^ftp\-data'])

    def manual(self):
        self.add_manual_commands('Bruteforce logins:', [
            'hydra -L "' + self.get_global('username_wordlist') + '" -P "' + self.get_global('password_wordlist') + '" -e nsr -s {port} -o "{scandir}/{protocol}_{port}_ftp_hydra.txt" ftp://{address}',
            'medusa -U "' + self.get_global('username_wordlist') + '" -P "' + self.get_global('password_wordlist') + '" -e ns -n {port} -O "{scandir}/{protocol}_{port}_ftp_medusa.txt" -M ftp -h {address}'
        ])
