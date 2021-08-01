from autorecon import ServiceScan

class NmapSNMP(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "Nmap SNMP"
        self.tags = ['default', 'snmp']

    def configure(self):
        self.add_service_match('^snmp')

    async def run(self, service):
        await service.execute('nmap {nmap_extra} -sV -p {port} --script="banner,(snmp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_snmp-nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_snmp_nmap.xml" {address}')

class OneSixtyOne(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "OneSixtyOne"
        self.tags = ['default', 'snmp']

    def configure(self):
        self.add_service_match('^snmp')
        self.add_port_match('udp', 161)
        self.run_once(True)
        self.add_option('community-strings', default='/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt', help='The file containing a list of community strings to try. Default: %(default)s')

    async def run(self, service):
        await service.execute('onesixtyone -c ' + service.get_option('community-strings') + ' -dd {address} 2>&1', outfile='{protocol}_{port}_snmp_onesixtyone.txt')

class SNMPWalk(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = "SNMPWalk"
        self.tags = ['default', 'snmp']

    def configure(self):
        self.add_service_match('^snmp')
        self.add_port_match('udp', 161)
        self.run_once(True)

    async def run(self, service):
        await service.execute('snmpwalk -c public -v 1 {address} 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk.txt')
        await service.execute('snmpwalk -c public -v 1 {address} 1.3.6.1.2.1.25.1.6.0 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_system_processes.txt')
        await service.execute('snmpwalk -c public -v 1 {address} 1.3.6.1.2.1.25.4.2.1.2 2>&1', outfile='{scandir}/{protocol}_{port}_snmp_snmpwalk_running_processes.txt')
        await service.execute('snmpwalk -c public -v 1 {address} 1.3.6.1.2.1.25.4.2.1.4 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_process_paths.txt')
        await service.execute('snmpwalk -c public -v 1 {address} 1.3.6.1.2.1.25.2.3.1.4 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_storage_units.txt')
        await service.execute('snmpwalk -c public -v 1 {address} 1.3.6.1.2.1.25.2.3.1.4 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_software_names.txt')
        await service.execute('snmpwalk -c public -v 1 {address} 1.3.6.1.4.1.77.1.2.25 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_user_accounts.txt')
        await service.execute('snmpwalk -c public -v 1 {address} 1.3.6.1.2.1.6.13.1.3 2>&1', outfile='{protocol}_{port}_snmp_snmpwalk_tcp_ports.txt')
