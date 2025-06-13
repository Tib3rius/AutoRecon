from autorecon.plugins import ServiceScan
from urllib.parse import urlparse
import requests
import urllib3
import os
import ipaddress

urllib3.disable_warnings()

class RedirectHostnameDiscovery(ServiceScan):

    def __init__(self):
        super().__init__()
        self.name = 'Redirect Hostname Discovery'
        self.slug = 'redirect-host-discovery'
        self.tags = ['default', 'http', 'quick']

    def configure(self):
        self.match_service_name('^http')
        self.match_service_name('^nacn_http$', negative_match=True)
        self.add_true_option(
            'update-hosts',
            help='If set, discovered redirect hostnames will be added to /etc/hosts with the target IP'
        )

    async def run(self, service):
        try:
            ipaddress.ip_address(service.target.address)
        except ValueError:
            return 

        try:
            url = f"{'https' if service.secure else 'http'}://{service.target.address}:{service.port}/"
            resp = requests.get(url, verify=False, allow_redirects=False)

            if 'Location' in resp.headers:
                location = resp.headers['Location']
                parsed = urlparse(location)
                redirect_host = parsed.hostname

                if redirect_host:
                    service.info(f"[+] Redirect detected: {url} → {location}")
                    service.info(f"[+] Hostname found in redirect: {redirect_host}")

                    if self.get_option('update-hosts'):
                        if os.geteuid() != 0:
                            service.error("[!] --redirect-host-discovery.update-hosts requires root to modify /etc/hosts.")
                            return

                        ip = service.target.address
                        hostname = redirect_host

                        with open("/etc/hosts", "r") as hosts_file:
                            for line in hosts_file:
                                parts = line.strip().split()
                                if len(parts) >= 2 and parts[0] == ip and hostname in parts[1:]:
                                    return  # entry exists, skip writing

                        with open("/etc/hosts", "a") as hosts_file:
                            hosts_file.write(f"{ip} {hostname}\n")
                        service.info(f"[+] Hostname {hostname} added to /etc/hosts with IP {ip}")
                else:
                    service.info(f"[+] Redirect detected, but no hostname found in: {location}")
            else:
                service.info(f"[-] No redirect detected at {url}")

        except Exception as e:
            service.error(f"[!] Error during redirect check on {service.target.address}:{service.port} — {e}")