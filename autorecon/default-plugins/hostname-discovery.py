from autorecon.plugins import ServiceScan
import requests
from urllib.parse import urlparse
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

    async def run(self, service):
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

                    # Add to /etc/hosts if not already present (with tab) and only for valid IP-hostname pair
                    hosts_path = '/etc/hosts'
                    ip = service.target.address

                    # Check if ip is a valid IP address and not equal to the hostname
                    try:
                        ipaddress.ip_address(ip)
                        if redirect_host and redirect_host != ip:
                            entry = f"{ip}\t{redirect_host}"
                            try:
                                # Read existing entries
                                with open(hosts_path, 'r') as f:
                                    hosts_data = f.read()
                                # Check if entry already exists (tab or space, for safety)
                                if entry not in hosts_data and f"{ip} {redirect_host}" not in hosts_data:
                                    with open(hosts_path, 'a') as f:
                                        f.write(f"\n{entry}\n")
                                    service.info(f"[+] Added {redirect_host} to /etc/hosts for {ip}")
                                else:
                                    service.info(f"[+] {redirect_host} already present in /etc/hosts for {ip}")
                        else:
                            service.info(f"[+] Skipped adding /etc/hosts entry for invalid or duplicate IP-hostname pair ({ip}, {redirect_host})")
                    except ValueError:
                        service.info(f"[+] Skipped adding /etc/hosts entry because {ip} is not a valid IP address.")

                else:
                    service.info(f"[+] Redirect detected, but no hostname could be parsed: {location}")
            else:
                service.info(f"[-] No redirect detected at {url}")

        except Exception as e:
            service.error(f"[!] Error during redirect check on {service.target.address}:{service.port} — {e}")
