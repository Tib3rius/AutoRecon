FROM debian:12.9

RUN apt-get update
RUN apt-get install -y ca-certificates gnupg wget

RUN wget -q -O - https://archive.kali.org/archive-key.asc  | apt-key add -
RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list
RUN apt-get update

RUN apt-get install -y python3 python3-pip git seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nikto nmap onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf
RUN python3 -m pip install git+https://github.com/Tib3rius/AutoRecon.git


CMD ["/bin/bash"]
