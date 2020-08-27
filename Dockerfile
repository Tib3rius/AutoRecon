#sudo docker build -t tib3rius/autorecon .
#mkdir /root/results
#Usage: sudo docker run -it -v /root/results:/results --rm --name autorecon-container tib3rius/autorecon 127.0.0.1

FROM kalilinux/kali-bleeding-edge:latest
RUN apt-get update
RUN apt-get install sudo git -y
RUN sudo apt install python3 -y
RUN sudo apt install python3-pip -y
RUN python3 -m pip install --user pipx
RUN python3 -m pipx ensurepath
RUN python3 -m pip install git+https://github.com/Tib3rius/AutoRecon.git
RUN sudo apt install seclists curl enum4linux gobuster nbtscan nikto nmap onesixtyone oscanner smbclient smbmap smtp-user-enum snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf -y
RUN echo "Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/kali/.local/bin"" >> /etc/sudoers
RUN apt-get -y autoremove && apt-get -y autoclean
ENTRYPOINT ["autorecon"]
