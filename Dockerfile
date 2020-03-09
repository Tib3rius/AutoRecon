# AutoRecon Dockerfile
# 
# https://github.com/Tib3rius/AutoRecon
# 
# Run AutoRecon within a Docker, Podman, or Kata-Containers container.
# 
# Build:
# - git clone https://github.com/Tib3rius/AutoRecon.git
# - cd ./AutoRecon
# - docker build -t tib3rus/autorecon .
# 
# Basic Use:
# - sudo docker run -it --rm --name autorecon-container tib3rius/autorecon 127.0.0.1
#
# Use with Mounted Volumes to Save Output and Include Wordlists:
# - git clone https://github.com/danielmiessler/SecLists.git ~/Seclists
# - mkdir -p $HOME/recon-out
# - sudo docker run -it --rm -v $HOME/Seclists:/usr/share/seclists \
#       -v $HOME/recon-out:/autorecon/recon-out \
#       --name autorecon-container tib3rius/autorecon -ct 2 -cs 2 -vv -o /autorecon/recon-out 192.168.1.100 192.168.1.1/30 localhost

# Building GoBuster
FROM golang:1.14.0-buster AS build
LABEL description="gobuster build container"
RUN go get github.com/OJ/gobuster; exit 0 && \
	cd /go/src/github.com/OJ/gobuster && \
	go get && go build && go install

FROM debian:buster
LABEL description="Autorecon Container Image"
LABEL author="Tib3rius"
LABEL author="VltraHeaven"
COPY --from=build /go/bin/gobuster /bin/gobuster

# Creating autorecon user/group
RUN echo "Creating the autorecon user & group..." && \
        groupadd autorecon && \
        useradd autorecon -s /bin/sh -g autorecon && \
        mkdir -p /home/autorecon && \
        chown -R autorecon:autorecon /home/autorecon

# Installing AutoRecon dependencies from default debian repo
RUN apt-get update && \
        apt-get -y full-upgrade && \
        env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        gpg \
        gpg-agent \
        apt-utils \
        python3 \
        python3-pip \
        python3-toml \
        python3-colorama \
        curl \
        onesixtyone \
        perl \
        libwhisker2-perl \
        libnet-ssleay-perl \
        wget \
        git \
        dirmngr

# Adding kali repos and installing additional dependencies
RUN apt-key adv --keyserver pool.sks-keyservers.net --recv-keys ED444FF07D8D0BF6 && \
        echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list.d/kali.list

RUN env DEBIAN_FRONTEND=noninteractive apt-get update && \
        apt-get install -y --no-install-recommends \
        oscanner \
        python3-samba \
        samba-common-bin \
        smbclient \
        smbmap \
        samba \
        nbtscan \
        nmap \
        nikto \
        enum4linux \
        whatweb \
        smtp-user-enum \
        snmpcheck \
        sslscan \
        tnscmd10g && \
        wget https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.5/wkhtmltox_0.12.5-1.buster_amd64.deb -O /opt/wkhtmltox_0.12.5-1.buster_amd64.deb && \
        rm -rf /etc/apt/sources.list.d/kali.list && \
        apt-get update && \
        apt-get install -y --no-install-recommends /opt/wkhtmltox_0.12.5-1.buster_amd64.deb && \
        rm -rf /opt/wkhtmltox_0.12.5-1.buster_amd64.deb && \
	apt-get -y autoremove && \
        apt-get -y autoclean

# Sets autorecon as the default container user
# Comment out USER command to run container in root context for full nmap functionality
## USER autorecon

# Set /home/autorecon as working directory
WORKDIR /home/autorecon

# Pulling AutoRecon from git repo and installing requiirements using pip
RUN env DEBIAN_FRONTEND=noninteractive git clone https://github.com/Tib3rius/AutoRecon.git /home/autorecon && \
        python3 -m pip install -r /home/autorecon/requirements.txt

# Set HOME environment variable
ENV HOME /home/autorecon

#Set container entrypoint
ENTRYPOINT ["/home/autorecon/autorecon.py"]
