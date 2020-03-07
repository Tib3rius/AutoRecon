# AutoRecon Dockerfile
# 
# https://github.com/Tib3rius/AutoRecon
# 
# Run AutoRecon within a Docker, Podman, or Kata-Containers container.
# 
# Build:
# - git clone https://github.com/Tib3rius/AutoRecon.git
# - cd ./AutoRecon
# - docker build -t AutoRecon .
# 
# Basic Use:
# - sudo docker run -it --rm --name autorecon-container AutoRecon 127.0.0.1
#
# Use with Mounted Volumes to Save Output and Include Wordlists:
# - git clone https://github.com/danielmiessler/SecLists.git ~/Seclists
# - mkdir -p $HOME/recon-out
# - sudo docker run -it --rm -v $HOME/Seclists:/usr/share/seclists \
#       -v $HOME/recon-out:/autorecon/recon-out \
#       --name autorecon-container AutoRecon -ct 2 -cs 2 -vv -o /autorecon/recon-out 192.168.1.100 192.168.1.1/30 localhost

LABEL description="Autorecon Container Image"
LABEL author="Tib3rius"
LABEL author="VltraHeaven"

# Building GoBuster
FROM golang:1.14.0-alpine3.11 as build
RUN apk --no-cache add git
RUN go get github.com/OJ/gobuster; exit 0
WORKDIR /go/src/github.com/OJ/gobuster
RUN go get && go build && go install 

FROM debian:sid-slim

COPY --from=build /go/bin/gobuster /bin/gobuster

# Creating autorecon user/group
RUN echo "Creating the autorecon user & group..." && \
        groupadd autorecon && \
        useradd autorecon -s /bin/sh -g autorecon && \
        mkdir -p /autorecon && \
        chown -R autorecon:autorecon /autorecon

# Installing AutoRecon dependencies from default debian repo
RUN apt-get update \
        apt-get -y full-upgrade && \
        env DEBIAN_FRONTEND=noninteractive apt-get install -y no-install-recommends \
        gpg \
        apt-transport-https \
        python3 \
        python3-toml \
        python3-colorama \
        curl \
        nmap \
        nbtscan \
        onesixtyone \
        smbclient \
        smbmap \
        perl \
        libwhisker2-perl \
        libnet-ssleay-perl \
        wget \
        git

# Adding kali repos and installing additional dependencies
RUN env DEBIAN_FRONTEND=noninteractive \
        apt-key adv --keyserver pool.sks-keyservers.net --recv-keys ED444FF07D8D0BF6 && \
        echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list.d/kali.list && \
        apt-get install -y --no-install-recommends oscanner \
        nikto \
        enum4linux \
        whatweb \
        smtp-user-enum \
        snmpcheck \
        sslscan \
        tnscmd10g && \
        wget https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.5/wkhtmltox_0.12.5-1.buster_amd64.deb && \
        rm -rf /etc/apt/sources.list.d/kali.list && \ # Removing kali repo from apt sources
        apt-get update && \
        apt-get install -y wkhtmltox_0.12.5-1.buster_amd64.deb && \
        rm -rf wkhtmltox_0.12.5-1.buster_amd64.deb 

# Set autorecon as the default container user
USER autorecon

# Set /autorecon as working directory
WORKDIR /autorecon

# Pulling AutoRecon from git repo and installing requiirements using pip
RUN env DEBIAN_FRONTEND=noninteractive git clone https://github.com/Tib3rius/AutoRecon.git . && \
        python3 -m pip install -r requirements.txt

# Set HOME environment variable
ENV HOME /autorecon

#Set container entrypoint
ENTRYPOINT ["/autorecon/autorecon.py"]



# Testing for installing nikto and enum4linux from github repos
#
#RUN env DEBIAN_FRONTEND=noninteractive git clone https://github.com/sullo/nikto.git /opt/nikto && \
    #        chmod +x /opt/nikto/program/nikto.pl && \
    #    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    #    git clone https://github.com/portcullislabs/enum4linux.git /opt/enum4linux && \
    #    chmod +x /opt/enum4linux/enum4linux.pl && \
    #    ln -sf /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux


