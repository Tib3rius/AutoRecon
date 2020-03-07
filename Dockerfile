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
# - sudo docker run -it --rm --name AutoRecon AutoRecon 127.0.0.1
#
# Use with Mounted Volumes to Save Output and Include Wordlists:
# - git clone https://github.com/danielmiessler/SecLists.git ~/Seclists
# - mkdir -p $HOME/recon-out
# - sudo docker run -it --rm -v $HOME/Seclists:/usr/share/seclists \
#       -v $HOME/recon-out:/AutoRecon/recon-out \
#       --name AutoRecon -ct 2 -cs 2 -vv -o /AutoRecon/recon-out 192.168.1.100 192.168.1.1/30 localhost

LABEL description="Autorecon Container Image"
LABEL author="Tib3rius"
LABEL author="VltraHeaven"

FROM golang:1.14.0-alpine3.11 as build
RUN apk --no-cache add git
RUN go get github.com/OJ/gobuster; exit 0
WORKDIR /go/src/github.com/OJ/gobuster
RUN go get && go build && go install 

FROM debian:sid-slim
COPY --from=build /go/bin/gobuster /bin/gobuster
RUN apt-get update \
        apt-get -y full-upgrade && \
        env DEBIAN_FRONTEND=noninteractive apt-get install -y no-install-recommends \
        python3 \
        python3-toml \
        python3-colorama \
        curl \
        nmap \




