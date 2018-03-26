# Pull base image
FROM ubuntu:16.04

# Copy libsnark install script
COPY getlibsnark /usr/local/bin/getlibsnark

# Dependencies to run getlibsnark
RUN chmod +x /usr/local/bin/getlibsnark
RUN apt-get update
RUN apt-get install -y vim make git build-essential pkg-config cmake libgmp3-dev \
		libprocps4-dev python-markdown libboost-all-dev libssl-dev

RUN ["/bin/bash", "-c", "/usr/local/bin/getlibsnark"]

# Install opam
RUN apt-get install -y wget unzip m4
RUN wget https://raw.github.com/ocaml/opam/master/shell/opam_installer.sh -O - | sh -s /usr/local/bin
RUN /usr/local/bin/opam init -y --comp 4.05.0

# Setup Snarky
COPY getsnarky /usr/local/bin/getsnarky
RUN chmod +x /usr/local/bin/getsnarky
RUN ["/bin/bash", "-c", "/usr/local/bin/getsnarky"]