#Pull base image
FROM ubuntu:16.04

#Copy libsnark install script
COPY getlibsnark /usr/local/bin/getlibsnark

# dependencies to run getlibsnark
RUN chmod +x /usr/local/bin/getlibsnark
RUN apt-get update
RUN apt-get install -y vim make git build-essential pkg-config cmake libgmp3-dev \
		libprocps4-dev python-markdown libboost-all-dev libssl-dev

RUN ["/bin/bash", "-c", "/usr/local/bin/getlibsnark"]