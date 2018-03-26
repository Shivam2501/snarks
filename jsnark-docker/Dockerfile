#Pull base image
FROM ubuntu:16.04

#Copy jsnark install script
COPY getjsnark /usr/local/bin/getjsnark

# dependencies to run libsnark
RUN chmod +x /usr/local/bin/getlibsnark
RUN apt-get update
RUN apt-get install -y vim make git build-essential pkg-config cmake libgmp3-dev \
		libprocps4-dev python-markdown libboost-all-dev libssl-dev

# jdk 8 and junit 4
RUN apt-get install -y software-properties-common python-software-properties
RUN add-apt-repository -y ppa:openjdk-r/ppa
RUN apt-get update
RUN apt-get install -y openjdk-8-jdk junit4

RUN ["/bin/bash", "-c", "/usr/local/bin/getjsnark"]