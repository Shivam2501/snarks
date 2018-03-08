#Pull base image
FROM ubuntu:16.04

#Copy jsnark install script
COPY getjsnark /usr/local/bin/getjsnark

# dependencies to run libsnark
RUN chmod +x /usr/local/bin/getjsnark
RUN apt-get update
RUN apt-get install -y vim
RUN apt-get install -y make
RUN apt-get install -y git
RUN apt-get install -y build-essential
RUN apt-get install -y pkg-config
RUN apt-get install -y cmake
RUN apt-get install -y libgmp3-dev 
RUN apt-get install -y libprocps4-dev 
RUN apt-get install -y libgtest-dev
RUN apt-get install -y python-markdown 
RUN apt-get install -y libboost-all-dev 
RUN apt-get install -y libssl-dev

# jdk 8 and junit 4
RUN apt-get install -y software-properties-common 
RUN apt-get install -y python-software-properties
RUN add-apt-repository -y ppa:openjdk-r/ppa
RUN apt-get update
RUN apt-get install -y openjdk-8-jdk
RUN apt-get install -y junit4

RUN ["/bin/bash", "-c", "/usr/local/bin/getjsnark"]