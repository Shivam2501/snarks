#Pull base image
FROM ubuntu:16.04

#Copy libsnark install script
COPY getlibsnark /usr/local/bin/getlibsnark

# dependencies to run getlibsnark
RUN chmod +x /usr/local/bin/getlibsnark
RUN apt-get update
RUN apt-get install -y vim
RUN apt-get install -y make
RUN apt-get install -y git
RUN apt-get install -y build-essential
RUN apt-get install -y pkg-config
RUN apt-get install -y cmake
RUN apt-get install -y libgmp3-dev 
RUN apt-get install -y libprocps4-dev 
RUN apt-get install -y python-markdown 
RUN apt-get install -y libboost-all-dev 
RUN apt-get install -y libssl-dev

RUN ["/bin/bash", "-c", "/usr/local/bin/getlibsnark"]