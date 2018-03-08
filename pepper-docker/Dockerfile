#Pull base image
FROM ubuntu:16.04

#Copy jsnark install script
COPY getpepper /usr/local/bin/getpepper

# dependencies to run pepper
RUN chmod +x /usr/local/bin/getpepper
RUN apt-get update
RUN apt-get install -y software-properties-common 
RUN apt-get install -y python-software-properties
RUN add-apt-repository -y ppa:openjdk-r/ppa
RUN apt-get update
RUN apt-get install -y python2.7 libpython2.7 libpython2.7-dev openjdk-7-jdk \
        golang build-essential gcc g++ gcc-multilib g++-multilib ant  \
        ant-optional make git cmake vim time libboost-all-dev libgmp10 libgmp-dev   \
        zlib1g zlib1g-dev openmpi-bin openmpi-common libopenmpi-dev   \
        libssl-dev
RUN update-java-alternatives --set java-1.7.0-openjdk-amd64

RUN ["/bin/bash", "-c", "/usr/local/bin/getpepper"]