# Pull base image
FROM ubuntu:16.04

#Copy buffet install script
COPY getpepper /usr/local/bin/getpepper

# dependencies to run libsnark
RUN chmod +x /usr/local/bin/getpepper
RUN apt-get update
RUN apt-get install -y software-properties-common python-software-properties
RUN add-apt-repository -y ppa:openjdk-r/ppa
RUN apt-get update
RUN apt-get install -y python2.7 libpython2.7 libpython2.7-dev openjdk-8-jdk \
        golang build-essential gcc g++ gcc-multilib g++-multilib ant  \
        ant-optional make git cmake vim time libboost-all-dev libgmp10 libgmp-dev   \
        zlib1g zlib1g-dev openmpi-bin openmpi-common libopenmpi-dev   \
        libssl-dev

RUN ["/bin/bash", "-c", "/usr/local/bin/getpepper"]