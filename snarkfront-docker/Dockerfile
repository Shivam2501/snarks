# Pull base image
FROM ubuntu:16.04

# Copy snarklib install script
COPY getsnarkfront /usr/local/bin/getsnarkfront

RUN chmod +x /usr/local/bin/getsnarkfront
RUN apt-get update
RUN apt-get install -y git libgmp10 libgmp-dev make g++

RUN ["/bin/bash", "-c", "/usr/local/bin/getsnarkfront"]
