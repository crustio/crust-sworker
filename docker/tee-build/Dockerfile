# tee build base image
From "ubuntu:16.04"

ENV CURST_TEE_STAMP 1
RUN apt-get update
RUN apt-get install -y build-essential git libboost-all-dev openssl libssl-dev curl libelf-dev libleveldb-dev
# install build depends
RUN apt-get install -y expect libcurl3 libssl-dev libcurl4-openssl-dev libprotobuf-dev 
RUN apt-get install -y kmod unzip linux-headers-4.15.0-106 linux-headers-4.15.0-106-generic

ADD vendor /opt/vendor
COPY install_deps.sh /opt/files/
RUN /opt/files/install_deps.sh

WORKDIR /opt/crust-tee
