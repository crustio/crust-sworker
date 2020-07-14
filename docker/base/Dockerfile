# build base image
FROM ubuntu:16.04

# install build depends
RUN apt-get update
RUN apt-get install -y build-essential git libboost-all-dev openssl libssl-dev curl libelf-dev libleveldb-dev
RUN apt-get install -y expect libcurl3 libssl-dev libcurl4-openssl-dev libprotobuf-dev 
RUN apt-get install -y kmod unzip linux-headers-`uname -r`

ADD resource /crust-tee-base/resource
ADD scripts/*.sh /crust-tee-base/scripts/
RUN /crust-tee-base/scripts/install_deps.sh -u
RUN rm -rf /crust-tee-base
