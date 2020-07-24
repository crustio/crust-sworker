# crust sworker env image
FROM ubuntu:16.04

# install build depends
RUN apt-get update
RUN apt-get install -y build-essential git libboost-all-dev openssl libssl-dev curl libelf-dev libleveldb-dev expect libcurl3 libcurl4-openssl-dev libprotobuf-dev kmod unzip linux-headers-`uname -r`
ADD resource /crust-sworker-env/resource
ADD scripts/*.sh /crust-sworker-env/scripts/
ADD VERSION /crust-sworker-env/
RUN /crust-sworker-env/scripts/install_deps.sh -u
