# crust tee env image
FROM ubuntu:16.04

# install build depends
RUN apt-get update
RUN apt-get install -y build-essential git libboost-all-dev openssl libssl-dev curl libelf-dev libleveldb-dev expect libcurl3 libcurl4-openssl-dev libprotobuf-dev kmod unzip linux-headers-`uname -r`
ADD resource /crust-tee-env/resource
ADD scripts/*.sh /crust-tee-env/scripts/
ADD VERSION /crust-tee-env/
RUN /crust-tee-env/scripts/install_deps.sh -u
