# crust sworker env image
FROM ubuntu:18.04

# install build depends
RUN apt-get clean
RUN apt-get update
RUN apt-get install -y wget expect kmod unzip
RUN apt-get install -y libboost-all-dev libleveldb-dev build-essential
RUN apt-get install -y linux-headers-`uname -r` libssl-dev curl libprotobuf-dev libcurl4-openssl-dev
ADD resource /crust-sworker-env/resource
ADD scripts/*.sh /crust-sworker-env/scripts/
ADD VERSION /crust-sworker-env/
RUN /crust-sworker-env/scripts/install_deps.sh -u -d
