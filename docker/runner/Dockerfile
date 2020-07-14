# crust tee runner image
FROM crustio/crust-tee-base:0.4.0

ADD scripts /crust-tee/scripts
ADD src /crust-tee/src
ADD test /crust-tee/test
ADD VERSION /crust-tee/VERSION
ADD Makefile /crust-tee/Makefile
ADD buildenv.mk /crust-tee/buildenv.mk

RUN /crust-tee/scripts/install.sh -n
ENTRYPOINT /opt/crust/crust-tee/$(cat VERSION | head -n 1)/bin/crust-tee $0 $@
