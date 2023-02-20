# crust sworker image
FROM crustio/crust-sworker-env:1.1.2

ARG BUILD_MODE

ADD scripts /crust-sworker/scripts
ADD src /crust-sworker/src
ADD test /crust-sworker/test
ADD VERSION /crust-sworker/VERSION
ADD Makefile /crust-sworker/Makefile
ADD buildenv.mk /crust-sworker/buildenv.mk
RUN /crust-sworker/scripts/install.sh -d -m ${BUILD_MODE}
ADD docker/runner/start_sworker.sh /
CMD /start_sworker.sh
