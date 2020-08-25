# crust sworker image
FROM crustio/crust-sworker-env:0.5.0

RUN apt-get install -y jq

ADD scripts /crust-sworker/scripts
ADD src /crust-sworker/src
ADD test /crust-sworker/test
ADD VERSION /crust-sworker/VERSION
ADD Makefile /crust-sworker/Makefile
ADD buildenv.mk /crust-sworker/buildenv.mk
ADD docker/runner/start_sworker.sh /
ADD docker/runner/upgrade.sh /

RUN /crust-sworker/scripts/install.sh -d
CMD /start_sworker.sh
