# crust tee runner image
FROM crustio/crust-tee-base:0.4.0

ADD scripts /crust-tee/scripts
ADD src /crust-tee/src
ADD test /crust-tee/test
ADD VERSION /crust-tee/VERSION
ADD Makefile /crust-tee/Makefile
ADD buildenv.mk /crust-tee/buildenv.mk
ADD docker/runner/start_tee.sh /

RUN /crust-tee/scripts/install.sh -n
CMD /start_tee.sh
