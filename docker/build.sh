#!/usr/bin/env /bin/bash

BUILD_DIR="`pwd`/crust-tee"
CRUST_TEE_VER=`cat VERSION`
DIST_FILE="$BUILD_DIR/crust-tee-$CRUST_TEE_VER.tar"

function echo_c {
 echo -e "\e[1;$1m$2\e[0m"
}

function log_info {
  echo_c 33 "$1"
}

function log_success {
  echo_c 32 "$1"
}

function log_err {
  echo_c 35 "$1"
}

function pre_check {
  log_info "checking dependencies"
  if [ ! -e /dev/isgx ]; then
    log_err "SGX Device doesn't exist! Please make sure you have enabled SGX support and installed SGX driver"
    exit 1
  fi
  log_success "SGX device - passed"
  if [ -e /dev/mei0 ]; then
    log_success "secure device: /dev/mei0 exists - passed"
  elif [ -e /dev/dal0 ]; then
    log_success "secure device: /dev/dal0 exists - passed"
  fi

  if [ -f files.tar ]; then
    log_success "files.tar exists - passed"
  else
    log_err "files.tar doesn't exist! Please download files.tar and put it it under $BUILD_DIR"
  fi
}

function build_crust {
  echo_c 33 "using build dir: $BUILD_DIR"

  if [ -d "$BUILD_DIR" ]; then
    log_success "build directory exists, skip clone code"
  else
    echo_c 33 "will clone https://github.com/crustio/crust-tee.git to $BUILD_DIR"
    git clone https://github.com/crustio/crust-tee.git $BUILD_DIR
  fi

  log_success "prepare docker build image, run docker pull"
  docker pull crustio/tee-build:1.0.0
  if [ $? -ne 0 ]; then
    echo "failed to pull docker image"
    exit 1
  fi

  if [ ! -d "$BUILD_DIR/resource" ]; then
    echo "extract resource directory from files.tar"
    mkdir -p .tmp
    tar -xf files.tar -C .tmp files/resource
    mv .tmp/files/resource $BUILD_DIR
  else
    echo "resource file exists"
  fi

  cp -f onetbb.tar $BUILD_DIR/resource/

  RUN_OPTS="--device /dev/isgx"
  if [ -e /dev/mei0 ]; then
    echo_c 33 "/dev/mei0 exists"
    RUN_OPTS="$RUN_OPTS --device /dev/mei0"
  elif [ -e /dev/dal0 ]; then
    echo_c 33 "/dev/dal0 exists"
    RUN_OPTS="$RUN_OPTS --device /dev/dal0"
  fi

  echo_c 33 "using run opts: $RUN_OPTS"
  docker run -i -t $RUN_OPTS -v $BUILD_DIR:/opt/crust-tee pangwa/tee-build:1.0.0 /bin/bash -c '/opt/crust-tee/scripts/package.sh; echo done building'
  echo_c 33 "build done, validting result"

  if [ ! -f $DIST_FILE ]; then
    echo_c 33 "build failed, $DIST_FILE does not exist"
    exit 1
  else
    log_success "$DIST_FILE exists - passed"
    echo_c 33 "build validation passed"
  fi
}

function build_tee_runner {
  log_info "building tee runner"
  CRUST_RUNTIME_DIR=".tee-runner`date +%s`"
  log_info "building crust runtime image, using temp directory $CRUST_RUNTIME_DIR"
  mkdir -p $CRUST_RUNTIME_DIR
  cp templates/docker-tee-runner $CRUST_RUNTIME_DIR/Dockerfile
  cp templates/start_tee.sh $CRUST_RUNTIME_DIR/start_tee.sh
  cp $DIST_FILE $CRUST_RUNTIME_DIR/crust-tee.tar
  cd $CRUST_RUNTIME_DIR
  docker build . -t tee-runner:$CRUST_TEE_VER
  log_info "build complete, cleanup build dir"
  log_info "you can now run tee container using image: tee-runner:$CRUST_TEE_VER"
  cd -
  rm -rf $CRUST_RUNTIME_DIR
}

log_success "curst tee builder"
pre_check
build_crust
build_tee_runner

