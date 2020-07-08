#! /usr/bin/env bash
# crust builder using docker

BUILD_DIR="`pwd`"
VENDOR_DIR="$BUILD_DIR/vendor"
CRUST_TEE_VER=`cat VERSION`
DIST_FILE="$BUILD_DIR/crust-tee.tar"

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
        exit 1
    fi

    if [ -f $VENDOR_DIR/files.tar ]; then
        log_success "$VENDOR_DIR/files.tar exists - passed"
    else
        log_err "files.tar doesn't exist! Please download files.tar and put it it under $VENDOR_DIR"
        exit 1
    fi
}

function build_crust {
  echo_c 33 "using build dir: $BUILD_DIR"

  log_success "prepare docker build image, run docker pull"
  docker pull crustio/tee-build:$CRUST_TEE_VER
  if [ $? -ne 0 ]; then
    echo "failed to pull docker image"
    exit 1
  fi

  if [ ! -d "$BUILD_DIR/resource" ]; then
    echo "extract resource directory from files.tar"
    mkdir -p .tmp
    tar -xf $VENDOR_DIR/files.tar -C .tmp files/resource
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
  docker run -i -t $RUN_OPTS -v $BUILD_DIR:/opt/crust-tee crustio/tee-build:$CRUST_TEE_VER /bin/bash -c '/opt/crust-tee/scripts/package.sh; echo done building'
  echo_c 33 "build done, validting result"

  if [ ! -f $DIST_FILE ]; then
    echo_c 33 "build failed, $DIST_FILE does not exist"
    exit 1
  else
    log_success "$DIST_FILE exists - passed"
    echo_c 33 "build validation passed"
  fi
}

log_success "curst tee builder"
pre_check
build_crust

log_success "done building"
