#!/bin/sh
# This a convenience script to build samples in environments
# were pkg-config cannot be used. That can happen if pkg-config
# isn't available or though avialable the nspr and nss libraries
# aren't install in the sytem. This sript assumes that we are
# building the samples as part of a checkout of the nspr and nss
# sources and that nss has already being built.
#
# Invoke with sh ./makesample.s which_sample which_target
#
# the first argument if the sample to build, if empty then build all
# the second argument is th targer, either all or clean, defalt is all
export SAMPLES="sample1 sample2 sample3 sample4 sample5 sample6"
export ROOT_DIR=`pwd`/../..
export DIST_DIR=$ROOT_DIR/dist
export BIN_DIR=$DIST_DIR/bin
export LIB_DIR=$DIST_DIR/lib
export PATH=$PATH:$BIN_DIR
export LD_LIBRARY_PATH=LIB_DIR
export DONT_USE_PKG_CONFIG=1
export TARGET=[ "$2" -eq "clean" ] && "clean" || "all"
if [ -z "$1" ]; then
  for d in $SAMPLES
    do
      (cd $d; make $TARGET)
    done
else
    (cd $1; gmake $2)
fi

