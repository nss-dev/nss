#!/bin/sh
# This a convenience script to build samples in environments
# were pkg-config cannot be used. That can happen if pkg-config
# isn't available or though avialable the nspr and nss libraries
# aren't install in the sytem. This sript assumes that we are
# building the samples as part of a checkout of the nspr and nss
# sources and that nss has already being built.
#
# Invoke with sh ./makesample.s which_sample which_target objs_name
#
# the first argument if the sample to build, if empty then build all
# the second argument is the target, either all or clean, defalt is all
# the third arguments is the name of the objects directory
# for example: Linux3.17_x86_64_glibc_PTH_64_DBG.OBJ 
export SAMPLES="sample1 sample2 sample3 sample4 sample5 sample6"
export ROOT_DIR=`pwd`/../..
export DIST_DIR=${ROOT_DIR}/dist
export BIN_DIR=${DIST_DIR}/$3/bin
export LIB_DIR=${DIST_DIR}/$3/lib
export NSPR_INC_DIR=${DIST_DIR}/$3/include/nspr
export NSS_INC_DIR=${DIST_DIR}/public/nss
export PATH=${PATH}:${BIN_DIR}
export LD_LIBRARY_PATH=${LIB_DIR}
export DONT_USE_PKG_CONFIG=1
#export TARGET=[ "$2" = "clean" ] && "clean" || "all"
if [ -z "$1" ]; then
  for d in $SAMPLES
    do
      (cd $d; make $2)
    done
else
    (cd $1; export NSPR_INC_DIR=$NSPR_INC_DIR; export NSS_INC_DIR=$NSS_INC_DIR; \
     make $2)
fi

