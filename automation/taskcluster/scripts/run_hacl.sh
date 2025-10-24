#!/usr/bin/env bash

if [[ $(id -u) -eq 0 ]]; then
    # Drop privileges by re-running this script.
    # Note: this mangles arguments, better to avoid running scripts as root.
    exec su worker -c "$0 $*"
fi

set -e -x -v

export HACL_STAR=~/hacl-star
export KARAMEL=~/karamel
export LIBCRUX=~/libcrux

# HACL*
git clone -q "https://github.com/hacl-star/hacl-star" ${HACL_STAR}
git -C ${HACL_STAR} checkout -q 0f136f28935822579c244f287e1d2a1908a7e552

# Format the C snapshot.
cd ${HACL_STAR}/dist/mozilla
cp ${VCS_PATH}/nss/.clang-format .
find . -type f -name '*.[ch]' -exec clang-format -i {} \+
cd ${HACL_STAR}/dist/karamel
cp ${VCS_PATH}/nss/.clang-format .
find . -type f -name '*.[ch]' -exec clang-format -i {} \+
cd ${HACL_STAR}/dist/gcc-compatible
cp ${VCS_PATH}/nss/.clang-format .
find . -type f -name '*.[ch]' -exec clang-format -i {} \+

cd ${HACL_STAR}
patches=(${VCS_PATH}/nss/automation/taskcluster/scripts/patches/*.patch)
for f in "${patches[@]}"; do
    git apply "$f"
done

# Libcrux

git clone -q "https://github.com/cryspen/libcrux" ${LIBCRUX}
git -C ${LIBCRUX} checkout -q 5a1d172a1bcff83bb401bfa718d08a2dc8c77e4e

cd ${LIBCRUX}
cp ${VCS_PATH}/nss/.clang-format .
find libcrux-ml-kem/extracts/c/generated -type f -name '*.[ch]' -exec clang-format -i {} \+

# Karamel
git clone -q "https://github.com/FStarLang/karamel" ${KARAMEL}
git -C ${KARAMEL} checkout -q 80f5435f2fc505973c469a4afcc8d875cddd0d8b

cd ${KARAMEL}
cp ${VCS_PATH}/nss/.clang-format .
find include krmllib -type f -name '*.[ch]' -exec clang-format -i {} \+

# These diff commands will return 1 if there are differences and stop the script.

# We have two checks in the script. 
# The first one only checks the files in the verified/internal folder; the second one does for all the rest
# It was implemented like this due to not uniqueness of the names in the verified folders
# For instance, the files Hacl_Chacha20.h are present in both directories, but the content differs.

# TODO(Bug 1899443): remove these exceptions
files=($(find ${VCS_PATH}/nss/lib/freebl/verified/internal -type f -name '*.[ch]'))
for f in "${files[@]}"; do
    file_name=$(basename "$f")
    hacl_file=($(find ${HACL_STAR}/dist/mozilla/internal/ ${LIBCRUX}/libcrux-ml-kem/extracts/c/generated/internal -type f -name $file_name))
    if [ $file_name == "Hacl_Ed25519.h" \
        -o $file_name == "Hacl_Ed25519_PrecompTable.h" ]
    then
        continue
    fi
    diff -u $hacl_file $f
done

files=($(find ${VCS_PATH}/nss/lib/freebl/verified/ -type f -name '*.[ch]' -not -path "*/freebl/verified/internal/*" -not -path "*/freebl/verified/config.h" -not -path "*/freebl/verified/libcrux*"))
for f in "${files[@]}"; do
    file_name=$(basename "$f")
    hacl_file=($(find ${HACL_STAR}/dist/mozilla/ ${KARAMEL}/include/ ${KARAMEL}/krmllib/dist/  ${LIBCRUX}/libcrux-ml-kem/extracts/c/generated/ -type f -name $file_name -not -path "*/hacl-star/dist/mozilla/internal/*"  -not -path "*/libcrux-ml-kem/extracts/c/generated/internal/*"))
    if [ $file_name == "Hacl_P384.c"  \
        -o $file_name == "Hacl_P384.h" \
        -o $file_name == "Hacl_P521.c" \
        -o $file_name == "Hacl_P521.h" \
        -o $file_name == "eurydice_glue.h" \
        -o $file_name == "target.h" ]
    then
        continue
    fi

    if [ $file_name == "Hacl_Ed25519.h"  \
        -o $file_name == "Hacl_Ed25519.c" ]
    then
        continue
    fi
    diff -u $hacl_file $f
done

# Here we process the code that's not located in /hacl-star/dist/mozilla/ but
# /hacl-star/dist/gcc-compatible. 

files=($(find ${VCS_PATH}/nss/lib/freebl/verified/internal -type f -name '*.[ch]'))
for f in "${files[@]}"; do
    file_name=$(basename "$f")
    hacl_file=($(find ${HACL_STAR}/dist/gcc-compatible/internal/ -type f -name $file_name))
    if [ $file_name != "Hacl_Ed25519.h" \
        -a $file_name != "Hacl_Ed25519_PrecompTable.h" ]
    then
        continue
    fi  
    diff -u $hacl_file $f
done

files=($(find ${VCS_PATH}/nss/lib/freebl/verified/ -type f -name '*.[ch]' -not -path "*/freebl/verified/internal/*"))
for f in "${files[@]}"; do
    file_name=$(basename "$f")
    hacl_file=($(find ${HACL_STAR}/dist/gcc-compatible/ -type f -name $file_name -not -path "*/hacl-star/dist/gcc-compatible/internal/*"))
    if [ $file_name != "Hacl_Ed25519.h" \
        -a $file_name != "Hacl_Ed25519.c" ]
    then
        continue
    fi  
    diff -u $hacl_file $f
done
