#!/bin/bash

if test -z $1
then
        echo "usage: $0 <Directory to diff *.c/h against *.c./h.orig> <diff args>"
        exit
fi

for file in `(find $1 -type f -name "*.c.orig" && find $1 -type f -name "*.h.orig")`;
do
  echo $file
  DIFF=$(diff $2 $file "${file%.*}")
  if [ "$DIFF" != "" ]
  then
    echo "Sorry, $file is not formatted properly. Please use clang-format 3.8 on your patch before landing."
    echo "$DIFF"
    exit 1
  fi
done
