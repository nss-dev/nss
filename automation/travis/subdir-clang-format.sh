#!/bin/sh

if test -z $1
then
        echo "usage: $0 <Directory to reformat with clang-format>"
        exit
fi

export ORIG=".orig"
for file in `(find $1 -type f -name "*.c" && find $1 -type f -name "*.h")`;
do
  echo $file
  mv "$file" "$file$ORIG"
  clang-format-3.8 "$file$ORIG" > "$file"
done
