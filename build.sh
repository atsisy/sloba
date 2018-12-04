#!/bin/bash

cp ./src/slob.c ./linux/mm
cp ./src/slab.h ./linux/mm

if test $# -gt 0;
then
    if test $1 = 'update-config';
    then
        echo 'Copy kernel build configuration'
        cp ./src/.config ./linux
    fi
fi

echo 'Start building kernel'

cd linux && make -j$(grep -c processor /proc/cpuinfo) && cd ..
