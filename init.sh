#!/bin/bash

path='linux'
linux_repo='https://github.com/torvalds/linux.git'

if [ ! -e $path ];
then
    git clone $linux_repo
else
    echo 'Linux git repository is already exist.'
fi

echo 'Initializing is done.'
