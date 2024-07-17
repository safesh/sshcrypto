#!/bin/sh

# TODO: Config

set -e
ssh-keygen -t dsa -f ./ca-key -C 'User Certificate Authority for Testing' -N ""

name=$(date +%s)
ssh-keygen -t dsa -f "./$name" -C 'root@locahost' -N ""
echo "./$name.pub"

ssh-keygen -s ./ca-key -I 'abc' -z '0002' -n root "./$name.pub"

rm "./ca-key"
rm "./ca-key.pub"

rm "./$name"
rm "./$name.pub"
