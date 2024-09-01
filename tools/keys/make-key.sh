#!/bin/sh

set -e

T="rsa"
C="root@locahost"

FILE_NAME="key"

while getopts ":t:c:" opt; do
    case $opt in
    t)
        T="$OPTARG"
        ;;
    c)
        C="$OPTARG"
        ;;
    \?)
        echo "invalid option: -$OPTARG" >&2 && exit 1
        ;;
    :)
        echo "option -$OPTARG requires an argument." >&2 && exit 1
        ;;
    esac
done

ssh-keygen -t "$T" -C "$C" -f "$T-$FILE_NAME"
