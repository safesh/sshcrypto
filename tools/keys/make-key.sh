#!/bin/sh

set -e

T="rsa"
C="root@localhost"

FILE_NAME="key"

while getopts ":t:c:f:" opt; do
    case $opt in
    f)
        FILE_NAME="$OPTARG"
        ;;
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
