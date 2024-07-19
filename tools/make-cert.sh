#!/bin/sh

set -e

T="rsa"
C="root@locahost"
N="root"
I="root"
Z="0001"

FILE_NAME="$(date +%s)"

while getopts ":i:t:c:n:z" opt; do
    case $opt in
    i)
        I="$OPTARG"
        ;;
    t)
        T="$OPTARG"
        ;;
    c)
        C="$OPTARG"
        ;;
    n)
        N="$OPTARG"
        ;;
    z)
        Z="$OPTARG"
        ;;
    \?)
        echo "invalid option: -$OPTARG" >&2 && exit 1
        ;;
    :)
        echo "option -$OPTARG requires an argument." >&2 && exit 1
        ;;
    esac
done

shift "$((OPTIND-1))"

ssh-keygen -t "$T" -f ./ca-key -C 'User Certificate Authority for Testing' -N ""

ssh-keygen -t "$T" -f "./$FILE_NAME" -C "$C" -N ""

ssh-keygen -s ./ca-key -I "$I" -z "$Z" -n "$N" "./$FILE_NAME.pub"

cleanup() {
    rm "./ca-key"
    rm "./ca-key.pub"

    rm "./$FILE_NAME"
    rm "./$FILE_NAME.pub"
}

cleanup
