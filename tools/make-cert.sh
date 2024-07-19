#!/bin/sh

set -e

T="rsa"
C="root@locahost"
N="root"
I="root"
Z="0001"
O=""

FILE_NAME="cert"

while getopts ":i:t:c:n:z:o:" opt; do
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
    o)

        echo "$OPTARG"
        O="-O $OPTARG"

        echo "$O"
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

ssh-keygen -s ./ca-key -I "$I" -z "$Z" -O force-command='ls -la' -O source-address='198.51.100.0/24,203.0.113.0/26' -n "$N" "./$FILE_NAME.pub"

cleanup() {
    rm "./ca-key"
    rm "./ca-key.pub"

    rm "./$FILE_NAME"
    rm "./$FILE_NAME.pub"
}

cleanup
