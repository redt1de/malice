#!/bin/bash

BASE_ADDR=0x1000

function usage(){
    echo "Usage: $0 <a|d> [options]"
    echo "  a: assemble"
    echo "  d: disassemble"
    exit 1
}

function usagea(){
    echo "Usage: $0 a <asm code> [basea addr]"
    echo "      asm code: semicolon separated asm code: syscall;ret"
    exit 1
}

function usaged(){
    echo "Usage: $0 d <hex code> [basea addr]"
    echo "      hex code: commas,spaces, '0x' and '\x' are ignored"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

#cstool x64 "0xcc" 0x1000

# assemble
if [ "$1" == "a" ]; then
    if [ $# -lt 2 ]; then
        usagea
    fi
    ASMCODE=$(echo "$2" | sed -e 's/;/\n/g')
    echo "$ASMCODE" > /tmp/tmp.s

    nasm -g -f win64 /tmp/tmp.s -o /tmp/tmp.o && objdump -d /tmp/tmp.o |grep -vE '\.text|^$|tmp/tmp' > /tmp/tmp.d
    a=$(cat /tmp/tmp.d| sed 's/:\t/>/g'|cut -d'>' -f2|awk -F'\t' '{print $1}'| sed 's/  */ /g')
    read -a arr <<< "${a//[$'\n ']/ }"
    b=$(for i in "${arr[@]}";do echo -n "0x$i, "; done)
    echo "[]byte{$(echo $b|sed 's/,$//g')} // $2"
    # cat /tmp/tmp.d| sed 's/:\t/>/g'|cut -d'>' -f2|sed 's/\t/\/\/ /g' # commented
fi

# disassemble
if [ "$1" == "d" ]; then
    if [ $# -lt 2 ]; then
        usaged
    fi
    HEXDAT=$(echo "$2" | sed -e 's/0x//g' -e 's/\\x//g' -e 's/,//g' -e 's/ //g')
    cstool x64 "$HEXDAT" $BASE_ADDR
fi
