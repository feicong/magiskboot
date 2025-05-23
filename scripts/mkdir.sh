#!/bin/bash
# mkdir-wrapper to create directories only when required

MKDIR_FLAGS=""
DIRS=""

while [ $# -gt 0 ]; do # last arg(s) are/is DIRECTORY(ies)
    case "$1" in
        --help|--version) ;; # ignored, for production.
        -m) MKDIR_FLAGS="${MKDIR_FLAGS} $1 $2 "; shift ;; # pass args accordingly
        -*|--*) MKDIR_FLAGS="${MKDIR_FLAGS} $1 " ;; # pass args accordingly
        *) [ -d "$1" ] || { DIR=${1#$TOPDIR/}; echo -e "  MKDIR\t    ${DIR}"; DIRS="${DIRS} $1 "; } ;; # this is a dir
    esac
    shift
done

if [ -z "$DIRS" ]; then
    exit 0
fi

eval mkdir ${MKDIR_FLAGS} ${DIRS}

exit $?