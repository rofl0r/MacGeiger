#!/bin/sh
# this is a script to create a release tarball.
# it requires the sources of concol in ../concol.
# you need to pass a version as VER env variable.
# e.g. VER=0.0.0 ./create-dist.sh

if [ -z "$VER" ] ; then
	echo set VER!
	exit
fi

set -e

prog=macgeiger
concol=$PWD/../concol
progrepo=$PWD

me=`pwd`
tempdir=/tmp/"$prog"-0000
tempdir_b=$tempdir/"$prog"-"$VER"
rm -rf $tempdir_b
mkdir -p $tempdir_b

this="$PWD"

cd $tempdir_b
git clone "$concol" concol
git clone "$progrepo" $prog
mv $prog/* .
mv dist/Makefile.dist Makefile

sed -i 's@"../concol/@"concol/@g' $prog.c
sed -i 's@../lib/@libulz/@g' Makefile

rm -rf $prog

rm -rf concol/.git
rm -f concol/Makefile

cd $tempdir
tar cjf "$prog"-"$VER".tar.bz2 "$prog"-"$VER"
mv "$prog"-"$VER".tar.bz2 $me/"$prog"-"$VER".tar.bz2
ls -la $me/"$prog"-$VER.tar.bz2
rm -rf "$tempdir"
