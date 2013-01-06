#!/bin/bash
# set to the joomla directory you want to deploy to:
dstdir=

# internal variables to be updated when files are added:
extname=bfstop
sqlfiles="sql"
srcfiles="$extname.php $extname.xml $sqlfiles index.html"
docs="README LICENSE.txt"
plgtype="system"
langs="en-GB de-DE"
langfilefilter="*.ini"
version=0.9.6

if [ "$1" == "zip" ]
then
    zip -r $extname-$version.zip $sqlfiles $srcfiles $docs $langfilefilter
	exit
fi

if [ "$1" != "" ]
then
	dstdir=$1
fi

if [ "$dstdir" == "" ]
then
	echo "You have to set dstdir variable first (to the joomla directory you want to deploy to)"
	exit
fi

cp $srcfiles $dstdir/plugins/$plgtype/$extname/

for lang in $langs
do
    cp $lang.* $dstdir/administrator/language/$lang/
done

