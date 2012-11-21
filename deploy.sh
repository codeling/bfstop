#!/bin/bash
extname=bfstop
srcfiles="$extname.php $extname.xml"
plgtype="system"
langs="en-GB de-DE"
dstdir=~/htdocs/hdh

if [ "$1" == "zip" ]
then
    zip $extname.zip *.ini *.php *.xml
	exit
fi

cp $srcfiles $dstdir/plugins/$plgtype/$extname/

for lang in $langs
do
    cp $lang.* $dstdir/administrator/language/$lang/
done



