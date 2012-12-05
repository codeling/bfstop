#!/bin/bash
extname=bfstop
sqlfiles="install.mysql.utf8.sql uninstall.mysql.utf8.sql"
srcfiles="$extname.php $extname.xml $sqlfiles"
plgtype="system"
langs="en-GB de-DE"
dstdir=~/htdocs/hdh

if [ "$1" == "zip" ]
then
    zip $extname.zip *.ini *.php *.xml *.sql
	exit
fi

cp $srcfiles $dstdir/plugins/$plgtype/$extname/

for lang in $langs
do
    cp $lang.* $dstdir/administrator/language/$lang/
done



