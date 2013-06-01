#!/bin/bash
#
# Simple deployment script. Can create a zip file from all
# files or can copy to a Joomla! folder (to update an
# existing installation)
#
# set to the joomla directory you want to deploy to:
dstdir=

# internal variables to be updated when files are added:
extname=bfstop
sqlfiles="sql"
srcfiles="$extname.php helper_log.php helper.db.php helper.notify.php $extname.xml $sqlfiles index.html"
langfiles="language"
docs="CHANGELOG LICENSE.txt README"
plgtype="system"
langs="de-DE en-GB"
version=0.9.10.2

if [ "$1" == "zip" ]
then
	zip -r $extname-$version.zip $srcfiles $docs $langfiles
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

cp -r $srcfiles $dstdir/plugins/$plgtype/$extname/

for lang in $langs
do
	cp language/$lang/* $dstdir/administrator/language/$lang/
done

