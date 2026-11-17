#!/bin/bash
#
# Builds the release zip of the system plugin (zip), or copies the plugin into
# a Joomla! site (to update an existing installation for development):
#
#   plugin/deploy.sh zip                 writes plugin/bfstop-<version>.zip
#   plugin/deploy.sh <joomla directory>  copies the files into that site
#
# The release zips of all extensions and the package are built by
# package/build.sh.
set -e
cd "$(dirname "$0")"

# set to the joomla directory you want to deploy to:
dstdir=

# internal variables to be updated when files are added:
extname=bfstop
sqlfiles="sql"
srcfiles="$extname.xml $sqlfiles updatescript.php index.html src services"
langfiles="language"
# the documentation of the repository, put at the top of the zip
docs="CHANGELOG LICENSE.txt README.md"
plgtype="system"
langs="de-DE en-GB"
version="$(sed -n 's:.*<version>\(.*\)</version>.*:\1:p' "$extname.xml" | head -n 1)"

if [ "$1" == "zip" ]
then
	rm -f $extname-$version.zip
	zip -r $extname-$version.zip $srcfiles $langfiles
	(cd .. && zip "plugin/$extname-$version.zip" $docs)
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
