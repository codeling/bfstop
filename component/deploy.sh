#!/bin/bash
name=bfstop
# released together with the plugin, with the same version: see
# tests/lint/check-versions.php and package/build.sh of codeling/bfstop
version="$(sed -n 's:.*<version>\(.*\)</version>.*:\1:p' "$(dirname "$0")/${name}.xml" | head -n 1)"

component_name=com_${name}
site_files=site/*
admin_files=admin/*
zipfile_name=${component_name}-${version}.zip
src_files="${name}.xml ${site_files} ${admin_files} installscript.php"

if [ "$1" == "zip" ]
then
	rm -f ${zipfile_name}
	zip -r ${zipfile_name} ${src_files}
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

cp -r ${site_files} ${dstdir}/components/${component_name}/
cp -r ${admin_files} ${dstdir}/administrator/components/${component_name}/
