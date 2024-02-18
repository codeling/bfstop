#!/bin/bash
name=bfstop
version=1.5.2

component_name=com_${name}
site_files=site/*
admin_files=admin/*
admlang_files=admlang/*
zipfile_name=${component_name}-${version}.zip
src_files="${name}.xml ${site_files} ${admin_files} ${admlang_files} installscript.php"

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
cp -r ${admlang_files} ${dstdir}/administrator/language/
