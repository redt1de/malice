#!/bin/bash

PTH="/usr/local/go/src/*"

for line in `find $PTH|grep -E '\.s$'`; do
	results=$(cat $line|grep "${1}")
	if [ ! -z "$results" ]; then
		echo ""
		echo $line;
		echo "${results}";
	fi

done
