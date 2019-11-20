#!/bin/bash

ls -f1 $( \
	( \
		grep '^#include' * | \
		grep -v '<' | \
		grep -v MBEDTLS_ | \
		sed 's/:#include//;s/"//g' | \
		grep -v _alt.h; \
		ls *.h | \
		awk '{print $1 " " $1}' \
	) | \
	tsort | \
	tac | \
	egrep -v '^(compat-1.3.h|certs.h|config.h|check_config.h)$' \
)
