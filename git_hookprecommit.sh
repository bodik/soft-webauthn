#!/bin/sh
# git helper; do not allow root authored commits

if [ "${GIT_AUTHOR_NAME}" = "root" ]; then
	echo "ERROR: not allowed to commit as root"
	exit 1
fi
