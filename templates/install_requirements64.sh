#!/bin/bash

#############################################################################
# This script will install any python dependencies that will be needed
# by any *64-bit* Pythia code.
#
# To install the dependencies for a plugin, simply drag a requirements.txt
# file onto install_requirements64.sh
#############################################################################

interpreter=`dirname "$0"`/python-{version}-embed-linux64

echo ===============================================================================
echo Installing requirements for $interpreter from "$1"...
echo ===============================================================================

"${interpreter}"/bin/python3 -I -m pip install  --upgrade --no-warn-script-location -r "$1"

if [ $? -ne 0 ]; then
    echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    echo An error happened during requirements installation. Your python environment is
    echo now in an undefined state!
    echo Fix the issues and reinstall the requirements!
    echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    exit 1
fi
