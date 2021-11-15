#!/bin/bash

#############################################################################
# This script will install any python dependencies that will be needed
# by any Pythia code.
#
# To install the dependencies for a plugin, simply drag a requirements.txt
# file onto install_requirements.sh
#############################################################################

for interpreter in `dirname "$0"`/python-*-embed-linux*
do
    echo ===============================================================================
    echo Installing requirements for $interpreter from "$1"...
    echo ===============================================================================

    "${interpreter}"/bin/python3 -m pip install --no-warn-script-location --upgrade -r "$1"

    if [ $? -ne 0 ]; then
        echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        echo An error happened during requirements installation. Your python environment is
        echo now in an undefined state!
        echo Fix the issues and reinstall the requirements!
        echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        exit 1
    fi
done
