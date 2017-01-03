#!/usr/bin/env python3

#######################
#  Frontline Setup Script  #
#######################

import os
import sys
import shutil
import platform
import subprocess
import winreg

######## GLOBALS #########
PROJECTDIR = "@Pythia"
##########################

def main():
    print("""
  ###########################################
  # Frontline Development Environment Setup #
  ###########################################

  This script will create your Frontline dev environment for you.

  This script will create two hard links on your system:
    [Arma 3 Installation folder]   	=> @Pythia
    [Arma 3 Installation folder]   	=> python
  """)
    print("\n")

    try:
        reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        key = winreg.OpenKey(reg,
                r"SOFTWARE\Wow6432Node\bohemia interactive\arma 3")
        armapath = winreg.EnumValue(key,1)[1]
    except:
        print("Failed to determine Arma 3 Path.")
        return 1

    try:
        # Get the normal user name
        regmission = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
        keymission = winreg.OpenKey(regmission,
                r"SOFTWARE\bohemia interactive\arma 3")
        armauser = winreg.EnumValue(keymission,0)[1]
    except:
        print("Failed to determine Arma 3 User.")
        return 2

    scriptpath = os.path.realpath(__file__)
    projectpath = os.path.dirname(os.path.dirname(scriptpath))
    pythonpath = os.path.join(armapath,"python")

    print("# Detected Paths:")
    print("  Arma Path:     {}".format(armapath))
    print("  Repository Path:  {}".format(projectpath))

    repl = input("\nAre these correct? (y/n): ")
    if repl.lower() != "y":
        return 3

    print("\n# Creating links ...")

    try:
        if not os.path.exists(pythonpath):
            os.mkdir(pythonpath)

        if platform.win32_ver()[0] == "7":
            subprocess.call(["cmd", "/c", "mklink", "/D", os.path.join(armapath, PROJECTDIR), os.path.join(projectpath, PROJECTDIR)])
        else:
            subprocess.call(["cmd", "/c", "mklink", "/D", "/J", os.path.join(armapath, PROJECTDIR), os.path.join(projectpath, PROJECTDIR)])
    except:
        raise
        print("Something went wrong during the link creation. Please finish the setup manually.")
        return 6

    print("# Links created successfully.")

    # Install Mikero tools to pack PBO and build PBO
    # repl = input("\nInstall Mikero tools? (y/n): ")
    # if repl.lower() != "y":
    #     return 3
    #
    # execfile("install_mikero_tools.py")
    #
    # repl = input("\nRebuild PBOs? (y/n): ")
    # if repl.lower() != "y":
    #     return 3
    #
    # execfile("make_pbos.py")

    return 0


if __name__ == "__main__":
    exitcode = main()
    if exitcode > 0:
        print("\nSomething went wrong during the setup. Make sure you run this script as administrator.")
    else:
        print("\nSetup successfully completed.")



    input("\nPress enter to exit ...")
    sys.exit(exitcode)
