echo off

rem ###########################################################################
rem This script will install any python dependencies that will be needed
rem by any *32-bit* Pythia code.
rem
rem To install the dependencies for a plugin, simply drag a requirements.txt
rem file onto install_requirements32.bat
rem ###########################################################################

set requirements_file=%1
IF %1==nopause set requirements_file=%2
IF %requirements_file%.==. GOTO END_MISSING_ARGUMENT

set interpreter=%~dp0\python-{version}-embed-win32

echo ===============================================================================
echo Installing requirements for %interpreter% from %requirements_file%...
echo ===============================================================================

echo.
"%interpreter%\python.exe" -I -m pip install  --upgrade --no-warn-script-location -r %requirements_file%
if ERRORLEVEL 1 GOTO END_PIP_ERROR
echo.


echo ===============================================================================
echo Installation done.
echo ===============================================================================

rem ### Error handling ########################################################
GOTO END_OK

:END_PIP_ERROR
  ECHO.
  ECHO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ECHO An error happened during requirements installation. Your python environment is
  ECHO now in an undefined state!
  ECHO Fix the issues and reinstall the requirements!
  ECHO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  ECHO.
GOTO END_NOT_OK


:END_MISSING_ARGUMENT
  ECHO Missing requirements file!
GOTO END_NOT_OK

rem ### Error handling ########################################################

:END_OK
IF %1==nopause goto END_NOPAUSE
pause

:END_NOPAUSE
EXIT /b

:END_NOT_OK
IF %1==nopause goto END_NOT_OK_NOPAUSE
pause

:END_NOT_OK_NOPAUSE
EXIT /b 1
