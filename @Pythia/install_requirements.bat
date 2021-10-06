echo off

rem ###########################################################################
rem This script will install any python dependencies that will be needed
rem by any Pythia code.
rem
rem To install the dependencies for a plugin, simply drag a requirements.txt
rem file onto install_requirements.bat
rem ###########################################################################

set requirements_file=%1
IF %requirements_file%.==. GOTO END_MISSING_ARGUMENT

FOR /D %%G IN ("%~dp0\python-*-embed-amd64" "%~dp0\python-*-embed-win32") DO (
    echo ===============================================================================
    echo Installing requirements for %%G from %requirements_file%...
    echo ===============================================================================

    echo.
    "%%G\python.exe" -m pip install --upgrade --no-warn-script-location -r "%requirements_file%"
    if ERRORLEVEL 1 GOTO END_PIP_ERROR
    echo.
)

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
GOTO END_OK

:END_MISSING_ARGUMENT
  ECHO Missing requirements file!
GOTO END_OK

rem ### Error handling ########################################################

:END_OK
pause
