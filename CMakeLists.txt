cmake_minimum_required(VERSION 3.6.2)
project(PythiaProject)

message(STATUS "Setting MSVC flags")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++latest")

set(CMAKE_CXX_FLAGS_DEBUG          "/D_DEBUG /MTd /Zi /Ob0 /Od /RTC1 /EHsc")
set(CMAKE_CXX_FLAGS_MINSIZEREL     "/MT /Ox /Oi /Ob1 /EHsc /DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE        "/MT /Ox /Oi /Ob2 /EHsc /DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/MT /Zi /Ox /Oi /Ob2 /EHsc /DNDEBUG")

set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "/debug /INCREMENTAL:NO")

ADD_DEFINITIONS(-DUNICODE)

# Spdlog
ADD_DEFINITIONS(-D_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING)
ADD_DEFINITIONS(-D_SILENCE_CXX17_OLD_ALLOCATOR_MEMBERS_DEPRECATION_WARNING)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

###############################################################################
# Set your Python version here:
###############################################################################
set(PYTHON_VERSION_MAJOR "3")
set(PYTHON_VERSION_MINOR "7")

add_definitions(-DPYTHON_VERSION="${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}")
add_definitions(-DPYTHON_VERSION_DOTTED="${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}")

# These are supported in cmake 3.12 and later so we're using the older add_definitions() instead
#add_compile_definitions(PYTHON_VERSION="${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}")
#add_compile_definitions(PYTHON_VERSION_DOTTED="${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}")

# The python executables and libraries are in the same directories as they are on an AppVeyor machine:
# https://www.appveyor.com/docs/windows-images-software/#python
# Create a symlink if you don't want to move your python installation here, for example:
# mklink /j c:\my_path\Python36-64 c:\Python36-x64
if(CMAKE_CL_64)
    set(PYTHON_PATH "C:\\Python${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}-x64")
else()
    set(PYTHON_PATH "C:\\Python${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}")
endif()

add_subdirectory(src/Pythia)
add_subdirectory(src/PythiaSetPythonPath)
add_subdirectory(src/PythiaTester)
# add_subdirectory(src/UnitTests)

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT PythiaSetPythonPath)


# Dump all cmake variables
# get_cmake_property(_variableNames VARIABLES)
# list (SORT _variableNames)
# foreach (_variableName ${_variableNames})
#     message(STATUS "${_variableName}=${${_variableName}}")
# endforeach()
# execute_process(COMMAND "${CMAKE_COMMAND}" "-E" "environment")
