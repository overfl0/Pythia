cmake_minimum_required(VERSION 3.14.7)

###############################################################################
# Set your Python version here:
###############################################################################
set(PYTHON_VERSION "3.7.9")

string(REPLACE "." ";" PYTHON_VERSION_LIST ${PYTHON_VERSION})
list(GET PYTHON_VERSION_LIST 0 PYTHON_VERSION_MAJOR)
list(GET PYTHON_VERSION_LIST 1 PYTHON_VERSION_MINOR)
list(GET PYTHON_VERSION_LIST 2 PYTHON_VERSION_PATCH)

option(USE_64BIT_BUILD "USE_64BIT_BUILD" ON)


project(PythiaProject)

message(STATUS "Cmake version: ${CMAKE_VERSION}")
message(STATUS "Compiler: ${CMAKE_C_COMPILER} version ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Compiling for Python ${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}")

if(CMAKE_COMPILER_IS_GNUCXX)
    if (CMAKE_COMPILER_IS_GNUCXX AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
        message(FATAL_ERROR "Require at least gcc-9.0")
    endif()

    if(USE_64BIT_BUILD)
        message(STATUS "Setting GCC flags (64bit)")
        set(CMAKE_LIBRARY_ARCHITECTURE x86_64-linux-gnu)
        set(CMAKE_CXX_FLAGS "-O3 -s -fPIC -pthread")
        set(CMAKE_PREFIX_PATH "@Pythia/python-${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}-embed-linux64")
    else()
        message(STATUS "Setting GCC flags (32bit)")
        set(CMAKE_LIBRARY_ARCHITECTURE i386-linux-gnu)
        set(CMAKE_CXX_FLAGS "-O3 -s -fPIC -pthread -march=i686 -m32")
        set(CMAKE_PREFIX_PATH "@Pythia/python-${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}-embed-linux32")
    endif()

else() # MSVC
    if(CMAKE_SIZEOF_VOID_P LESS 8)
        set(USE_64BIT_BUILD OFF)
        message(STATUS "Setting MSVC flags (32bit)")
        set(CMAKE_PREFIX_PATH "@Pythia/python-${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}-embed-win32")
    else()
        message(STATUS "Setting MSVC flags (64bit)")
        set(CMAKE_PREFIX_PATH "@Pythia/python-${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}-embed-amd64")
    endif()

    message(STATUS "Setting MSVC flags")

    set(CMAKE_CXX_FLAGS_DEBUG          "/D_DEBUG /MTd /Zi /Ob0 /Od /RTC1 /EHsc")
    set(CMAKE_CXX_FLAGS_MINSIZEREL     "/MT /Ox /Oi /Ob1 /EHsc /DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE        "/MT /Ox /Oi /Ob2 /EHsc /DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/MT /Zi /Ox /Oi /Ob2 /EHsc /DNDEBUG")

    set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "/debug /INCREMENTAL:NO")
endif()

message(STATUS "Cmake prefix path: ${CMAKE_PREFIX_PATH}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

ADD_DEFINITIONS(-DUNICODE)

# Spdlog
ADD_DEFINITIONS(-D_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING)
ADD_DEFINITIONS(-D_SILENCE_CXX17_OLD_ALLOCATOR_MEMBERS_DEPRECATION_WARNING)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

add_compile_definitions(PYTHON_VERSION="${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}")
add_compile_definitions(PYTHON_VERSION_DOTTED="${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}")
add_compile_definitions(PYTHON_VERSION_MINOR=${PYTHON_VERSION_MINOR})

execute_process(
  COMMAND git rev-parse --short HEAD
  #RESULT_VARIABLE SHORT_HASH_RESULT
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_REV
  OUTPUT_STRIP_TRAILING_WHITESPACE)

message(STATUS "Configuring Pythia ${GIT_REV}")
add_compile_definitions(GIT_REV="${GIT_REV}")

find_package (Python3 "${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}" EXACT REQUIRED COMPONENTS Development)
message(STATUS "Python include_directories: ${Python3_INCLUDE_DIRS}")
message(STATUS "Python link_directories: ${Python3_LIBRARY_DIRS}")

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
