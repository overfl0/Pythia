###############################################################################
# Set your Python version here:
###############################################################################
set(PYTHON_VERSION_MAJOR "3")
set(PYTHON_VERSION_MINOR "7")

cmake_minimum_required(VERSION 3.14.7)
project(PythiaProject)

message(STATUS "Cmake version: ${CMAKE_VERSION}")
message(STATUS "Compiler: ${CMAKE_C_COMPILER}")


if(CMAKE_COMPILER_IS_GNUCXX)
    if (CMAKE_COMPILER_IS_GNUCC AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
        message(FATAL_ERROR "Require at least gcc-8.0")
    endif()

    message(STATUS "Setting GCC flags")
    #SET(CMAKE_CXX_FLAGS "-std=c++17 -march=i686 -m32 -O2 -s -fPIC -fpermissive")
    SET(CMAKE_CXX_FLAGS "-std=c++17 -O2 -s -fPIC -pthread")
    set(CMAKE_LIBRARY_ARCHITECTURE x86_64)
    #set(CMAKE_LIBRARY_ARCHITECTURE i386-linux-gnu)

else() # MSVC

    message(STATUS "Setting MSVC flags")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++latest")

    set(CMAKE_CXX_FLAGS_DEBUG          "/D_DEBUG /MTd /Zi /Ob0 /Od /RTC1 /EHsc")
    set(CMAKE_CXX_FLAGS_MINSIZEREL     "/MT /Ox /Oi /Ob1 /EHsc /DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE        "/MT /Ox /Oi /Ob2 /EHsc /DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/MT /Zi /Ox /Oi /Ob2 /EHsc /DNDEBUG")

    set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "/debug /INCREMENTAL:NO")
endif()

ADD_DEFINITIONS(-DUNICODE)

# Spdlog
ADD_DEFINITIONS(-D_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING)
ADD_DEFINITIONS(-D_SILENCE_CXX17_OLD_ALLOCATOR_MEMBERS_DEPRECATION_WARNING)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

add_compile_definitions(PYTHON_VERSION="${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}")
add_compile_definitions(PYTHON_VERSION_DOTTED="${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}")

find_package (Python3 "${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}" EXACT REQUIRED COMPONENTS Development)
set(PYTHON_PATH "${Python3_RUNTIME_LIBRARY_DIRS}")

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
