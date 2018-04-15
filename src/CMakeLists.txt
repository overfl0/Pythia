cmake_minimum_required(VERSION 3.6.2)
project(PythiaProject)

message(STATUS "Setting MSVC flags")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Oi /EHc /std:c++latest")
string(REPLACE "/O2" "/Ox" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")

ADD_DEFINITIONS(-DUNICODE)

# Spdlog
ADD_DEFINITIONS(-D_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING)
ADD_DEFINITIONS(-D_SILENCE_CXX17_OLD_ALLOCATOR_MEMBERS_DEPRECATION_WARNING)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/../bin")

set(PYTHON_PATH "C:\\Python35")

add_subdirectory(Pythia)
add_subdirectory(PythiaSetPythonPath)
add_subdirectory(PythiaTester)
# add_subdirectory(UnitTests)

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT PythiaSetPythonPath)


# Dump all cmake variables
# get_cmake_property(_variableNames VARIABLES)
# list (SORT _variableNames)
# foreach (_variableName ${_variableNames})
#     message(STATUS "${_variableName}=${${_variableName}}")
# endforeach()

# execute_process(COMMAND "${CMAKE_COMMAND}" "-E" "environment")
