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
