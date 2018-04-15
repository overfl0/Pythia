# include_directories(${CMAKE_SOURCE_DIR}/libutil)
# include_directories(${CMAKE_SOURCE_DIR}/../include)
include_directories(${PYTHON_PATH}/include)
link_directories(${PYTHON_PATH}/libs)
link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

file(GLOB headers *.h)
add_library(PythiaSetPythonPath SHARED 
    dllmain.cpp
    stdafx.cpp
    ../Pythia/Logger.cpp
    ../Pythia/Paths.cpp
    ${headers}
)

# Copy the file to the @Pythia directory after the fact
add_custom_command(
    TARGET PythiaSetPythonPath POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/PythiaSetPythonPath.dll"
        "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/../@Pythia"
)

# add_definitions(-DEXPMODULE)

# target_link_libraries(PythiaSetPythonPath debug libutil.lib)
# target_link_libraries(PythiaSetPythonPath optimized libutil.lib)
