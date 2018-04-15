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

# add_definitions(-DEXPMODULE)

# target_link_libraries(PythiaSetPythonPath debug libutil.lib)
# target_link_libraries(PythiaSetPythonPath optimized libutil.lib)
