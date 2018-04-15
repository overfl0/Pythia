# include_directories(${CMAKE_SOURCE_DIR}/libutil)
# include_directories(${CMAKE_SOURCE_DIR}/../include)
include_directories(${PYTHON_PATH}/include)
link_directories(${PYTHON_PATH}/libs)
link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

file(GLOB headers *.h)
file(GLOB files *.cpp)
file(GLOB doubleconversion third_party/double-conversion/*.cc)
file(GLOB modules Modules/*.cpp)
add_library(Pythia SHARED 
    ${files}
    ${doubleconversion}
    ${modules}
    ${headers}
    Pythia.rc
)

# add_definitions(-DEXPMODULE)

# target_link_libraries(PythiaSetPythonPath debug libutil.lib)
# target_link_libraries(PythiaSetPythonPath optimized libutil.lib)
