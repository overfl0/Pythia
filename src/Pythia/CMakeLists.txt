include_directories(${Python3_INCLUDE_DIRS})
link_directories(${Python3_LIBRARY_DIRS})
link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

include(${PROJECT_SOURCE_DIR}/CMakeModules/EmbedResource.cmake)
embed_resource("python/Adapter.py" "python_generated/py_adapter.h" "PY_ADAPTER")

file(GLOB headers *.h)
file(GLOB files *.cpp)
file(GLOB doubleconversion third_party/double-conversion/*.cc)
file(GLOB modules Modules/*.cpp)
file(GLOB python_generated python_generated/*.h)

add_library(Pythia SHARED
    ${files}
    ${doubleconversion}
    ${modules}
    ${headers}
    ${python_generated}
)

if(CMAKE_COMPILER_IS_GNUCXX)
    target_link_libraries(Pythia ${Python3_LIBRARIES} stdc++fs dl)
else() # MSVC
    if(CMAKE_BUILD_TYPE STREQUAL RelWithDebInfo OR CMAKE_BUILD_TYPE STREQUAL Release)
        set_target_properties(Pythia PROPERTIES COMPILE_FLAGS "/GL")
        set_target_properties(Pythia PROPERTIES LINK_FLAGS "/LTCG")
    endif()
endif()

# Copy the file to the @Pythia directory after the fact
add_custom_command(
    TARGET Pythia POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:Pythia>"
        "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/../@Pythia/"
)

if(USE_64BIT_BUILD)
    set_target_properties(Pythia PROPERTIES
        OUTPUT_NAME "Pythia_x64"
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "\$ORIGIN/python-${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}-embed-linux64/lib"
    )
else()
    set_target_properties(Pythia PROPERTIES
        OUTPUT_NAME "Pythia"
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "\$ORIGIN/python-${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}-embed-linux32/lib"
    )
endif()

# PYTHON_CONFIGURE_OPTS="--enable-shared" time pyenv install --force 3.7.9
