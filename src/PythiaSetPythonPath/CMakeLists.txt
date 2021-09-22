link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

file(GLOB headers *.h)
add_library(PythiaSetPythonPath SHARED
    dllmain.cpp
    ../Pythia/Logger.cpp
    ../Pythia/Paths.cpp
    ${headers}
)

if(CMAKE_COMPILER_IS_GNUCXX)

endif()

# Copy the file to the @Pythia directory after the fact
add_custom_command(
    TARGET PythiaSetPythonPath POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:PythiaSetPythonPath>"
        "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/../@Pythia/"
)

if(USE_64BIT_BUILD)
    set_target_properties(PythiaSetPythonPath PROPERTIES OUTPUT_NAME "PythiaSetPythonPath_x64")
else()
    set_target_properties(PythiaSetPythonPath PROPERTIES OUTPUT_NAME "PythiaSetPythonPath")
endif()
