include_directories(${Python3_INCLUDE_DIRS})
link_directories(${Python3_LIBRARY_DIRS})
link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

file(GLOB headers *.h)
add_executable(PythiaTester
    PythiaTester.cpp
)

# Copy the file to the @Pythia directory after the fact
add_custom_command(
    TARGET PythiaTester POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:PythiaTester>"
        "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/../@Pythia/"
)

if(CMAKE_CL_64)
    set_target_properties(PythiaTester PROPERTIES OUTPUT_NAME "PythiaTester_x64")
else()
    set_target_properties(PythiaTester PROPERTIES OUTPUT_NAME "PythiaTester")
endif()

#target_link_libraries(PythiaTester ${PYTHON_LIBRARIES})
# add_definitions(-DEXPMODULE)

# target_link_libraries(PythiaTester debug libutil.lib)
# target_link_libraries(PythiaTester optimized libutil.lib)
