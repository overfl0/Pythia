include_directories(${Python3_INCLUDE_DIRS})
link_directories(${Python3_LIBRARY_DIRS})
link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

file(GLOB headers *.h)
add_executable(PythiaTester
    PythiaTester.cpp
    ${headers}
)

# Copy the file to the @Pythia directory after the fact
add_custom_command(
    TARGET PythiaTester POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:PythiaTester>"
        "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/../@Pythia/"
)

if(USE_64BIT_BUILD)
    set_target_properties(PythiaTester PROPERTIES
        OUTPUT_NAME "PythiaTester_x64"
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "\$ORIGIN"
    )
else()
    set_target_properties(PythiaTester PROPERTIES
        OUTPUT_NAME "PythiaTester"
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "\$ORIGIN"
    )
endif()


if(CMAKE_COMPILER_IS_GNUCXX)
    target_link_libraries(PythiaTester dl)
else() # MSVC

endif()
