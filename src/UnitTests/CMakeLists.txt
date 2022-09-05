include_directories(${Python3_INCLUDE_DIRS})
link_directories(${Python3_LIBRARY_DIRS})
link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
link_directories($ENV{VCInstallDir}Auxiliary/VS/UnitTest/lib/)


file(GLOB files ../Pythia/*.cpp)
file(GLOB doubleconversion ../Pythia/third_party/double-conversion/*.cc)
file(GLOB modules ../Pythia/Modules/*.cpp)

set(UNIT_TEST_TARGET_NAME PythiaUnitTests)
add_library(${UNIT_TEST_TARGET_NAME} SHARED)
target_sources(${UNIT_TEST_TARGET_NAME} PRIVATE
    SQF_Reading.cpp
    SQF_Writing.cpp
    SQF_Fuzzing.cpp

    # Dependencies
    ${files}
    ${doubleconversion}
    ${modules}
)
target_link_libraries(${UNIT_TEST_TARGET_NAME}
    PRIVATE MSUnitTestFramework::MSUnitTestFramework)

find_program(VSTest_EXECUTABLE NAME vstest.console.exe REQUIRED)
list(PREPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/CMakeModules")
find_package(MSUnitTestFramework REQUIRED)

add_test(NAME ${UNIT_TEST_TARGET_NAME}
    COMMAND "${VSTest_EXECUTABLE}" "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/${UNIT_TEST_TARGET_NAME}.dll"
)
