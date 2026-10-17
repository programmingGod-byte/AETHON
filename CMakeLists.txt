cmake_minimum_required(VERSION 3.20)
project(Aethon CXX)

# Default to Debug build if no build type is explicitly passed
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose build type: Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


# Third-Party Dependencies
include(FetchContent)

set(CLI11_BUILD_TESTS OFF CACHE INTERNAL "")
set(CLI11_BUILD_EXAMPLES OFF CACHE INTERNAL "")
set(CLI11_BUILD_DOCS OFF CACHE INTERNAL "")

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/extern/CLI11/CMakeLists.txt")
    FetchContent_Declare(
        CLI11
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/extern/CLI11
    )
else()
    FetchContent_Declare(
        CLI11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG        v2.4.2
    )
endif()

set(FLUXIO_BUILD_PYTHON OFF CACHE INTERNAL "")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/extern/FluxIO/CMakeLists.txt")
    FetchContent_Declare(
        FluxIO
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/extern/FluxIO
    )
else()
    FetchContent_Declare(
        FluxIO
        GIT_REPOSITORY https://github.com/programmingGod-byte/FluxIO.git
        GIT_TAG        main
    )
endif()
FetchContent_MakeAvailable(CLI11 FluxIO)

# Create app & link FluxIO
add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE FluxIO::fluxio)

# Facebook Folly-Style Root CMake Architecture
add_subdirectory(aethon)
add_subdirectory(benchmarks)
add_subdirectory(src)
