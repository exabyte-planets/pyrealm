cmake_minimum_required(VERSION 3.25)
project(pyrealm_native LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)

set(REALM_ENABLE_SYNC OFF CACHE BOOL "" FORCE)
set(REALM_APP_SERVICES OFF CACHE BOOL "" FORCE)
set(REALM_ENABLE_GEOSPATIAL OFF CACHE BOOL "" FORCE)
set(REALM_BUILD_LIB_ONLY ON CACHE BOOL "" FORCE)
set(REALM_NO_TESTS ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    realm_core
    URL
        https://github.com/realm/realm-core/archive/dcb6fac8642ab92b86a9459e4bb10a2878b6f6a1.tar.gz
    URL_HASH
        SHA256=c2d2d23576ea27c1c9286d75640c8bcc30cc761c789fa9c35960f29c98af475b
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(realm_core)

# Realm Core 13's cli_args.cpp relies on a transitive <cstdlib> include that
# newer Clang releases no longer provide.
if(NOT MSVC)
    target_compile_options(Storage PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:-include;cstdlib>")
endif()

set(PYBIND11_FINDPYTHON ON)
find_package(Python COMPONENTS Interpreter Development.Module REQUIRED)
find_package(pybind11 CONFIG REQUIRED)

pybind11_add_module(_native MODULE native/module.cpp)
target_link_libraries(_native PRIVATE RealmFFIStatic)
target_include_directories(_native PRIVATE ${realm_core_BINARY_DIR}/src)

if(MSVC)
    target_compile_options(_native PRIVATE /W4)
else()
    target_compile_options(_native PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS _native DESTINATION pyrealm_forensics)

add_executable(pyrealm_fixture_generator EXCLUDE_FROM_ALL native/create_fixture.cpp)
target_link_libraries(pyrealm_fixture_generator PRIVATE RealmFFIStatic)
