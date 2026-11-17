cmake_minimum_required(VERSION 3.16)
project(breachcheck_psi LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -DNDEBUG")

include(FetchContent)
include(ExternalProject)
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Microsoft SEAL 4.1.2 (BFV). Built from source; optional compression
# libraries are disabled so that the only network dependency is GitHub.
# ---------------------------------------------------------------------------
set(SEAL_USE_ZLIB OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZSTD OFF CACHE BOOL "" FORCE)
set(SEAL_USE_MSGSL OFF CACHE BOOL "" FORCE)
set(SEAL_USE_INTEL_HEXL OFF CACHE BOOL "" FORCE)
set(SEAL_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SEAL_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SEAL_BUILD_BENCH OFF CACHE BOOL "" FORCE)
FetchContent_Declare(seal
  GIT_REPOSITORY https://github.com/microsoft/SEAL.git
  GIT_TAG        v4.1.2
  GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(seal)

# ---------------------------------------------------------------------------
# libsodium (ristretto255, Ed25519, SHA-512). Uses a system copy if one with
# headers exists, otherwise builds release 1.0.22 from GitHub. It is linked
# as a shared library: SEAL's static archive also defines an internal
# `blake2b` symbol, which libsodium.so does not export.
# ---------------------------------------------------------------------------
find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY NAMES sodium)
if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY AND NOT BCPSI_BUILD_SODIUM)
  message(STATUS "Using system libsodium: ${SODIUM_LIBRARY}")
  add_library(sodium_dep INTERFACE)
  target_include_directories(sodium_dep INTERFACE ${SODIUM_INCLUDE_DIR})
  target_link_libraries(sodium_dep INTERFACE ${SODIUM_LIBRARY})
else()
  message(STATUS "Building libsodium from source")
  set(SODIUM_PREFIX ${CMAKE_BINARY_DIR}/sodium)
  ExternalProject_Add(libsodium_ext
    GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
    GIT_TAG        1.0.22-RELEASE
    GIT_SHALLOW    TRUE
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=${SODIUM_PREFIX}
                      --enable-shared --disable-static --quiet
    BUILD_COMMAND     make -j4 --quiet
    INSTALL_COMMAND   make install --quiet
    BUILD_BYPRODUCTS  ${SODIUM_PREFIX}/lib/libsodium.so)
  file(MAKE_DIRECTORY ${SODIUM_PREFIX}/include)
  add_library(sodium_dep INTERFACE)
  add_dependencies(sodium_dep libsodium_ext)
  target_include_directories(sodium_dep INTERFACE ${SODIUM_PREFIX}/include)
  target_link_libraries(sodium_dep INTERFACE ${SODIUM_PREFIX}/lib/libsodium.so)
  set(CMAKE_BUILD_RPATH ${SODIUM_PREFIX}/lib)
endif()

# ---------------------------------------------------------------------------
# Project library and executables
# ---------------------------------------------------------------------------
add_library(bcpsi STATIC
  src/params.cpp
  src/oprf.cpp
  src/hashing.cpp
  src/zt.cpp
  src/manifest.cpp
  src/server.cpp
  src/client.cpp
  src/baseline.cpp
  src/dataset.cpp
  src/protocol.cpp)
target_include_directories(bcpsi PUBLIC src)
target_link_libraries(bcpsi PUBLIC SEAL::seal sodium_dep Threads::Threads)

add_executable(bcpsi_demo  src/main_demo.cpp)
add_executable(bcpsi_tests tests/test_main.cpp)
add_executable(bcpsi_bench bench/bench_main.cpp)
foreach(t bcpsi_demo bcpsi_tests bcpsi_bench)
  target_link_libraries(${t} PRIVATE bcpsi)
endforeach()
