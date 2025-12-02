cmake_minimum_required(VERSION 3.22)
project(bnb C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build options
option(BUILD_TESTING "Build test executables" ON)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Source files
set(SOURCES
    src/utils.c
    src/crypto.c
    src/content.c
    src/encoding.c
    src/parsing.c
    src/beb.c
)

# Find required libraries
find_package(OpenSSL REQUIRED)

# Include directories for dependencies
include_directories(${OPENSSL_INCLUDE_DIR})

# Build libsecp256k1 from submodule
# Check if submodule exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/CMakeLists.txt")
    message(STATUS "Building libsecp256k1 from submodule")
    
    # Set libsecp256k1 as not top-level to avoid installation conflicts
    set(libsecp256k1_IS_TOP_LEVEL OFF CACHE BOOL "" FORCE)
    set(SECP256K1_INSTALL OFF CACHE BOOL "" FORCE)
    
    # Disable modules we don't need (optional, for faster builds)
    # We only need basic ECDSA/pubkey operations
    set(SECP256K1_ENABLE_MODULE_RECOVERY OFF CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_EXTRAKEYS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_SCHNORRSIG OFF CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_ECDH OFF CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_MUSIG OFF CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF CACHE BOOL "" FORCE)
    
    add_subdirectory(secp256k1)
    set(SECP256K1_LIBRARIES secp256k1)
    set(SECP256K1_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/include")
    include_directories(${SECP256K1_INCLUDE_DIRS})
else()
    message(STATUS "secp256k1 submodule not found, trying system installation")
    find_package(PkgConfig QUIET)
    
    if(PkgConfig_FOUND)
        pkg_check_modules(SECP256K1 QUIET libsecp256k1)
    endif()
    
    if(NOT SECP256K1_FOUND)
        message(FATAL_ERROR "libsecp256k1 not found. Please initialize git submodules: git submodule update --init --recursive")
    endif()
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# Debug flags
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")

# Create static library
add_library(beb STATIC ${SOURCES})

# Link libraries
target_link_libraries(beb
    ${OPENSSL_LIBRARIES}
    ${SECP256K1_LIBRARIES}
)

# Install targets
install(TARGETS beb
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES include/beb.h
    DESTINATION include
)

# Build tests if enabled
if(BUILD_TESTING)
    # Try to find cJSON for JSON parsing (required when testing is enabled)
    # First try a CMake package, then fall back to pkg-config on distros like Arch.
    find_package(cJSON QUIET)
    if(NOT cJSON_FOUND)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(CJSON QUIET cjson)
        endif()
    endif()

    # Normalise detection into a single flag
    set(HAVE_CJSON_LIB OFF)
    if(cJSON_FOUND OR CJSON_FOUND)
        set(HAVE_CJSON_LIB ON)
    endif()

    if(NOT HAVE_CJSON_LIB)
        message(FATAL_ERROR "cJSON not found but BUILD_TESTING is ON. Please install cJSON (e.g. 'sudo apt-get install libcjson-dev' or 'sudo pacman -S cjson') or disable tests with -DBUILD_TESTING=OFF.")
    endif()

    # Unit tests
    add_executable(test_main tests/test_main.c)
    target_link_libraries(test_main beb ${OPENSSL_LIBRARIES} ${SECP256K1_LIBRARIES})
    add_test(NAME beb_unit_tests COMMAND test_main)
    set_tests_properties(beb_unit_tests PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
    )
    
    # Test vectors runner
    add_executable(test_vectors_runner tests/test_vectors.c)
    target_link_libraries(test_vectors_runner beb ${OPENSSL_LIBRARIES} ${SECP256K1_LIBRARIES})

    # Link against cJSON and define HAVE_CJSON now that we know it's available
    target_link_libraries(test_vectors_runner ${CJSON_LIBRARIES})
    target_include_directories(test_vectors_runner PRIVATE ${CJSON_INCLUDE_DIRS})
    target_compile_definitions(test_vectors_runner PRIVATE HAVE_CJSON)
    
    add_test(NAME beb_test_vectors COMMAND test_vectors_runner)
    set_tests_properties(beb_test_vectors PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
    )
endif()

# Print configuration summary
message(STATUS "BEB Configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  OpenSSL: ${OPENSSL_VERSION}")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/CMakeLists.txt")
    message(STATUS "  libsecp256k1: building from submodule")
elseif(SECP256K1_VERSION)
    message(STATUS "  libsecp256k1: ${SECP256K1_VERSION} (system)")
else()
    message(STATUS "  libsecp256k1: found (system)")
endif()
message(STATUS "  Build tests: ${BUILD_TESTING}")

