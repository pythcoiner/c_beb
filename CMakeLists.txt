cmake_minimum_required(VERSION 3.22)
project(beb_ll C)

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
    src/beb_ll.c
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
    # Fallback: try to find system-installed libsecp256k1
    message(STATUS "secp256k1 submodule not found, trying system installation")
    find_package(PkgConfig QUIET)
    
    if(PkgConfig_FOUND)
        pkg_check_modules(SECP256K1 QUIET libsecp256k1)
    endif()
    
    if(NOT SECP256K1_FOUND)
        find_library(SECP256K1_LIBRARY
            NAMES secp256k1
            PATHS
            /usr/local/lib
            /usr/lib
            /opt/local/lib
        )
        
        find_path(SECP256K1_INCLUDE_DIR
            NAMES secp256k1.h
            PATHS
            /usr/local/include
            /usr/include
            /opt/local/include
        )
        
        if(SECP256K1_LIBRARY AND SECP256K1_INCLUDE_DIR)
            set(SECP256K1_LIBRARIES ${SECP256K1_LIBRARY})
            set(SECP256K1_INCLUDE_DIRS ${SECP256K1_INCLUDE_DIR})
            set(SECP256K1_FOUND TRUE)
            include_directories(${SECP256K1_INCLUDE_DIRS})
        endif()
    else
        include_directories(${SECP256K1_INCLUDE_DIRS})
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
add_library(beb_ll STATIC ${SOURCES})

# Link libraries
target_link_libraries(beb_ll
    ${OPENSSL_LIBRARIES}
    ${SECP256K1_LIBRARIES}
)

# Install targets
install(TARGETS beb_ll
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES include/beb_ll.h
    DESTINATION include
)

# Build tests if enabled
if(BUILD_TESTING)
    # Try to find cJSON for JSON parsing (optional)
    find_package(cJSON QUIET)
    
    # Build test_main.c if it exists
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_main.c")
        add_executable(test_main tests/test_main.c)
        target_link_libraries(test_main beb_ll ${OPENSSL_LIBRARIES} ${SECP256K1_LIBRARIES})
        add_test(NAME beb_ll_unit_tests COMMAND test_main)
        set_tests_properties(beb_ll_unit_tests PROPERTIES
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
        )
    endif()
    
    # Build test_vectors.c if it exists
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_vectors.c")
        add_executable(test_vectors_runner tests/test_vectors.c)
        target_link_libraries(test_vectors_runner beb_ll ${OPENSSL_LIBRARIES} ${SECP256K1_LIBRARIES})
        
        if(cJSON_FOUND)
            target_link_libraries(test_vectors_runner ${CJSON_LIBRARIES})
            target_include_directories(test_vectors_runner PRIVATE ${CJSON_INCLUDE_DIRS})
            target_compile_definitions(test_vectors_runner PRIVATE HAVE_CJSON)
        endif()
        
        add_test(NAME beb_ll_test_vectors COMMAND test_vectors_runner)
        set_tests_properties(beb_ll_test_vectors PROPERTIES
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
        )
    endif()
endif()

# Print configuration summary
message(STATUS "BEB LL Configuration:")
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

