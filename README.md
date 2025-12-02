# BEB LL C Implementation

This is a C reimplementation of the low-level (ll) module from the Bitcoin Encrypted Backup Rust implementation. It is designed to be integrated into Bitcoin Core.

## Build System

This project uses **CMake** as the build system.

## Dependencies

- **OpenSSL** (1.1+): For AES-GCM-256 encryption/decryption
- **libsecp256k1**: For secp256k1 public key operations (included as git submodule)
- **C99 compiler**: GCC or Clang
- **CMake** (3.22+): Build system (required for libsecp256k1 submodule)

## Building

### Basic Build

First, initialize and update git submodules (from the project root):

```bash
git submodule update --init --recursive
```

Or if cloning the repository for the first time:

```bash
git clone --recursive <repository-url>
```

Then build:

```bash
cd c
mkdir build
cd build
cmake ..
cmake --build .
```

**Note**: The libsecp256k1 submodule is required. If the submodule is not initialized, CMake will fall back to trying to find a system-installed libsecp256k1, but this is not recommended for Bitcoin Core integration.

This will create:
- `libbeb_ll.a` - Static library
- `test_main` - Unit test executable (if BUILD_TESTING is ON)
- `test_vectors_runner` - Test vectors executable (if BUILD_TESTING is ON)

### Debug Build

```bash
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
```

### Release Build

```bash
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

### Disable Tests

```bash
cd build
cmake -DBUILD_TESTING=OFF ..
cmake --build .
```

### Clean

```bash
cd build
cmake --build . --target clean
# Or remove the entire build directory
rm -rf build
```

### Install

```bash
cd build
cmake ..
cmake --build .
sudo cmake --install .
```

## Usage

Include the header file:

```c
#include "beb_ll.h"
```

Link against the library:

```bash
# After building with CMake
gcc your_program.c -L./build -lbeb_ll -lssl -lcrypto -lsecp256k1 -I./include
```

Or use CMake's find_package in your CMakeLists.txt:

```cmake
find_package(beb_ll REQUIRED)
target_link_libraries(your_target beb_ll)
```

## API Overview

The API closely mirrors the Rust implementation in `src/ll.rs`. Key functions include:

- **Encryption**: `beb_ll_encrypt_aes_gcm_256_v1_with_nonce()`
- **Decryption**: `beb_ll_decrypt_aes_gcm_256_v1()`
- **Parsing**: `beb_ll_decode_v1()`, `beb_ll_parse_*()` functions
- **Encoding**: `beb_ll_encode_*()` functions

## Bitcoin Core Integration

This implementation is designed for eventual integration into Bitcoin Core:

- Uses Bitcoin Core's libsecp256k1 for public key operations
- SHA256 implementation can be swapped with Bitcoin Core's `crypto/sha256.h`
- OpenSSL is only used for AES-GCM (Bitcoin Core doesn't provide this)
- Follows Bitcoin Core coding style patterns

## Testing

Basic unit tests are included in `tests/test_main.c` and test vectors in `tests/test_vectors.c`. To run:

```bash
cd build
cmake --build .
ctest
# Or run test executables directly
./test_main              # Unit tests
./test_vectors_runner    # Test vectors from BIP
```

For full test vector validation, a JSON parser library (e.g., cJSON) would be needed to load the test vectors from `../test_vectors/`. CMake will automatically detect cJSON if installed.

## Memory Management

All functions that allocate memory return pointers that must be freed by the caller using the corresponding `*_free()` functions:

- `beb_ll_content_free()`
- `beb_ll_derivation_paths_free()`
- `beb_ll_secrets_free()`
- `beb_ll_decode_v1_result_free()`
- `beb_ll_decrypt_result_free()`

## Error Handling

All functions return `beb_ll_error_t` error codes. Use `beb_ll_error_string()` to get a human-readable error message.

## License

Same as the main project.

