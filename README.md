# BEB C Implementation

This is a C implementation of Bitcoin Encrypted Backup BIP.

## Build System

This project uses **CMake** as the build system.

## Dependencies

- **OpenSSL** (1.1+): For AES-GCM-256 encryption/decryption
- **libsecp256k1**: For secp256k1 public key operations (included as git submodule)
- **C99 compiler**: GCC or Clang
- **CMake** (3.22+): Build system (required for libsecp256k1 submodule)
- **cJSON**: For JSON test vectors (required when `BUILD_TESTING=ON`)

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
mkdir build
cd build
cmake ..
cmake --build .
```

**Note**: The libsecp256k1 submodule is required.

This will create:
- `libbeb_ll.a` - Static library
- `test_main` - Unit test executable (if BUILD_TESTING is ON)
- `test_vectors_runner` - Test vectors executable (if BUILD_TESTING is ON)

If `BUILD_TESTING` is enabled (the default), `cJSON` must be available or CMake
configuration will fail.

### Installing cJSON

#### Debian / Ubuntu

On Debian/Ubuntu and derivatives:

```bash
sudo apt-get update
sudo apt-get install libcjson-dev
```

This installs the development headers and library so that `find_package(cJSON)`
in CMake can locate it.

#### Arch Linux

On Arch Linux and derivatives:

```bash
sudo pacman -S cjson
```

This provides the `cJSON` library and headers. After installing, re-run CMake:

```bash
cd build
cmake ..
cmake --build .
```


## Usage

Include the header file:

```c
#include "beb_ll.h"
```

Use CMake's find_package in your CMakeLists.txt:

```cmake
find_package(beb_ll REQUIRED)
target_link_libraries(your_target beb_ll)
```

## API Overview

The API closely mirrors the Rust implementation in `src/ll.rs`. Key functions include:

- **Encryption**: `beb_ll_encrypt_aes_gcm_256_v1_with_nonce()`
- **Decryption**: Low-level helpers such as `beb_ll_try_decrypt_aes_gcm_256()`, combined with the parsing functions.
- **Parsing**: `beb_ll_decode_v1()`, `beb_ll_parse_*()` functions
- **Encoding**: `beb_ll_encode_*()` functions

## Testing

Basic unit tests are included in `tests/test_main.c` and test vectors in `tests/test_vectors.c`. To run:

```bash
just test
```
