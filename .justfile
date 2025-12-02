build:
    mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF .. && cmake --build .

build_debug:
    mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON .. && cmake --build .

test:
    just build_debug
    chmod +x ./build/test_main
    ./build/test_main
    chmod +x ./build/test_vectors_runner
    ./build/test_vectors_runner

clean:
    rm -fRd build
