## See [docker-script].

# Run CMake.
mkdir -Force cmake >$null
pushd cmake
# TODO: This is not up-to-date. Something like `cmake -GNinja ..` works.
cmake -GNinja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl `
    -DCMAKE_LINKER=lld-link ..
popd
