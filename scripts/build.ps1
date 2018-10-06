## See [docker-script].

# Run CMake.
mkdir -Force cmake >$null
pushd cmake
cmake -GNinja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl -DCMAKE_LINKER=lld-link -DCMAKE_RC_COMPILER=llvm-rc ..
popd
