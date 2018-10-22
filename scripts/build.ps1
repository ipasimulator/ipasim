## See [docker-script].

# Run CMake.
mkdir -Force cmake >$null
pushd cmake
# The compilers specified here are actually used just to build LLVM+Clang.
# TODO: Maybe hardcode them into `CMakeLists.txt` then.
cmake -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl `
    -DCMAKE_LINKER=lld-link ..
popd
