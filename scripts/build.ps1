## See [docker-script].

# Run CMake. We use LLVM + Clang, no Visual Studio is installed. Hence, we need
# `CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY`, so that CMake doesn't use
# linking when testing C and C++ compiler. And that's good, because the test
# linking requires also resource compiler and other tools we do not have on our
# build platform (because we don't need them).
mkdir -Force cmake >$null
pushd cmake
cmake -GNinja -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl ..
popd
