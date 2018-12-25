## See [docker-script].

# Run CMake. See #3.
# TODO: When we use CMake v3.13, rewrite this to
# `cmake -G Ninja -S <source_dir> -B <build_dir>`.
mkdir -Force "C:/ipaSim/build" >$null
pushd "C:/ipaSim/build"
cmake -G Ninja "C:/ipaSim/src"

# Build everything.
ninja ipaSim-x86-Debug
