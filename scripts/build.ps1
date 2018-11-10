## See [docker-script].

# Run CMake. See #3.
# TODO: When we use CMake v3.13, rewrite this to
# `cmake -G Ninja -S <source_dir> -B <build_dir>`.
pushd "C:/build"
cmake -G Ninja "C:/project"
