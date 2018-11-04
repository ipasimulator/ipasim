## See [docker-script].

# Run CMake. See #3.
mkdir -Force "C:/build" >$null
pushd "C:/build"
cmake "C:/project"
