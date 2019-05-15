## See [docker-script].

# Run CMake. See #3.
mkdir -Force "C:/ipaSim/build" >$null
pushd "C:/ipaSim/build"
cmake -G Ninja "C:/ipaSim/src"

if ($env:BUILD_TABLEGENS_ONLY -eq "1") {
    # Sample build command to test incremental building. See also #14.
    ninja tblgens-x86-Release
} else {
    # Build everything.
    ninja ipaSim-x86-Debug ipaSim-x86-Release
}
exit $LASTEXITCODE
