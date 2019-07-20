## See [docker-script].

# Run CMake. See i3.
# TODO: When we use CMake v3.13, rewrite this to
# `cmake -G Ninja -S <source_dir> -B <build_dir>`.
mkdir -Force "C:/ipaSim/build" >$null
pushd "C:/ipaSim/build"
cmake -G Ninja "C:/ipaSim/src"

if ($env:BUILD_TABLEGENS_ONLY -eq "1") {
    # Sample build command to test incremental building. See also i14.
    ninja tblgens-x86-Release
} else {
    # Build everything.
    ninja ipaSim-x86-Debug ipaSim-x86-Release
}
$ExitCode = $LastExitCode

popd
exit $ExitCode
