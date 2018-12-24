## See #3.

if (Test-Path C:/ipaSim/build) { rm -r C:/ipaSim/build }
cp -r -Container C:/ipaSim/src/cmake C:/ipaSim/build
