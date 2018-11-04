## See #3.

if (Test-Path C:/build) { rm -r C:/build }
cp -r -Container C:/project/cmake C:/build
