@echo off

echo.
echo build.cmd: Linking...
echo.

"..\..\build\bin\lld-link.exe" -nologo -dll -force:multiple -ignore:4042 -ignore:4049,4217 -def:".\libobjc.def" -out:".\Debug\libobjc.A.dll" -debug "libcmt.lib" "..\..\Debug\pthread\pthread.lib" "..\..\Debug\dyld.lib" @".\Debug\files.txt" %*
