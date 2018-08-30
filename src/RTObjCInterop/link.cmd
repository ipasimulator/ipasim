@echo off

echo.
echo build.cmd: Linking...
echo.

"..\..\build\bin\lld-link.exe" -nologo -dll -def:".\export.def" -out:".\Debug\RTObjCInterop.dll" -debug "libcmt.lib" @".\Debug\files.txt" "..\..\Debug\dyld_initializer.obj" "..\objc\Debug\libobjc.A.lib" "..\..\deps\WinObjC\tools\Win32\Debug\Logging\Logging.lib" "..\..\deps\WinObjC\build\Win32\Debug\Universal Windows\Foundation.lib"  "..\..\deps\WinObjC\build\Win32\Debug\Universal Windows\CoreFoundation.lib" "RuntimeObject.lib" "..\..\Debug\dyld.lib" %*
