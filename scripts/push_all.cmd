@echo off

rem This script will push all of "our code". That means this repository,
rem as well as any submodules that we have ported. It will also push GTM data.

call push_one.cmd ..\deps\apple-headers
call push_one.cmd ..\deps\clang
call push_one.cmd ..\deps\libclosure
call push_one.cmd ..\deps\libdispatch
call push_one.cmd ..\deps\Libffi
call push_one.cmd ..\deps\LIEF
call push_one.cmd ..\deps\lld
call push_one.cmd ..\deps\lldb
call push_one.cmd ..\deps\llvm
call push_one.cmd ..\deps\objc4
call push_one.cmd ..\deps\tapi
call push_one.cmd ..\deps\unicorn
call push_one.cmd ..\deps\WinObjC
call push_one.cmd ..\deps\WinObjC\deps\3rdparty\openssl
call push_one.cmd ..\deps\WinObjC\deps\3rdparty\zlib
call push_one.cmd ..\deps\WinObjC\deps\3rdparty\libobjc2
call push_one.cmd ..\deps\WinObjC\tools\vsimporter\third-party\PlistCpp
call push_one.cmd ..\deps\WinObjC\tools\vsimporter\third-party\sole
call push_one.cmd ..\deps\WinObjC\tools\vsimporter\third-party\PlistCpp\third-party\pugixml
call push_one.cmd ..\deps\WinObjC\tools\vsimporter\third-party\PlistCpp\third-party\unittest-cpp
call push_one.cmd ..\deps\WinObjC\tools\vsimporter\third-party\PlistCpp\third-party\NSPlist
call push_one.cmd ..\deps\WinObjC\tools\vsimporter\third-party\PlistCpp\third-party\unittest-cpp\docs
call push_one.cmd ..

echo.
pause
