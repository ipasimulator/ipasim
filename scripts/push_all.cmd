@echo off

rem This script will push all of "our code". That means this repository,
rem as well as any submodules that we have ported. It will also push GTM data.

call push_one.cmd ..\deps\apple-headers
call push_one.cmd ..\deps\clang
call push_one.cmd ..\deps\libclosure
call push_one.cmd ..\deps\LIEF
call push_one.cmd ..\deps\lld
call push_one.cmd ..\deps\llvm
call push_one.cmd ..\deps\objc4
call push_one.cmd ..\deps\WinObjC
call push_one.cmd ..

pause
