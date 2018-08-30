@echo off

if exist ".\Debug\files.txt" del ".\Debug\files.txt"

call build_one.cmd objective-c++ RTObject.mm %*
call build_one.cmd objective-c++ RTHelpers.mm %*
call build_one.cmd objective-c++ ObjCHelpers.mm %*
call build_one.cmd objective-c++ InteropBase.mm %*
call build_one.cmd c++ dllmain.cpp %*

call link.cmd
