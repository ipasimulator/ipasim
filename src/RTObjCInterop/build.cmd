@echo off

if exist ".\Debug\files.txt" del ".\Debug\files.txt"

call build_one.cmd objective-c++ RTObject.mm %*
