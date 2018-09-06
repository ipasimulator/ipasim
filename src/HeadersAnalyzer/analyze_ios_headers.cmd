@echo off

:: Create a response file for Clang from `analyze_ios_headers.txt`.
type analyze_ios_headers.txt | findstr /V "^# ^$" > .\Debug\args.txt

:: And call Clang.
"..\..\build\bin\clang" @".\Debug\args.txt"
