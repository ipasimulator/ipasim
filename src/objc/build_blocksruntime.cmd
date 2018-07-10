@echo off

echo.
echo Building BlocksRuntime...
echo.

clang -target "i386-pc-windows-msvc" -I"..\..\deps\blocksruntime" -c "..\..\deps\blocksruntime\BlocksRuntime\data.c" -o ".\Debug\data.o"
clang -target "i386-pc-windows-msvc" -I"..\..\deps\blocksruntime" -c "..\..\deps\blocksruntime\BlocksRuntime\runtime.c" -o ".\Debug\runtime.o"
"C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\VC\Tools\MSVC\14.14.26428\bin\Hostx86\x86\lib.exe" -nologo -out:".\Debug\blocksruntime.lib" ".\Debug\data.o" ".\Debug\runtime.o"
