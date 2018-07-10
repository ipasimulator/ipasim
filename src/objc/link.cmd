@echo off
set LIB=C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\VC\Tools\MSVC\14.14.26428\ATLMFC\lib\x86;C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\VC\Tools\MSVC\14.14.26428\lib\x86;C:\Program Files (x86)\Windows Kits\NETFXSDK\4.6.1\lib\um\x86;C:\Program Files (x86)\Windows Kits\10\lib\10.0.17134.0\ucrt\x86;C:\Program Files (x86)\Windows Kits\10\lib\10.0.17134.0\um\x86;
lld-link -dll @".\Debug\files.txt"
