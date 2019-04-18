@echo off
dumpbin /exports %1 > exports.txt
echo LIBRARY %4 > %3.def
echo EXPORTS >> %3.def
for /f "skip=19 tokens=4" %%A in (exports.txt) do @echo %%A >> %3.def
lib /def:%3.def "/out:%2" /machine:x86
