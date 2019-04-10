@echo off
dumpbin /exports %1 > exports.txt
echo LIBRARY UCRTBASED > ucrtbased.def
echo EXPORTS >> ucrtbased.def
for /f "skip=19 tokens=4" %%A in (exports.txt) do @echo %%A >> ucrtbased.def
lib /def:ucrtbased.def "/out:%2" /machine:x86
