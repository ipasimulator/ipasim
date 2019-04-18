@echo off
dumpbin /exports %1 > exports.txt
echo LIBRARY %4 > %3.def
echo EXPORTS >> %3.def
setlocal EnableDelayedExpansion
for /f "skip=19 tokens=4" %%A in (exports.txt) do (
    echo %%A >> %3.def
    rem If name has an underscore prefix, export it without it, as well.
    set a=%%A
    if "!a:~0,1!"=="_" (
        echo !a:~1! >> %3.def
    )
)
lib /def:%3.def "/out:%2" /machine:x86
