@echo off

set in=%1.td
set out=%1.inc
set options=%2

echo.
echo Tablegenning "%in%" with "%TABLEGEN%-tblgen"...

mkdir "..\..\build\include\tapi\%in%\.." 2>NUL
"..\..\deps\llvm\build\Release\bin\%TABLEGEN%-tblgen.exe" -o="..\..\build\include\tapi\%out%" -I="..\..\build\include" %options% "..\..\deps\tapi\include\tapi\%in%"
