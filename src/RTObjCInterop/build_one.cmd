@echo off

rem TODO: This has an almost-exact duplicate in `/src/objc/build_one.cmd`.

set language=%1
set file=%2

rem Get everything after %2
shift
shift
set params=%1
:loop
shift
if [%1]==[] goto afterloop
set params=%params% %1
goto loop
:afterloop

echo.
echo build.cmd: Building %file%...
echo.

if [%language%]==[objective-c++] (set std=-std=c++14) else (set std=)

if [%language%]==[assembler-with-cpp] (
    set obj=o
    set target=i386-apple-macosx10.13.0
) else (
    set obj=obj
    set target=i386-pc-windows-msvc
)

mkdir ".\Debug\" 2>NUL
"..\..\build\bin\clang" -x "%language%" -o ".\Debug\%file%.%obj%" -c -target "%target%" %std% -fblocks -fobjc-runtime=macosx-10.13.0 -g -gcodeview -DOBJC_PORT -DHAVE_STRUCT_TIMESPEC -DNOMINMAX -Wno-microsoft -Wno-extern-initializer -Wno-ignored-attributes -Wno-nullability-completeness -DWINAPI_FAMILY=WINAPI_FAMILY_APP -DOBJCWINRT_EXPORT=__declspec(dllexport) -DDEBUG=1 -ffunction-sections -fdata-sections -d2bigobj -I "..\..\deps\WinObjC\include" -I "..\..\deps\WinObjC\include\Platform\Universal Windows" -I "..\..\deps\WinObjC\Frameworks\include" -I "..\..\deps\WinObjC\include\xplat" -I "..\..\deps\WinObjC\tools\include\WOCStdLib" -I "..\..\deps\WinObjC\tools\include" -I "..\..\deps\WinObjC\tools\Logging\include" -I "..\..\deps\WinObjC\tools\include\xplat" -I "..\..\deps\WinObjC\tools\deps\prebuilt\include" ".\%file%" %params%

if [%language%]==[assembler-with-cpp] objconv -fcoff -v0 ".\Debug\%file%.%obj%"

echo ".\Debug\%file%.obj" >> ".\Debug\files.txt"
