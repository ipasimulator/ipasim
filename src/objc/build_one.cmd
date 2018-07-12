@echo off

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

mkdir ".\Debug\%file%\..\" 2>NUL
clang -x "%language%" -fmessage-length=0 -fdiagnostics-show-note-include-stack -fmacro-backtrace-limit=0 -stdlib=libc++ -Wno-trigraphs -fno-exceptions -fno-sanitize=vptr -fpascal-strings -O0 -Wno-missing-field-initializers -Wno-missing-prototypes -Wno-implicit-atomic-properties -Wno-arc-repeated-use-of-weak -Wno-non-virtual-dtor -Wno-overloaded-virtual -Wno-exit-time-destructors -Wno-missing-braces -Wparentheses -Wswitch -Wno-unused-function -Wno-unused-label -Wno-unused-parameter -Wunused-variable -Wunused-value -Wno-empty-body -Wno-uninitialized -Wno-unknown-pragmas -Wshadow -Wno-four-char-constants -Wno-conversion -Wno-constant-conversion -Wno-int-conversion -Wno-bool-conversion -Wno-enum-conversion -Wno-float-conversion -Wno-non-literal-null-conversion -Wno-objc-literal-conversion -Wshorten-64-to-32 -Wnewline-eof -Wno-selector -Wno-strict-selector-match -Wno-undeclared-selector -Wno-deprecated-implementations -Wno-c++11-extensions -DOS_OBJECT_USE_OBJC=0 -DLIBC_NO_LIBCRASHREPORTERCLIENT -fstrict-aliasing -Wprotocol -Wno-deprecated-declarations -Wno-invalid-offsetof -mmacosx-version-min=10.13 -g -fvisibility=hidden -fvisibility-inlines-hidden -Wno-sign-conversion -Wno-infinite-recursion -Wno-move -Wno-comma -Wno-block-capture-autoreleasing -Wno-strict-prototypes -Wno-range-loop-analysis -Wall -Wextra -Wstrict-aliasing=2 -Wstrict-overflow=4 -Wno-unused-parameter -Wno-deprecated-objc-isa-usage -Wno-cast-of-sel-type -fdollars-in-identifiers -fobjc-legacy-dispatch -D_LIBCPP_VISIBLE= -MMD -MT dependencies -o ".\Debug\%file%.%obj%" -c -target "%target%" %std% -fblocks -fobjc-runtime=macosx-10.13.0 -g -gcodeview -DOBJC_PORT -D__OBJC2__=1 -DBUILDING_OBJC=1 -DHAVE_STRUCT_TIMESPEC -DNOMINMAX -Wno-nullability-completeness -I ".\include" -I "..\..\deps\apple-headers" -I "..\..\deps\pthreads.2" -I "..\..\deps\libclosure" "..\..\deps\%dir%\%file%" %params%

if [%language%]==[assembler-with-cpp] objconv -fcoff -v0 ".\Debug\%file%.%obj%"

echo ".\Debug\%file%.obj" >> ".\Debug\files.txt"
