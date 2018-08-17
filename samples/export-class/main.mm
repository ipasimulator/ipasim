// Compiled with:
// TODO: Doesn't work due to the `-fuse-ld` option for some reason.
// ..\..\build\bin\clang -target i386-pc-windows-msvc main.mm -o build/main.exe -fobjc-runtime=ios-11 -g -gcodeview -fuse-ld=..\..\build\bin\lld-link -L "..\..\src\objc\Debug" -L "..\..\Debug" -L ".\build" -llibobjc.A -ltestclass -ldyld -Wl,-debug -I "..\..\deps\llvm\include" -I "..\..\deps\llvm\build\Debug\include"

// To get .obj:
// ..\..\build\bin\clang -target i386-pc-windows-msvc -c main.mm -o build/main-obj.obj -fobjc-runtime=ios-11 -g -gcodeview -I "..\..\deps\llvm\include" -I "..\..\deps\llvm\build\Debug\include"

// To link the .obj with testclass.dll:
// ..\..\build\bin\lld-link -out:build\main.exe -debug -libpath:"..\..\src\objc\Debug" -libpath:"..\..\Debug" -libpath:".\build" main-obj.obj testclass.lib libcmt.lib libobjc.A.lib dyld.lib

#include "..\..\src\dyld\dyld.h"
#include "testclass.h"
#include <cstdio> // for puts

extern "C" void _objc_init(void);

extern "C" llvm::MachO::mach_header _mh_dylib_header;

@interface DerivedTestClass : TestClass
@end

@implementation DerivedTestClass
@end

int main() {
    puts("Press any key to coninue...");
    getc(stdin);

    // Initialize the runtime.
    // TODO: Use `dyld_initializer.obj` instead.
    _dyld_initialize(&_mh_dylib_header);
    _objc_init();

    [TestClass sampleMethod];
    return 0;
}
