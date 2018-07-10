# Building `libc++`

## Motivation

Library `objc4` on macOS uses `libc++` as standard library.
It sometimes depends heavily on it (e.g. it calls directly `__cxa_throw` in `objc-exception.mm`).
So, it would be ideal to use it for our Windows `objc` port as well.

**TODO: Ok, it turns out, we would also need `libc++abi` library, which is not buildable on Windows yet.**

## Building from sources

See also <https://libcxx.llvm.org/docs/BuildingLibcxx.html#experimental-support-for-windows>.

### Prerequisites

- cmake-3.11.4-win64-x64.msi
- SlikSVN 1.9.7, 64 BIT
- `C:\Program Files\LLVM\tools\msbuild\install.bat` (for `LLVM-vs2014` toolset)
  - This requires Visual Studio (tested with Enterprise 2017, 15.7.4) with VC++ v140 toolset to be installed.

### Instructions

This was run on 10.7.2018 13:44 (LLVM revision 336661):

```cmd
svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm
cd llvm\projects
svn co http://llvm.org/svn/llvm-project/libcxx/trunk libcxx
svn co http://llvm.org/svn/llvm-project/libcxxabi/trunk libcxxabi
cd ..
mkdir build
cd build
cmake -G "Visual Studio 14 2015" -T "LLVM-vs2014" -DLLVM_PATH=.. -DLIBCXX_ENABLE_SHARED=YES -DLIBCXX_ENABLE_STATIC=NO -DLIBCXX_ENABLE_EXPERIMENTAL_LIBRARY=NO ..\projects\libcxx
cmake --build .
```

The result should be located in `build\lib\Debug\`.

**TODO: Add the sources as a dependency.
Ideally, some stable version should be forked as a submodule.**

## Using the built library

See also <https://libcxx.llvm.org/docs/UsingLibcxx.html#alternate-libcxx>.
