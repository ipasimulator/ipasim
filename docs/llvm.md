# LLVM and Clang

This document describes submodules `deps/llvm`, `deps/clang` and `deps/lld`.
They were forked from <https://git.llvm.org/git/llvm.git/>, <https://git.llvm.org/git/clang.git/> and <https://git.llvm.org/git/lld.git/>, respectively, using `git clone --mirror` and `git push --mirror`.

## Microsoft patches

Then, Microsoft patches 0009-0019 from `deps/WinObjC/contrib/clang` were applied to Clang using `git am`.
They are applied in branch `microsoft` which is based on `google/stable` (that's some time after `release_60`, where patches prior to 0009 have been already applied by Microsoft).
In LLVM, there were no patches to apply, but branch `microsoft` was created nevertheless, based on `stable`, for consistency.
**TODO: Maybe base it on [`RELEASE_601` tag](http://llvm.org/viewvc/llvm-project/llvm/tags/RELEASE_601/final/), instead of `stable` branch.**
Similarly LLD, but there was not even a `stable` branch, so it was based on some random commit which originated around the same time as the `stable` branches in LLVM and Clang.

> There are also old branches named `port`, not currently used.
> Before using them again (if changing something in LLVM or Clang), delete them first.

## Apple patches

We also added library `ObjCMetadata` to LLVM from <https://opensource.apple.com/source/clang/clang-800.0.42.1/>.

## Building

Follow the instructions below to build patched LLVM and Clang.
**TODO: See and somehow use also repo `clang-build` (it contains older build instructions than are those below, though).**

- Make sure you have installed CMake.
- Run these commands from Developer Command Prompt inside `deps/llvm`:
  **TODO: Build only projects (and `LLVM_TARGETS_TO_BUILD`) that are necessary.**

```cmd
mkdir build && cd build
mkdir Release && cd Release
cmake -G "Ninja" -DLLVM_TARGETS_TO_BUILD="X86" -DLLVM_EXTERNAL_CLANG_SOURCE_DIR="..\..\..\clang" -DLLVM_EXTERNAL_LLD_SOURCE_DIR="..\..\..\lld" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="..\..\..\..\build" ..\..
ninja install-clang install-libclang install-lld install-llvm-headers tools/clang/lib/install lib/install install-LLVMSupport install-LLVMDemangle
```

- The outputs will be in `/build/`.

> Alternatively, you can add option `-DCMAKE_BUILD_TYPE=Debug` to the CMake command to build a version of Clang which you will be able to debug in Visual Studio (do this preferably inside folder `/deps/llvm/build/Debug/`).
> **TODO: We would also like to add option `-DLLVM_OPTIMIZED_TABLEGEN=On`, but it currently doesn't work.**

For a `Debug` build with `Release` TableGen, do this (after building `llvm-tblgen` and `clang-tblgen` inside `/deps/llvm/build/Release/`):

```cmd
cmake -G "Ninja" -DLLVM_TARGETS_TO_BUILD="X86" -DLLVM_EXTERNAL_CLANG_SOURCE_DIR="..\..\..\clang" -DLLVM_EXTERNAL_LLD_SOURCE_DIR="..\..\..\lld" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="..\..\..\..\build" -DLLVM_TABLEGEN="%cd%\..\Release\bin\llvm-tblgen.exe" -DCLANG_TABLEGEN="%cd%\..\Release\bin\clang-tblgen.exe" ..\..
```

## Porting

### Comment keywords

- `[ipasim-objc-runtime]`: We are adding a new runtime called `ipasim` that derives from the `ios` runtime and introduces changes that the `microsoft` runtime introduced.
- `[dllimport]`: See section "Objective-C symbols across DLLs".
- `[mhdr]`: We are patching linker (`lld-link`) to add a section named `.mhdr` which will contain Mach-O header.
  This Mach-O header will then be used by our `libobjc` to initialize the image.
- `[fixbind]`: See `[dllimport]` - we are fixing some symbols to use `__declspec(dllimport)` semantics, but that introduces another level of indirection in data pointers.
  Unfortunately, Windows loader cannot bind symbols directly, so we need to fix those bindings at runtime.
  In Clang, we create a new section called `.fixbind` which contains addresses to all the bindings that need to be fixed.
  At runtime, we then fix those addresses in our `dyld`.
- `[pretty-print]`: We improved pretty printing of functions to match our needs in `HeadersAnalyzer`.

### Objective-C symbols across DLLs

Currently, Clang works pretty well when configured to use Apple's Objective-C runtime and COFF object file format.
This is actually surprising since this combination doesn't really make sense in the real world.
However, it obviously starts making sense as soon as our runtime is involved.
And then, we will see that it doesn't work perfectly, so we need to make some changes to Clang.

One such thing is `__declspec(dllimport)`ing Objective-C classes.
Clang actually recognizes this attribute and sets it correctly for the corresponding `GlobalVariable` (see `CGObjCNonFragileABIMac::GetClassGlobal` in `CGObjCMac.cpp`).
But, this information is later not considered when emitting the `GlobalVariable` in `TargetMachine::getSymbol` in `AsmPrinter::getSymbol` in `AsmPrinter::EmitGlobalVariable` in `AsmPrinter::doFinalization`.

## Debug info

Besides the `-g -gcodeview` options that make Clang to emit debugging information, there is also a mysterious `-mllvm -emit-codeview-ghash-section` flag.
More information about it can be found in [this LLVM blog post](http://blog.llvm.org/2018/01/improving-link-time-on-windows-with.html).
Originally, this was found on SO in [these](https://stackoverflow.com/a/48573877/9080566) [two](https://stackoverflow.com/a/48604068/9080566) answers.
