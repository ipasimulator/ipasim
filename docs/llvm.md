# LLVM and Clang

This document describes submodules `deps/llvm` and `deps/clang`.
They were forked from <https://git.llvm.org/git/llvm.git/> and <https://git.llvm.org/git/clang.git/>, respectively, using `git clone --mirror` and `git push --mirror`.

## Microsoft patches

Then, Microsoft patches (0009-0019) from `deps/WinObjC/contrib/clang` were applied to Clang using `git am`.
They are applied in branch `microsoft` which is based on `release_60`.
Then, branch `port` was created in `deps/clang` based on branch `microsoft` and in `deps/llvm` based on branch `release_60`.

## Building

Follow the instructions below to build patched LLVM and Clang.

- Make sure you have installed CMake.
- Run these commands from Developer Command Prompt inside `deps/llvm`:

```cmd
mkdir build && cd build
cmake -G "Visual Studio 15" -DLLVM_TARGETS_TO_BUILD="ARM" -DLLVM_EXTERNAL_CLANG_SOURCE_DIR="..\..\clang" ..
msbuild /m "/t:CMakePredefinedTargets\ALL_BUILD" /p:Configuration=Debug /p:Platform=Win32 .\LLVM.sln
```
