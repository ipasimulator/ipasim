# LLVM and Clang

This document describes submodules `deps/llvm` and `deps/clang`.
They were forked from <https://git.llvm.org/git/llvm.git/> and <https://git.llvm.org/git/clang.git/>, respectively, using `git clone --mirror` and `git push --mirror`.

## Microsoft patches

Then, Microsoft patches (0009-0019) from `deps/WinObjC/contrib/clang` were applied to Clang using `git am`.
They are applied in branch `microsoft` which is based on `release_60`.
Then, branch `port` was created in `deps/clang` based on branch `microsoft` and in `deps/llvm` based on branch `release_60`.
