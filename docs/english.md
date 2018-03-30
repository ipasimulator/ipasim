# IPA Simulator

This is not in any way a complete documentation, it's just a draft containing some ideas that I could forgot until the final documentation is written.

## Projects organization

Projects inside the `Library/LLVM/ARM` solution folder are simply all projects from the generated `deps/llvm/build/arm/LLVM.sln`.
Similarly projects inside the `Library/LLVM/Win32` folder.
All of these were added simply by selecting the `.sln` file in the `Add Existing Project...` dialog in Visual Studio.

The same is true for projects inside the `Library/yaml-cpp` solution folder.

## Updating dependencies

There are some third-party dependencies that can be updated whenever new version comes out.
A list of them follows.

- `clang` and `llvm` (in `deps` folder) - just pull the latest *stable* version from the remote repository, run the `cmake` as described below and make sure no new projects were added nor any old projects removed (or re-add the whole solution as described above).
  Then rebuild `IpaSimulator` (which doesn't use those libraries right now, but its dependent library, `HeadersAnalyzer`, does).
- `yaml-cpp` - the same old story.
- `WinObjC` (in `packages` folder) - just restore NuGet packages for the `IpaSimulator` project to get the latest `WinObjC` files (`.h` files used by `HeadersAnalyzer` and `.dll`s used by the very `IpaSimulator`).
- `LiefPort` and `UnicornPort` (in `lib` folder) - not easy to update right now since there are lots of changes from the original version.
  This should be easier in the future either by making them submodules or using `clang` libraries instead.
- `iPhoneOS.sdk` (in `deps` folder) - just download the latest iPhone SDK and replace the contents of this folder with it.
  Then rebuild `IpaSimulator` (which should in turn run `HeadersAnalyzer` that uses `.h` and other files from this SDK).
- `pthreads.2` - just extract the latest `pthreads-w32-*-*-*-release.zip` from [pthreads-win32's ftp](ftp://sourceware.org/pub/pthreads-win32).
  Then make sure that `/src/pthread/pthread.vcxproj` is still valid (i.e., changes made to `/deps/pthreads.2/Makefile` and `/deps/pthreads.2/config.h` are reflected in the `.vcxproj`).
- `objc4` - just extract the latest tarball from [the official Apple's repository](https://opensource.apple.com/tarballs/objc4/).
  Currently extracted version is `objc4-723`.
  Then make sure that `/src/objc/objc.vcxproj` is still valid.
  See [documentation of the objc port](objc.md) for more details.

## How to build (on 64-bit Windows with Visual Studio 2017)

1. Checkout the repository and make sure submodules are checked out as well.
2. Install `cmake` and make sure it's in your `PATH` environment variable.
3. Run the following commands:

   ```cmd
   cd deps\llvm
   mkdir build && cd build
   mkdir win32 && cd win32
   cmake -G "Visual Studio 15" -DLLVM_TARGETS_TO_BUILD="ARM" -DLLVM_EXTERNAL_CLANG_SOURCE_DIR="..\..\..\clang" -Thost=x64 ..\..
   cd ..
   mkdir arm && cd arm
   cmake -G "Visual Studio 15 ARM" -DLLVM_TARGETS_TO_BUILD="ARM" -DLLVM_EXTERNAL_CLANG_SOURCE_DIR="..\..\..\clang" -DLLVM_TABLEGEN="<full path to source directory>\deps\llvm\build\win32\Release\bin\llvm-tblgen.exe" -Thost=x64 ..\..
   cd ..\..\yaml-cpp
   mkdir build && cd build
   mkdir win32 && cd win32
   cmake -G "Visual Studio 15" -Thost=x64 ..\..
   ```

   **TODO: probably remove the `-Thost=x64` option and allow only 32-bit Windows for tooling/compilation and ARM + 32-bit Windows for running the app.**
4. If projects were successfully generated, you can open the `IPASimulator.sln`.

## How does it work

It's *dynamic*, i.e., arbitrary apps (`.ipa` files) can be loaded at run-time.
First, the binary file is loaded into memory.
If it contains a position-independent code, it can be loaded anywhere into memory, otherwise, it should be loaded into the exact place it requires (that is not implemented yet, but theoretically could be in the future, since the program's memory is only its own, so it should be able to allocate memory wherever it wants).
Then, code relocations may be needed (there's nothing special to these, it's just shifting absolute addresses by the relocation offset).
All the memory with code is also mapped into the emulator (flagged as executable), of course.
The CPU's virtual addresses and the emulator's virtual addresses should match for simplicity (since there's no reason why they couldn't match).

Now the important phase: binding external symbols.
The bridge (iOS to UWP) `.dll`s are dynamically loaded (only those needed) when the `.ipa` is loaded (it could even be delayed until the symbol is used for the first time).
Then the memory at which they were loaded by the OS is mapped into the virtual machine (as non-executable, so that execution can be caught and specially handled there).
Then the exact virtual addresses are used for the symbol bindings.
Now, if we are on ARM machine, these addresses are perfectly aligned, so all is fine.
But if we are on x86, these addresses may (and most likely won't) be aligned as ARM ABI requires.
This could be resolved by adding another layer of indirection: a virtual memory existing only in the emulator where all readings, writings and executions would be caught and handled by mapping them into the real CPU's memory to the correct (but unaligned) addresses.
This is yet to be implemented, though.

All calls to those external symbols are then handled *semantically*.
That means that the handler is aware about the meanings of the functions' parameters.
If they are pointers to memory, they might need to be translated (if there is that one more indirection layer discussed above).
If they are callbacks (or structures containing callbacks or whatever), they need to be replaced by special handlers that will start emulator when called.

This semantical handling is based on an external map (a database file) of symbol names and structured data about them (mainly their signatures).
This map is built from the bridge's `.hpp` files at compile-time.
