# `HeadersAnalyzer`

## Building

First, [build LLVM](../../docs/llvm.md) in the same configuration you want to build `HeadersAnalyzer`.
Then, open and build `HeadersAnalyzer` in Visual Studio.

## Running

Make sure your working directory is the root directory of the repository when running the program.

## How should it work (a.k.a. roadmap)

There are two types of functions - exported and callbacks.
By exported functions, we mean functions exported from iOS `.dylib`s, i.e., functions that emulated apps can call.
We generate wrappers for those functions that take an emulation context (i.e., registers and stack of the virtual machine, e.g., `uc_engine *`) and function pointer, extract its arguments and call the function.

By callbacks, we mean functions that exist in the emulated code and that our compiled code can call (e.g., if some event occurs, etc.).
We manually identify those callbacks in our source code and wrap it in some helper function or macro that instead of calling the function directly, looks if it's inside the emulated app or not.
If it isn't, it is called normally.
If it is, however, it calls a wrapper that we generate at compile time.
This wrapper takes the function's arguments and emulation context and copies the arguments into registers and stack of the virtual machine and calls the function inside the VM.

Here's how our compile-time code generation utility works:

1. It analyzes TBD files of iOS `.dylib`s to find exported functions.
2. Via Clang, it analyzes iOS header files (from `/deps/apple-headers/iPhoneOS11.1.sdk/`) to find those exported functions' signatures.
   It gets debugging information for those functions, as if we're inside them when they're being called (this will be useful when calling from emulated to compiled code).
   It also gets debugging information for callback functions, this time the other way around, i.e., as if we're outside of them when they're being called (this will be useful when calling from compiled to emulated code).
3. It analyzes our compiled `.dll`s and their `.pdb`s to find exported functions and their signatures, respectively.
   It maps iOS functions to our functions and verifies that they have compatible signatures.
4. It also generates a map that is used at run time to quickly map from function names imported in the emulated app to function addresses exported from our compiled `.dll`s (this mapping is done via ordinals on the `.dll` side, rather than names, for better performance).
5. Via LLDB, it generates wrappers mentioned above.
   It throws function signatures at LLDB and asks it where are the arguments in registers and stack.
   It then puts or extracts arguments from there (when generating wrappers from compiled to emulated code, or from emulated to compiled code, respectively).

### Analyzing TBD files

This is implemented with the help of Apple's TAPI library that can read TBD files.
See [our documentation about it](../../docs/tapi.md) for details.

### Analyzing iOS headers

This is work in progress.
