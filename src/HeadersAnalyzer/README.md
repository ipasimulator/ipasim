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
6. We also parse `WinObjC` headers (i.e., those used to produce our `.dll`s) to find which functions are implemented and which are not.
   This can be easily determined because unimplemented functions are marked as deprecated with `__attribute((deprecated))`.
   They also have documentation comments with more details and we parse those, too.

### Analyzing TBD files

This is implemented with the help of Apple's TAPI library that can read TBD files.
See [our documentation about it](../../docs/tapi.md) for details.

### Analyzing iOS headers

> Note that better approach to this would be analyzing debugging symbols of iOS `.dylib`s.
> That way, we would get all the necessary type information and we could be 100% sure that it is correct (i.e., matching the `.dylib`s).
> When analyzing headers, we might get wrong information if we don't configure Clang exactly the same way Apple did when building the `.dylib`s.
> Unfortunately, it seems that there are no debugging symbols available for Apple's `.dylib`s.

#### Clang command line

To analyze headers, we run Clang on iOS headers as if we were building some iOS `.dylib`.
In fact, we already know how to do this - we ported `libobj.A.dylib`.
Of course, we built it for Windows platform, but the sources we based our build commands on were targeted for macOS/iOS.
So, here we can base our Clang command line on those sources (it probably doesn't differ that much, it's mainly about the `-target` option).

See `analyze_ios_headers.txt` for the command line arguments.

#### Possible implementations

We need LLVM and debugging information about all the functions, so that we can later figure out how and where arguments lie in memory and registers.
To do that, we execute `EmitLLVMAction` along with option `-g` (to emit debug info).
That won't preserve undefined functions, though (i.e., functions that only have declarations, no body).
We obviously have mostly those functions as we analyze headers and we want them emitted too (with empty bodies possibly as we only care about signatures).

This could be done by rewriting the AST tree before emitting LLVM to include empty bodies for every function (possibly with some throw statement, so that even functions that should return something are valid).
Or we could lower the functions manually to LLVM representation and then get debug info for them.
Or we could just somehow "use" the function's type since that all we care about anyway.
For example, emitting some global variable and initializing it with address to that function.
But that would also require an AST-rewriting step or emitting textual code.

#### Our approach

We chose the simplest (and we believe also the cleanest) solution - we used Clang's `LangOpts.EmitAllDecls` and made it emit really all declarations.
Until our changes, this option only emitted functions that *had bodies* but were discarded because no other function referenced them.
After our changes, this option emits also functions without bodies.
See tag `[emit-all-decls]` in Clang's code to see those changes.

### Generating wrappers

There are two possible approaches to this.
One would be to leverage debugging information to get mapping from function arguments to registers and stack offsets.
This is what debugger should know - if we are debugging and set a breakpoint inside a function, it has to show us values of the function's arguments.
Although, it may as well use the other approach, too.

This other approach is to use Clang to generate wrappers in ARM and in i386 for every function.
The ARM wrapper has the same signature as the iOS function, and it simply extracts the function's arguments into some well-known structure (stored on stack).
We generate this wrapper simply by generating C++ code which is then compiled by Clang.
Currently, this code is generated in textual form, but it could also be generated as AST or LLVM IR and then compiled.
That way, we delegate the low-level details of argument passing, calling conventions, etc. to Clang which should know them best.
Even better then, say, debugger, that's also why we chose this approach over the one mentioned above.
The i386 wrapper then takes a pointer to this structure and calls the real function with arguments from that structure.
Again, this wrapper is generated from C++ code using Clang.
Then, at runtime, the ARM wrappers are mapped to the virtual machine and their code is emulated.
When they call our i386 wrappers, the machine code jumps to an unmapped memory.
We catch that and simply extract a pointer to the structure (it's always in some well known location, e.g., if it's first argument, then the location is register `r0`).
Then, we call the proper i386 wrapper with this pointer as a parameter.
Return values are passed in the same structure.
Wrappers for callbacks are generated similarly.

The wrappers themselves are generated in LLVM IR.
That was chosen over C++ because it's easier to generate and the result is more robust.
