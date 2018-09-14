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

Note that our goal is to later generate `.dylib`s that look exactly like it's described in TBD files from the iOS SDK.
To be able to do that, several things interest us in the TBD files.
First is list of exported symbols, of course.
We simply export those symbols from our wrapper `.dylib` (see below).
Second is list of re-exported symbols.
Again, we simply re-export symbols the same way real `.dylib` would do it (and our dynamic loader handles it the same way `dyld` would).
Third is list of Objective-C classes.
Not only we export symbols for them (`OBJC_CLASS_$_` and `OBJC_METACLASS_$_`), but we also note them to later generate wrappers for all of their methods.

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

**TODO: Note that currently, we actually emit *definitions* even if they were only *declarations* in the source code.
Those fake definitions have probably invalid bodies but we don't care since we are only interested in signatures.
We do that just for simplicity - there were less modification of Clang's code this way.
But it would really be better if we didn't emit any bodies, i.e., declarations were emitted as declarations.
Now, it would probably be a problem if there was a definition and a declaration of the same function in the analyzed files.
Because we would make the declaration into a definition and then there would be two definitions of the same thing.
Also, we should probably name the option differently and don't extend the existing `EmitAllDecls` since it actually does a different thing.
Our option (let's call it `DeclareEverything`) includes all declarations in the resulting LLVM IR, whereas the existing option `EmitAllDecls` really just makes *definitions* (duh) that would otherwise be discarded visible in the resulting LLVM IR.**

### Generating wrappers

There are two possible approaches to this.
One would be to leverage debugging information to get mapping from function arguments to registers and stack offsets.
This is what debugger should know - if we are debugging and set a breakpoint inside a function, it has to show us values of the function's arguments.
Although, it may as well use the other approach, too.

This other approach is to use Clang to generate wrappers in ARM and in i386 for every function.
The ARM wrapper has the same signature as the iOS function, and it simply extracts the function's arguments into some well-known structure (stored on stack).
We generate this wrapper simply by generating LLVM IR code which is then compiled to an object file.
This object file is then linked into a thin `.dylib` that contains only this object file and also imports the corresponding i386 wrappers.
That way, we delegate the low-level details of argument passing, calling conventions, etc. to Clang which should know them best.
Even better than, say, debugger, that's also why we chose this approach over the one mentioned above.
The i386 wrapper then takes a pointer to this structure and calls the real function with arguments from that structure.
Again, this wrapper is generated from LLVM IR code and compiled into an object file that is then linked into a thin DLL which imports the functions from the original DLL.
This wrapper DLL has the same name as the original one, but is inside folder `/Wrappers/` when deployed on the target machine, so that they can be distinguished.
Then, at runtime, the ARM wrappers are mapped to the virtual machine and their code is emulated.
When they call our i386 wrappers, the machine code jumps to an unmapped memory.
We catch that and simply extract a pointer to the structure (it's always in some well known location, e.g., if it's first argument, then the location is register `r0`).
Then, we call the proper i386 wrapper with this pointer as a parameter.
Return values are passed in the same structure.
Wrappers for callbacks are generated similarly.

The wrappers themselves are generated in LLVM IR which was chosen over C++ because it's easier to generate and the result is more robust.

Note that the correspondence between ARM and i386 wrapper libraries doesn't have to be 1:1.
For example, we can have function `foo` exported from library `libfoo.dylib` on iOS (we would get this information from `libfoo.tbd`) and function `bar` exported from the same library.
But on Windows, these can be implemented in different DLLs (maybe for historical reasons), e.g., `Foo.dll` and `Bar.dll`, respectively.
Then, `libfoo.dylib` would import from both of those DLLs.
Or, more precisely, `libfoo.dylib` would import from wrapper DLLs `/Wrappers/Foo.dll` and `/Wrappers/Bar.dll` which would then import from the original DLLs `Foo.dll` and `Bar.dll`, respectively.

For example, let's say we want to generate wrappers for function `int main(int, char**)`.
In C++ they would look roughly like this:

```cpp
// The iOS (ARM) wrapper.
int main(int argc, char **argv) {
  union {
    struct {
      int *arg0;
      char ***arg1;
    } args;
    int retval;
  } s;
  s.args.arg0 = &argc;
  s.args.arg1 = &argv;
  $__ipaSim_wrapper_main(&s);
  return s.retval;
}

// The DLL (i386) wrapper.
int $__ipaSim_wrapper_main(void *args) {
  union {
    struct {
      int *arg0;
      char ***arg1;
    } args;
    int retval;
  } *argsp = (decltype(argsp))args;
  // Here we call the real native function.
  argsp->retval = main(*argsp->args.arg0, *argsp->args.arg1);
}
```

Of course, we don't generate them like this, in C++.
Instead, we generate an equivalent LLVM IR code.

> Note that we build the i386 DLLs ourselves, so there shouldn't be a problem generating those wrappers as C++ code and compiling it directly into the DLL.
> This would have the advantage of not having twice as much DLLs like we have with the approach described above.
>
> Or, we could analyze header files of those DLLs' and generate the wrappers from that information into LLVM IR and then object files.
> And then use those object files when linking the DLLs.
> This should be implemented after we completely migrate to Clang for building those DLLs - because then, we could use generated [`compile_commands.json` files](https://clang.llvm.org/docs/JSONCompilationDatabase.html) to configure our header analyzer correctly.

#### Exporting Objective-C methods

Since Objective-C methods are only called dynamically by the Objective-C runtime, they don't need to and cannot be normally exported from a DLL.
But we need them exported so that we can link our wrapper DLL which imports those methods.
We could (and probably should) modify Clang to support exporting those methods.
But there is also a simpler solution - we can simply import some symbol that's guaranteed to exist (e.g., `_mh_dylib_header`) and compute runtime address of the Objective-C method from runtime address of that symbol and compile-time-known RVA of the Objective-C method.
For now, we chose the second approach since it's easier to implement.

### Calling functions at runtime

We need to be able to call any function from our DLLs based just on an address to which the emulated app jumps.
For example, the emulated app could manually do what `objc_msgLookup` does, i.e., getting function pointer from Objective-C metadata and then jumping to it.
(You could argue that most of apps won't do this, so why bother?
Well, the app could also simply call `objc_msgLookup` and cache the result, which might be an optimization that a compiler would make.)

One approach to this would be modifying the linker.
It would generate the iOS ARM wrappers inside the DLL in some custom section.
The Objective-C metadata would then be pointing to those wrappers and the dynamic loader would load this section into the emulator.
That way, we would delegate most of the work to the compile time, the dynamic loader wouldn't have to do anything special.

It would be too complex to implement, though, so we chose another approach.
We simply create a map from DLL function addresses to iOS wrapper function addresses.
And the dynamic loader then uses this map when the emulated app jumps out of mapped executable memory.

#### Function addresses inconsistency

The disadvantage in the second approach is that there is an inconsistency between addresses bound by dynamic loader and addresses located in Objective-C metadata.
If the emulated code only calls those addresses, it's not a problem as the former are just wrappers around the latter.
But if the code somehow depended on the values of those addresses, e.g., it compared them, it would be a problem.
Note that this usually doesn't happen since the addresses stored in the Objective-C metadata are not exported as functions that the dynamic loader could bind.
**TODO: Will this ever happen, then, or can we just ignore it?
Note that we should be able to determine what's the case, since it only depends on whether *our* DLLs (in accordance to iOS `.dylib`s, though) export Objective-C functions or not.**

How to solve this?
One possibility would be to compile all Objective-C declarations along with the wrapper functions into a small `.dylib`, that would be then loaded by the dynamic loader into the emulated address space.
This would have the advantage that the `.dylib` would seem legit to the emulated code, since it would be a real `.dylib` generated by Clang for ARM (with the proper header and everything).
But it would probably be problematic for the native DLL to then use the Objective-C metadata from that `.dylib`.
**TODO: Even if we realized that this inconsistency isn't a problem, this would still be a good approach to emulating the iOS system `.dylib`s in order for the emulated app not to recognize it's emulated.
So, don't delete this paragraph.**

We chose, again, a simpler approach, though.
Because all the Objective-C metadata need to be bound by our dynamic loader (even those between two native DLLs, see `[fixbind]`), we use the map from DLL to iOS addresses to fix up those metadata, so that they point to the wrapper functions, too.

### Variadic functions

We cannot simply generate wrappers around variadic functions that would take its arguments, because we have no simple and general way of knowing the arguments.
We divide variadic functions to two categories, *messengers* and *loggers*.

**Messengers** are functions like `objc_msgSend`, `objc_msgSend_stret`, etc.
They have two guaranteed arguments: `id self` and `SEL op`.
Other arguments can be determined only after the function corresponding to the selector (`op`) passed to them is found.
It can be found easily by calling the corresponding lookup functions, like `objc_msgLookup`, `objc_msgLookup_stret`, etc.
Those functions take *only* those two arguments mentioned above and return a function address corresponding to the selector.
They also don't modify the stack, so that it can be jumped directly to the function and we do exactly that if the resulting function resides in the emulated address space.
Otherwise, we have to jump to the wrapper function (also in the emulated address space) that extracts the (already known) arguments for us and calls the native DLL function.

Generally, we generate iOS wrappers for messengers that call the corresponding lookup functions (or more precisely, their iOS wrappers).
Then, they simply jump to the result.
If the result is inside the emulated code, it simply continues execution, otherwise, it is be handled by our emulation engine as any other function call.

**Loggers** are functions like `printf`, `NSLog`, etc.
Their arguments can be completely determined from the format string, usually their first argument.
**TODO: Implement wrappers for those.**
