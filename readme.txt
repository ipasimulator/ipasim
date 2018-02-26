IPA Simulator
-------------

TODO: add unit tests testing that overlapping memory_map_ptr gives errors
TODO: maybe when calling .dll function from IPA (ARM) code, just change stack pointer to that of unicorn engine,
remember and remove the return address, call the function and then change it back...
TODO: what if there are callbacks passed from the ARM code into the x86 code?
Well, just hook 'em (i.e., pass instead of them some middle layer).
We can recognize function parameters that are callbacks simply by manually listing all of them (from the header files).
TODO: rename /lib/ to /deps/.
TODO: include LIEF and Unicorn as submodules in /deps/ and add only .vcxproj files to /src/.
TODO: add README.md files to more folders (and remove this readme.txt file).
TODO: allow only Debug and Release configurations and Win32 and ARM platforms.
TODO: is LiefPort still necessary? clang lib should be enough.
TODO: is UnicornPort still necessary? Maybe LLVM could be emulated. Or at least interpreted on ARM (with relocations and so on provided by llvm).
TODO: maybe use clang to link Mach-O app with WinObjC .dlls at compile-time (or even runtime) for ARM.
TODO: also, llvm should contain some dynamic linker, which we should definitely use instead of our own code.

### How does it work?

(Or better how it should work after it's done...)

1. It copies all segments from the Mach-O binary into memory.
Or, if the segment has no protection right, no memory has to be allocated.

2. It maps the segment's memory with correct rights into the Unicorn Engine.

3. It relocates (rebases) the segment addresses.

4. It loads the frameworks the binary depends on via LoadPackagedLibrary (which is the only LoadLibrary-like function that can be used in UWP apps).
It loads symbols from these libraries using GetProcAddress and remembers the lowest and greatest address from each library.
It then maps memory regions from these lowest to highest addresses into the Unicorn Engine with read/write rights.
This ensures, the data can be written, the code cannot (OS will ensure that) and function execution can be caught and serviced.

5. It hooks function calls (see TODOs above) and executes the entry point.
