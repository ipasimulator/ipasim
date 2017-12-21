IPA Simulator
-------------

TODO: add unit tests testing that overlapping memory_map_ptr gives errors
TODO: maybe when calling .dll function from IPA (ARM) code, just change stack pointer to that of unicorn engine,
remember and remove the return address, call the function and then change it back...

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
