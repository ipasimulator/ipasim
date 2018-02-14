# IPA Simulator

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
