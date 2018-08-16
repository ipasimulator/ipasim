# Sample `export-class`

This sample demonstrates how our patched Objective-C runtime `libobjc` works with the simplest class.
It's not the most trivial sample, though, because the class resides in another `.dll`.
Therefore, the runtime needs to do some initialization (realize the class and also unify selectors across assemblies).

## Building

See instructions in `main.mm` and `testclass.mm`.
You also need to copy dependent `.dll`s into the output `build` directory.
**TODO: Automate this (by for example having just one `build` directory for all the projects in ipaSim, so that we don't have to copy anything anywhere).**
