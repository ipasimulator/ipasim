# Utility `pe_patcher`

This utility adds `.mhdr` section containing Mach header into PE images.

## Design

There are actually two possible approaches to this.
One is to modify LLVM linker (`lld-link`) to produce the `.mhdr` section.
The other one is to use LIEF library to add `.mhdr` section into existing `.dll` file.

## Building

- Checkout submodule `deps/LIEF`.
- Run the following commands in `deps\LIEF`:

```cmd
mkdir build && cd build
cmake -DLIEF_PYTHON_API=off ..
msbuild /t:"LIB_LIEF_SHARED" /p:Configuration=Debug /p:Platform=Win32 /v:m .\LIEF.sln
```
