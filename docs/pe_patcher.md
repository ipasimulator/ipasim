# Utility `pe_patcher`

This utility adds `.mhdr` section containing Mach header into PE images.

## Building

- Checkout submodule `deps/LIEF`.
- Run the following commands in `deps\LIEF`:

```cmd
mkdir build && cd build
cmake -DLIEF_PYTHON_API=off ..
msbuild /t:"LIB_LIEF_STATIC" /p:Configuration=Debug /p:Platform=Win32 /v:m .\LIEF.sln
```
