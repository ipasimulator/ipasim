# Dependency `LIEF`

It can be found in `/deps/LIEF/`.

## Building

```cmd
mkdir build && cd build
echo ** > .gitignore
mkdir Debug && cd Debug
cmake -G Ninja -DLIEF_PYTHON_API=Off -DLIEF_DOC=Off -DLIEF_EXAMPLES=Off -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=..\..\..\..\build ..\..
ninja LIB_LIEF_SHARED install
copy /Y LIEF.dll ..\..\..\..\build\bin\LIEF.dll
```

There is a bug - both import and static libraries have target named `LIEF.lib`, so Ninja is confused.
Small lib (~ 1 MB) is the static one; big lib (~ 200 MB) is the import one.
If you get the wrong one, delete the output (inside `/deps/LIEF/build/` not `/build/lib/`) and re-run the `ninja` command.
If you delete `LIEF.lib`, the static library will be linked, so you will get the static version of `LIEF.lib`.
If you delete `LIEF.dll`, the shared and import library will be linked, so you will get the import version of `LIEF.lib`.
