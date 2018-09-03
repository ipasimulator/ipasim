# Dependency `LIEF`

It can be found in `/deps/LIEF/`.
Our port was forked from <https://github.com/lief-project/LIEF>.
Branch `port` was based on tag `9.0.0`.

## Building

```cmd
mkdir build && cd build
mkdir Debug && cd Debug
cmake -G Ninja -DLIEF_PYTHON_API=Off -DLIEF_DOC=Off -DLIEF_EXAMPLES=Off -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=..\..\..\..\build ..\..
ninja LIB_LIEF_STATIC install
copy /Y LIEF.dll ..\..\..\..\build\bin\LIEF.dll
```

There is a bug - both import and static libraries have target named `LIEF.lib`, so Ninja is confused.
Small lib (~ 1 MB) is the static one; big lib (~ 200 MB) is the import one.
If you get the wrong one, delete the output (inside `/deps/LIEF/build/` not `/build/lib/`) and re-run the `ninja` command.
If you delete `LIEF.lib`, the static library will be linked, so you will get the static version of `LIEF.lib`.
If you delete `LIEF.dll`, the shared and import library will be linked, so you will get the import version of `LIEF.lib`.

## Git tags

- `[lief-mt]`: We link LIEF statically, because we need only substantial portion of it.
  But UWP apps need to link to CRT dynamically, so we need to use `/MD` compiler option instead of `/MT`.
