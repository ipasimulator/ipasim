# Dependency `LIEF`

It can be found in `/deps/LIEF/`.

## Building

```cmd
mkdir build && cd build
echo ** > .gitignore
mkdir Debug && cd Debug
cmake -G Ninja -DLIEF_PYTHON_API=Off -DLIEF_DOC=Off -DLIEF_EXAMPLES=Off -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=..\..\..\..\build ..\..
ninja LIB_LIEF_STATIC install
```
