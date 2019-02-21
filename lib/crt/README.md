# C runtime DLLs

`ucrtbased.dll` was copied from `/src/IpaSimulator/Debug/IpaSimApp/AppX/`
(after building `IpaSimApp` in Visual Studio). `ucrtbased.pdb` was copied from
Visual Studio's symbol cache (after enabling Microsoft Symbol Servers).

`ucrtd.lib` is located in
`C:/Program Files (x86)/Windows Kits/10/Lib/10.0.17134.0/ucrt/x86/`. But it
doesn't contain all symbols (e.g., `strrchr`). So, instead, we crafted our own
import library. Inspiration was
[an answer on StackOverflow](https://stackoverflow.com/a/9946390).

```cmd
dumpbin /exports ucrtbased.dll > exports.txt
echo LIBRARY UCRTBASED > ucrtbased.def
echo EXPORTS >> ucrtbased.def
for /f "skip=19 tokens=4" %A in (exports.txt) do @echo %A >> ucrtbased.def
lib /def:ucrtbased.def /out:ucrtbased.dll.a /machine:x86
```
