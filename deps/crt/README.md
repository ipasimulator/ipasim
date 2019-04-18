# C runtime DLLs

## Prerequisites

Make sure you have installed
[Debugging Tools for Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools).
Also make sure that `symchk.exe` from
`C:\Program Files (x86)\Windows Kits\10\Debuggers\x86` is in your `PATH`.

## Getting DLLs and PDBs

`ucrtbase.dll` was copied from `C:\Windows\SysWOW64\`. `ucrtbased.dll` was
copied from
`C:\Program Files (x86)\Microsoft SDKs\Windows Kits\10\ExtensionSDKs\Microsoft.UniversalCRT.Debug\10.0.17134.0\Redist\Debug\x86`.
Their symbol files (`.pdb`s) were retrieved with `symchk`:

```cmd
symchk .\ucrtbase.dll /s SRV*%CD%\syms*https://msdl.microsoft.com/download/symbols
symchk .\ucrtbased.dll /s SRV*%CD%\syms*https://msdl.microsoft.com/download/symbols
```

And copied from folder `./syms/` to `./`.

## Getting LIBs

`ucrtd.lib` is located in
`C:/Program Files (x86)/Windows Kits/10/Lib/10.0.17134.0/ucrt/x86/`. But it
doesn't contain all symbols (e.g., `strrchr`). So, instead, we crafted our own
import library. Inspiration was
[an answer on StackOverflow](https://stackoverflow.com/a/9946390).
