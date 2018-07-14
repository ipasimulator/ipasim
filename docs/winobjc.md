# WinObjC

## How was it forked?

Note that not all objects were fetched from [the origin](https://github.com/Microsoft/WinObjC), because of the limits of their [LFS](https://git-lfs.github.com/).

```cmd
git clone https://github.com/Microsoft/WinObjC.git
cd WinObjC
git remote add new-origin https://jjones.visualstudio.com/DefaultCollection/IPASimulator/_git/WinObjC
git push new-origin develop
```

See also [some info about forking LFS](https://help.github.com/enterprise/2.13/admin/guides/installation/migrating-to-a-different-large-file-storage-server/), although it was not actually used after all.

## Building from source

To be able to work with it, we need to be able to build it from source first.
Official instructions can be found [in WinObjC's wiki](https://github.com/Microsoft/WinObjC/wiki/Building-From-Source).
But beware of some caveats described below.

### Restoring NuGet packages

Currently, there are [some problems with restoring NuGet packages](https://github.com/Microsoft/WinObjC/issues/2877#issuecomment-392991200).
This works, though:

```cmd
msbuild /t:Restore /p:BuildProjectReferences=false .\tools\tools.sln
msbuild /t:Restore /p:BuildProjectReferences=false .\build\build.sln
```

### Installing `WinObjC.Tools`

They can be found at [Chocolatey](https://chocolatey.org), as is described [in WinObjC's wiki](https://github.com/Microsoft/WinObjC/wiki/Using-vsimporter).

### Building in Visual Studio

If the build fails because Visual Studio cannot read or write some files, it seems that you need to wait until the solution is fully loaded, `#include`s parsed, etc. - i.e., until it says "Ready" in the status bar.

### Summing up

Follow these instructions to build from source.

- Install `WinObjC.Tools` (see above).
  **TODO: Maybe build `WinObjC.Tools` package and install it before building everything else...**
  Also make sure Git LFS is installed (`git lfs install`).
- Switch to the `develop` or `master` branch (not `port`).
- Run PowerShell inside `deps/WinObjC`:

```ps
.\init.ps1
```

- Run Developer Command Prompt inside `deps/WinObjC`:

```cmd
msbuild /t:Restore /p:BuildProjectReferences=false .\tools\tools.sln
msbuild "/t:WinObjC Language Package\Package\WinObjC_Language" /p:Configuration=Debug /p:Platform=x86 .\tools\tools.sln
msbuild "/t:WinObjC Packaging Package\Package\WinObjC_Packaging" /p:Configuration=Debug /p:Platform=x86 .\tools\tools.sln
msbuild /t:Restore /p:BuildProjectReferences=false .\build\build.sln
git submodule update --init --recursive
msbuild "/t:WinObjC Frameworks Package\Package\WinObjC_Frameworks" /p:Configuration=Debug /p:Platform=x86 .\build\build.sln
```

It should all succeed (except for the `NugetRestore` project, that can fail) and generate output packages in `deps/WinObjC/tools/OutputPackages/Debug/` and `deps/WinObjC/build/OutputPackages/Debug/`.
Now clean the working directory with `git clean -fdx`, switch back to branch `port` and proceed to building the ported version as described below.

## Porting

**TODO: Not complete.**
To inject our Objective-C runtime into WinObjC, follow these instructions:

- Copy the runtime (as `libobjc2{.dll,.lib,.pdb}`) into `deps/WinObjC/tools/deps/prebuilt/Universal Windows/x86/`.
- Build projects `WinObjC.Language` and `WinObjC.Packaging` in solution `deps/WinObjC/tools/tools.sln` for configuration `x86`.
- Run inside `deps/WinObjC/tools/OutputPackages/Debug/`:

```cmd
..\..\..\.tools\nuget add -source ..\..\..\..\..\build\packages WinObjC.Language<tab>
..\..\..\.tools\nuget add -source ..\..\..\..\..\build\packages WinObjC.Compiler<tab>
..\..\..\.tools\nuget add -source ..\..\..\..\..\build\packages WinObjC.Logging<tab>
..\..\..\.tools\nuget add -source ..\..\..\..\..\build\packages WinObjC.Packaging<tab>
```

- Finally, restore packages for the main thing:

```cmd
msbuild /t:Restore /p:BuildProjectReferences=false .\build\build.sln
```

- Build project `WinObjC.Frameworks` in solution `deps/WinObjC/build/build.sln` for configuration `x86`.

**TODO: `pthreads-win32`'s `.dll` should be probably included with our runtime, too.**
