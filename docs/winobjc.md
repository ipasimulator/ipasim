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
.\.tools\nuget.exe restore .\tools\tools.sln
```

- Run Developer Command Prompt inside `deps/WinObjC`:

> Note that multi-core building (with MSBuild's option `/m`) doesn't work very well.
> It sometimes gives the following error:
> ```
> fatal error C1041: cannot open program database '<path to repository>\deps\WinObjC\tools\WinObjCRT\dll\Release\vc141.pdb'; if multiple CL.EXE write to the same .PDB file, please use /FS [<path to repository>\deps\WinObjC\tools\WinObjCRT\dll\WinObjCRT.vcxproj]
> ```
> **TODO: Fix that error and use multi-core building.**

```cmd
msbuild "/t:WinObjC Language Package\Package\WinObjC_Language;WinObjC Packaging Package\Package\WinObjC_Packaging" /p:Configuration=Debug /p:Platform=x86 .\tools\tools.sln
msbuild /t:Restore /p:BuildProjectReferences=false .\build\build.sln
git submodule update --init --recursive
msbuild "/t:WinObjC Frameworks Package\Package\WinObjC_Frameworks" /p:Configuration=Debug /p:Platform=x86 .\build\build.sln
```

> How to build projects in solutions with `MSBuild`?
> See [this StackOverflow answer](https://stackoverflow.com/a/19534376/9080566) and [official docs](https://docs.microsoft.com/en-us/visualstudio/msbuild/how-to-build-specific-targets-in-solutions-by-using-msbuild-exe).

It should all succeed and generate output packages in `deps/WinObjC/tools/OutputPackages/Debug/` and `deps/WinObjC/build/OutputPackages/Debug/`.
Now clean the working directory with `git clean -fdx`, switch back to branch `port` and proceed to building the ported version as described below.

> To clean up even more, delete all `WinObjC.*` folders from `%HomePath%\.nuget\packages\`.

## Porting

To inject our Objective-C runtime into WinObjC, follow these instructions:

- Copy the runtime (as `libobjc2{.dll,.lib,.pdb}`) into `deps/WinObjC/tools/deps/prebuilt/Universal Windows/x86/`.
- Follow the exact same process as when building from source, except that now you should be on branch `port`, of course.
  **TODO: It doesn't work!**

**TODO: `pthreads-win32`'s `.dll` should be probably included with our runtime, too.**
