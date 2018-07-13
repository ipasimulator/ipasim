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

## Porting

To inject our Objective-C runtime into WinObjC, follow these instructions:

- Copy the runtime (as `libobjc2{.dll,.lib,.pdb}`) into `deps/WinObjC/tools/deps/prebuilt/Universal Windows/x86/`.
- Build solution `deps/WinObjC/tools/tools.sln`.
- Run inside `deps\WinObjC\tools\OutputPackages\Debug`:

```cmd
..\..\..\.tools\nuget add -source ..\..\..\..\..\packages WinObjC.Language.0.2.180221-dev-20180713113359.nupkg
..\..\..\.tools\nuget add -source ..\..\..\..\..\packages WinObjC.Compiler.0.2.180221-dev-20180713113359.nupkg
..\..\..\.tools\nuget add -source ..\..\..\..\..\packages WinObjC.Logging.0.2.180221-dev-20180713113359.nupkg
..\..\..\.tools\nuget add -source ..\..\..\..\..\packages WinObjC.Packaging.0.2.180221-dev-20180713104420.nupkg
cd ..\..\..
.\.tools\nuget.exe sources add -name local -source ..\..\packages -configfile .\nuget.config
```

- Then manually move the `local` source to the top in the `deps\WinObjC\nuget.config`.
- Restore packages again (in dev cmd) inside `deps\WinObjC`: (**TODO: Needed?**)

```cmd
msbuild /t:Restore /p:BuildProjectReferences=false .\tools\tools.sln
```

- And rebuild `tools.sln` (and reinstall the packages into the local source?) (**TODO: Needed?**)
- Finally, restore packages for the main thing:

```cmd
msbuild /t:Restore /p:BuildProjectReferences=false .\build\build.sln
```

- And build it (`deps\WinObjC\build\build.sln` (and maybe install those packages into the local NuGet source, too).

**TODO: `pthreads-win32`'s `.dll` should be probably included, too.**
