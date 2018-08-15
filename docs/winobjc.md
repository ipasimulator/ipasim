# WinObjC

## How was it forked?

> See [docs on Git](git.md) for updated information on how Git repositories should be forked.

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

They can be found at [Chocolatey](https://chocolatey.org), as is described on one [WinObjC's wiki page](https://github.com/Microsoft/WinObjC/wiki/Using-vsimporter).

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
>
> ```
> fatal error C1041: cannot open program database '<path to repository>\deps\WinObjC\tools\WinObjCRT\dll\Release\vc141.pdb'; if multiple CL.EXE write to the same .PDB file, please use /FS [<path to repository>\deps\WinObjC\tools\WinObjCRT\dll\WinObjCRT.vcxproj]
> ```
>
> **TODO: Fix that error and use multi-core building.**

```cmd
msbuild "/t:WinObjC Language Package\Package\WinObjC_Language;WinObjC Packaging Package\Package\WinObjC_Packaging" /p:Configuration=Debug /p:Platform=x86 /v:m .\tools\tools.sln
msbuild /t:Restore /p:BuildProjectReferences=false /v:m .\build\build.sln
git submodule update --init --recursive
msbuild "/t:WinObjC Frameworks Package\Package\WinObjC_Frameworks" /p:Configuration=Debug /p:Platform=x86 /v:m .\build\build.sln
```

> If you don't want to rebuild `tools.sln` every time you make some changes to them, you can directly edit the packages (in `%HomePath%\.nuget\packages`) instead and then build only `build.sln`.

> If you want to build just a specific project, you will want to know that the targets are named e.g. `WinObjC Frameworks Package\UIKit\dll\UIKit` (for `UIKit` inside `Frameworks` package).
> You want to pass this name into MSBuild's `/t:` parameter.
> Other root folders are named `WinObjC Frameworks` *`<name>`* `Package`, where *`<name>`* is either `Core`, `Third Party`, `UWP Core` or `UWP`.

> How to build projects in solutions with `MSBuild`?
> See [this StackOverflow answer](https://stackoverflow.com/a/19534376/9080566) and [official docs](https://docs.microsoft.com/en-us/visualstudio/msbuild/how-to-build-specific-targets-in-solutions-by-using-msbuild-exe).

It should all succeed and generate output packages in `deps/WinObjC/tools/OutputPackages/Debug/` and `deps/WinObjC/build/OutputPackages/Debug/`.
Now clean the working directory with `git clean -fdx`, switch back to branch `port` and proceed to building the ported version as described below.

> To clean up even more, delete all `WinObjC.*` folders from `%HomePath%\.nuget\packages\`.

## Porting

To inject our Objective-C runtime into WinObjC, follow these instructions:

- Copy the runtime (as `libobjc2{.dll,.lib,.pdb}`) into `deps/WinObjC/tools/deps/prebuilt/Universal Windows/x86/`.
- Copy Clang:
  - `clang.exe` into `deps/WinObjC/tools/WinObjC.Compiler/LLVM/bin/`.
  - `libclang.dll` into `deps/WinObjC/tools/WinObjC.Compiler/LLVM/bin/` and `deps/WinObjC/tools/bin/`.
- Copy `lld-link.exe` and our proxy `link.exe` - see `Islandwood.props` for more information.
  **TODO: Automate this.**
- Build `/src/dyld/dyld_initializer.cpp` and copy the resulting `dyld_initializer.obj` along with `dyld.lib` into `deps/WinObjC/tools/deps/prebuilt/Universal Windows/x86/`.
  **TODO: Automate this, too.**
- Follow the exact same process as when building from source, except that now you should be on branch `port`, of course.
  Also, add argument `/p:ObjC_Port=true` when executing the `msbuild` commands.

**TODO: `pthreads-win32`'s `.dll` should be probably included with our runtime, too.**

**TODO: Maybe we should port the `master` branch, not `develop`.**

### Building `HelloUI` sample

```cmd
msbuild "/t:Restore" /p:Configuration=Debug /p:Platform=Win32 /p:ObjC_Port=true /v:m .\samples\HelloUI\HelloUI-WinStore10.sln
msbuild "/t:HelloUI\HelloUI" /p:Configuration=Debug /p:Platform=Win32 /p:ObjC_Port=true /v:m .\samples\HelloUI\HelloUI-WinStore10.sln
```

Then, copy a lot of `.dll`s along.

## Comment keywords

- `[objc-class]` - We replace `_OBJC_CLASS__NSCF...` symbol references (those were generated by the GNUstep runtime) with `OBJC_CLASS_$__NSCF...` symbol references (which are generated by our Apple-like runtime).
- `[class-symbols]` - Changed `_OBJC_CLASS_*` to `OBJC_CLASS_$_*` and `__objc_class_name_*` to `OBJC_METACLASS_$_*`.
  This reflects the difference between how our runtime and the GNUstep runtime name those symbols.
  Although symbols `__objc_class_name_*` and `OBJC_METACLASS_$_*` probably doesn't mean the same thing, we only replace those symbols in `.def` files so it only causes them to be exported which is exactly what we want.
  Note that this "tag" is not actually used, because it would be virtually in every `.def` file inside `/deps/WinObjC/build/`.
  **TODO: Write a script that will do this automatically (without the need for manually changing those `.def` files).
  Then add this script into one of the MSBuild project files, conditioned with `'$(ObjC_Port)' == 'true'` as other changes.**
- `[ehtype]` - So that it is not an error to have multiple occurrences of symbol `_OBJC_EHTYPE_$_NSException`.
  **TODO: Instead make `clang` to not generate those symbols.**
- `[no-nsobject]` - `NSObject` is implemented in our runtime, so we disabled it in WinObjC's `Foundation` framework.
  **TODO: Is our `NSObject` complete, though?**
- `[uikit-autolayout]` - There is a circular dependency between projects `AutoLayout` and `UIKit`.
  You may need to manually build these projects twice to solve this dependency.
  But it's not that easy.
  First, it doesn't play nicely with `lld-link`.
  Second, you have to manually disable and then re-enable one of the dependencies while building twice.
  **TODO: How can this work in the original code?**
  **TODO: Solve this better.**
  See also [official MSDN docs about circular dependencies](https://docs.microsoft.com/en-us/cpp/build/reference/using-an-import-library-and-export-file) and also [this blog post](http://www.lurklurk.org/linkers/linkers.html).
