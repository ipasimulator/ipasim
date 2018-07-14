# Porting

This document contains general notes about porting Windows libraries to UWP (Universal Windows Platform), since there is a lot of such porting in this project.

## Using native `.dll`s in UWP apps

It's possible to build classical Win32 `.dll`s (or download prebuilt ones) and use them from an UWP app.
Simply add the `.dll` into the project with property `Content` set to `True` (so that it gets copied into the resulting `.appx`).

If there are some dependent `.dll`s that the target platform doesn't contain, though, it will end with error `-1073741515 (0xc0000135) 'A dependent dll was not found'`.
To debug this, see for example [this StackOverflow question](https://stackoverflow.com/q/44659598) and the links it contains.

These native `.dll`s are usually for Win32 platform only.
To build them for ARM, just add ARM platform in Configuration Manager in Visual Studio.
This alone won't do the trick, though, since building for ARM is disabled by default (you'll get error `MSB8022: Compiling Desktop applications for the ARM platform is not supported.`).
To overcome this, just add `<WindowsSDKDesktopARMSupport>true</WindowsSDKDesktopARMSupport>` to the `.vcxproj`'s `<PropertyGroup Label="Globals">`.
See for example [blog post on pete.akeo.ie](http://pete.akeo.ie/2017/05/compiling-desktop-arm-applications-with.html) for more details.

To sum up, using native `.dll`s in UWP apps can be very problematic - on Desktop, everything will probably work fine, but on other platforms, some `.dll`s can be missing, and it's very hard to debug that.
Also, if the library actually calls something that's not supported on UWP, some stub function will be called, which will probably just return `NULL` or something like that (and that may or may not be the correct behavior for our application).

## Creating UWP `.dll` project

So, an alternative and better approach is to create an UWP `.dll` project in Visual Studio, adding the original source code files into it and finally creating our own stub functions which will do what makes sense for our application.

> For more information about UWP and `.dll`s, see [these Microsoft docs](https://docs.microsoft.com/en-us/cpp/cppcx/dlls-c-cx).
> **TODO: Read and make use of it!**
> > Also, this comment (which will probably be removed in the future) has some good information:
> >
> > Advice above to set WINAPI_FAMILY=WINAPI_PARTITION_APP is counter to winapifamily.h:
> >
> > ```cpp
> > /*
> >  * The WINAPI_FAMILY values of 0 and 1 are reserved to ensure that
> >  * an error will occur if WINAPI_FAMILY is set to any
> >  * WINAPI_PARTITION value (which must be 0 or 1, see below).
> >  */
> > ```

### Why should we build for UWP?

After all, only difference is that it uses `api-ms-*` umbrella `.dll`s instead of `kernel32.dll` (if done properly - i.e., if built against UWP's `platform.winmd` - see [docs on Objective-C runtime](objc.md), section Porting, for more information).
Well, [umbrella libraries](https://docs.microsoft.com/en-us/windows/desktop/apiindex/windows-umbrella-libraries) are in fact just virtual `.dll`s (they don't exist anywhere on disk), they are mapped to physical `.dll`s (like `kernel32.dll`, `kernelbase.dll`, etc.) by `ApiSetSchema.dll` mapping library.
See [this StackOverflow answer](https://stackoverflow.com/a/47530043/9080566), where it's described.

**TODO: But does that have any pros or cons?**
As I see it now, those `api-ms-*.dll`s might only contain the high-level (i.e., structured) WinRT APIs and not the low-level ones (i.e., plain C, good old Win32 APIs).
Or, maybe they contain both, but the high-level ones cannot be found elsewhere (or at least not easily, because since they're umbrella libraries, all the APIs must technically exist elsewhere).

## Comments in code

When porting code by copying it (or cloning from a remote repository, etc.), we add comments prefixed with `[port]` to indicate that those are our comments.
And all changes to the source code are described by nearby comments prefixed with `[port] CHANGED:`.

Also, in `C`-based code, there are `#ifdef`s around the changed code, so that the changes are only effective if some preprocessor definition is passed to the compiler (e.g., in `objc` library, this is `OBJC_PORT` definition).

**TODO: Maybe we shouldn't ever change the original source code directly, but rather create a new branch in a repository containing just the dependency, then making the changes in this separate branch and adding it as a submodule.
This way, we could easily update the dependency by pulling changes into the branch with the original code and then merging it with the branch containing the changes.
Still, comments explaining those changes should be added, though.**
