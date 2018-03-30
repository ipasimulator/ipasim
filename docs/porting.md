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

## Comments in code

When porting code by copying it (or cloning from a remote repository, etc.), we add comments prefixed with `[port]` to indicate that those are our comments.
And all changes to the source code are described by nearby comments prefixed with `[port] CHANGE:`.
