# Project `RTObjCInterop`

Source files come from [this GitHub repository](https://github.com/msft-Jeyaram/WinObjC/tree/rtinterop) ([this commit](https://github.com/msft-Jeyaram/WinObjC/commit/266797015de2ada69bc794bc7d7a750c1c8e2135), to be more precise).

Originally, WinObjC used prebuilt assembly `RTObjCInterop.dll`.
We need to use that, too, but it cannot be the same prebuilt assembly since we need to use different Objective-C runtime (i.e., our ported Apple-like runtime).
That's why we created this project - to build our own version of `RTObjCInterop.dll`.

## Build instructions

Just run the `build.cmd` from Developer Command Prompt inside this directory.
This script was built simply by examining the project file `RTObjCInterop.vcxproj` in the original code.
Then, some include directories from `WinObjC/tools` were added (this would have been added probably by some included `.props` or `.targets` file into the `RTObjCInterop.vcxproj`, but we just guessed them, it was faster).
