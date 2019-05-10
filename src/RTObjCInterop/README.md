# Project `RTObjCInterop`

Source files come from
[this GitHub repository](https://github.com/msft-Jeyaram/WinObjC/tree/rtinterop)
([this commit](https://github.com/msft-Jeyaram/WinObjC/commit/266797015de2ada69bc794bc7d7a750c1c8e2135),
to be more precise).

Originally, WinObjC used prebuilt assembly `RTObjCInterop.dll`. We need to use
that, too, but it cannot be the same prebuilt assembly since we need to use
different Objective-C runtime (i.e., our ported Apple-like runtime). That's why
we created this project - to build our own version of `RTObjCInterop.dll`.
