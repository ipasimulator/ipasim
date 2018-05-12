# Objective-C runtime

Because the GNUstep runtime used by WinObjC is binary incompatible with the Apple's runtime used on iPhones, we cannot simply use it.
If we did, the runtime couldn't read the structures in the iPhone app binary as they are in Apple's format and the runtime expects them in its own different format.

So, the only option we see here is to recompile WinObjC with a different runtime (and pass clang a parameter to generate the Apple's structures - it can definitely do that since it's the compiler used on Apple for development).

## Apple's runtime

This is the runtime we would like to be binary-compatible with.

- Source code: [Official](https://opensource.apple.com/source/objc4/), [Tarballs](https://opensource.apple.com/tarballs/objc4/), [GitHub mirror](https://github.com/opensource-apple/objc4) (not updated so often)
- Documentation: [Official](https://developer.apple.com/documentation/objectivec/objective_c_runtime?language=objc)

### Ports

One cool thing to do would be to just take the source code of this and compile it for Windows.
Links to some interesting projects related to this follow.

- [GitHub] [0xxd0's buildable fork](https://github.com/0xxd0/objc4)
- [mailing list] [Building Objc4 on Windows](https://lists.apple.com/archives/darwin-dev/2009/Sep/msg00076.html)
- [SourceForge] [OpenCFLite](https://sourceforge.net/projects/opencflite/)
  - [mailing list] [Building Objc4 on Windows](https://lists.apple.com/archives/darwin-dev/2009/Nov/msg00045.html) (despite the same name, it's a different mailing list from the above)
- [GitHub] [isaacselement's buildable fork](https://github.com/isaacselement/objc4-706)
  - [GitHub] [lanvsblue's buildable fork](https://github.com/lanvsblue/objc4-706) (based on isaacselement's blog post)
- [GitHub] [Jeswang's buildable fork](https://github.com/Jeswang/objc4-532.2)
  - [StackOverflow] [Explanation of the repository](https://stackoverflow.com/questions/23469738/debugging-objc4-532-2-on-os-x-10-9)
- [GitHub] [oneofai's buildable fork](https://github.com/oneofai/objc4)
- [GitHub] [Mirror of objc4 with added comments](https://github.com/xuhong1105/objc4-680)
- [GitHub] [ishepherdMiner's buildable fork](https://github.com/ishepherdMiner/objc4-709/tree/v1.0)
  - [blog] [ishepherdMiner's blog post about `objc4-709`](http://www.iosugar.com/2017/05/05/objc-709-project-structures/)
  - [blog] [ishepherdMiner's blog post about `objc4-706`](http://www.iosugar.com/2017/02/11/objc-706-project-structures/)

Unfortunately, most of the projects above are for building the runtime on macOS.
And the others can build only the old runtime for Win32 (which is what even Apple was doing for Safari on Windows, so it is supported in the source code).
But we want the new runtime because that's the one used on iPhones.

## Other runtimes

### Modular Objective-C Run-Time Library

- Source code: [GitHub](https://github.com/charlieMonroe/modular-objc-run-time)
- Master thesis: [Local copy](../res/modular-objc.pdf), [CUNI repository](https://is.cuni.cz/webapps/zzp/detail/116510/29583005/)

### ObjFW

It contains an Objective-C runtime reimplementation.

- Source code: [Official GitHub mirror](https://github.com/Midar/objfw)

### Magenta project

- Info: [Official website](http://crna.cc/cat/open-source), [OSnews article](http://www.osnews.com/story/26060/Magenta_implements_Darwin_BSD_on_top_of_the_Linux_kernel), [Maemo.org thread](https://talk.maemo.org/showthread.php?t=84803)
- Source code: [Archive.org](https://web.archive.org/web/20120625011212/http://crna.cc:80/magenta_source.html)

### mulle-objc

- Info: [Official website](https://mulle-objc.github.io/)

**TODO: Add more.**

## Our runtime

After all, there is only one option left - we create our own Objective-C runtime written from scratch.
This runtime will have only one goal - to be binary compatible with the new Apple's runtime.

### Inspiration

Our code is inspired by the Apple's runtime source code, version 723.
We want it to be binary-compatible with the new runtime, so that's like `__OBJC2__` was defined.

The other projects listed above can be also useful for inspiration.

### Comments

Since lots of the code is copied from Apple's sources, we copy comments from there, as well, prefixing them with `[Apple]`.
Changes from the Apple's source should be well documented and comments documenting them are prefixed with `CHANGE:`.

### Threading

To ease porting from Apple's sources, which use `pthreads` APIs for threading, we use `pthreads-win32` wrapper library.
More specifically, we use the `pthreadVC2.dll`, i.e. the one that doesn't use structured exceptions (since iOS's `pthreads` most likely don't do that either **TODO: Verify!**) and is for MSVC compiler.

## Porting Apple's runtime

Now, we are trying to build the Apple's source code directly for UWP.
**TODO: If porting the Apple's runtime is the approach we choose, delete or incorporate the docs above.
Or better - leave it there as an option that we didn't choose after all.**
**TODO: Maybe extract from Starboard SDK information about how to build this using just clang and then use (c)make or something like that.**

### Building against a SDK

Currently on x86, we build it against the MacOSX SDK (`/deps/headers/MacOS*.sdk/`), but there's also an alternative - to build it against the iPhoneSimulator SDK.
Although, there shouldn't be much difference, because the Objective-C runtime shouldn't depend on anything platform specific in those headers.
**TODO: Decide properly what SDK should we build against.**

Our approach now is to try including as little of the SDK as possible.
We include the standard C++ things from MSVC instead, since we are building the library for UWP and the MacOSX SDK could use some Darwin-specific things.
But we haven't tried the opposite (i.e., including everything from the MacOSX SDK and not using the MSVC SDKs at all) yet, it might be cool as well (although it seems unlikely to work because of the Darwin-specific things - see for example `stdio.h` in MacOSX SDK).

**TODO: Right now, we also depend on some headers from `packages/WinObjC.Language.0.2.171110/build/include/WOCStdLib/` and similar.
We probably not want that, though.
(Maybe we can only take inspiration there.)**

### Preprocessor definitions

- `OBJC_PORT` - see [general notes about porting](porting.md) for more information.
- `TARGET_OS_*` and `TARGET_CPU_*` - see `TargetConditionals.h` in MacOSX SDK for more information about these.
  The apps we are trying to emulate are iPhone apps, so we are defining `TARGET_OS_IOS` while building the `objc` runtime to simulate that environment.
- `__OBJC2__` - we are building the new runtime (which is the only one available on iPhones anyway).
- `HAVE_STRUCT_TIMESPEC` - needed for `<pthread.h>` from the pthreads-win32 library.

### Proxy `#include`s

Because we definitely don't want to include the whole MacOSX SDK (for example, `<stdio.h>` and similar should be included from MSVC instead) but some header files are actually needed (they usually just contain macros, so it's safe to include them), we added proxy `.h` files.
These just `#include` the correct `.h` from MacOSX SDK, or sometimes don't do anything, if we don't need the `.h` actually (it was probably included through some other `.h` file).
Also, only the safe `.h` files are proxied this way, so it's ensured that nothing else is included from the MacOSX SDK.

### Non-SDK headers

Some headers `#include`d by the Apple's `objc4` library are not part of the MacOSX SDK.
Instead, they can be found in other Apple's libraries (downloadable from [its official repository](https://opensource.apple.com/tarballs/)).
See also the list of 3rd-party `objc4` ports as these must include those headers as well.
Below is list of those headers, where they are `#include`d and their original locations.

- `<System/pthread_machdep.h>` (e.g. in `objc-os.h`) - from `Libc-825.40.1/pthreads/pthread_machdep.h`.

### Building with Clang directly

Ideally, we would like to build this library with clang instead of Visual Studio (as it seems more appropriate and would be probably easier).
Currently, we use Clang with Visual Studio, which is some old version, though, so there are some errors.
To overcome them, just see the `Debug/objc.tlog/clang.command.*.log` files for information about what arguments to run clang with (but, of course, you need to first use Visual Studio to compile some files in order to generate this file).

[C++/WinRT](https://docs.microsoft.com/en-us/windows/uwp/cpp-and-winrt-apis/index) seems as the thing we would want to build against.
It's only header files, so it should be possible to use it from clang.
On the other side, it's very new, so we could probably support only very new versions of Windows.
But that's probably not a disadvantage, since with this we can port the `objc4` library fast and then worry about older versions later (or never, since it should be easy to update Windows 10).

> For more information about C++/WinRT, see also [Kenny Kerr's blog](https://kennykerr.ca/articles/) and [moderncpp.com](https://moderncpp.com/).

**TODO: Try `-###` option to see what SDK we really build against.**
