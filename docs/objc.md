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
Currently on x86, we build it against the MacOSX SDK (`/deps/headers/MacOS*.sdk/`), but there's also an alternative - to build it against the iPhoneSimulator SDK.
Although, there shouldn't be much difference, because the Objective-C runtime shouldn't depend on anything platform specific in those headers.
**TODO: Decide properly what SDK should we build against.**

### Preprocessor definitions

- `TARGET_OS_*` and `TARGET_CPU_*` - see `TargetConditionals.h` in MacOSX SDK for more information about these.
  The apps we are trying to emulate are iPhone apps, so we are defining `TARGET_OS_IOS` while building the `objc` runtime to simulate that environment.
- `__OBJC2__` - we are building the new runtime (which is the only one available on iPhones anyway).
