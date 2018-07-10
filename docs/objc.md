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
- [GitHub] [zhongwuzw's fork with comments for iOS ARM64](https://github.com/zhongwuzw/objc4-cn) (probably useless)

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

### Xamarin.iOS

- Not actually a runtime, but it's a notable exception and there is currently no better place for this.
- Xamarin.iOS is just a .NET wrapper around the Apple's Objective-C runtime.
  And [documentation about its internals](https://docs.microsoft.com/en-us/xamarin/ios/internals/) could be useful for us.
  For example, the [section about application startup](https://docs.microsoft.com/en-us/xamarin/ios/internals/architecture#application-launch) has useful information about how iOS apps starts, which surely is something our application needs to be aware of.

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

#### Constructing the command line

So, this is a command used for building the `hashtable2.mm` in Xcode on macOS:

```txt
/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -x objective-c++ -arch x86_64 -fmessage-length=0 -fdiagnostics-show-note-include-stack -fmacro-backtrace-limit=0 -std=gnu++11 -stdlib=libc++ -Wno-trigraphs -fno-exceptions -fno-rtti -fno-sanitize=vptr -fpascal-strings -O0 -Wno-missing-field-initializers -Wno-missing-prototypes -Wno-implicit-atomic-properties -Wno-arc-repeated-use-of-weak -Wno-non-virtual-dtor -Wno-overloaded-virtual -Wno-exit-time-destructors -Wno-missing-braces -Wparentheses -Wswitch -Wno-unused-function -Wno-unused-label -Wno-unused-parameter -Wunused-variable -Wunused-value -Wno-empty-body -Wno-uninitialized -Wno-unknown-pragmas -Wshadow -Wno-four-char-constants -Wno-conversion -Wno-constant-conversion -Wno-int-conversion -Wno-bool-conversion -Wno-enum-conversion -Wno-float-conversion -Wno-non-literal-null-conversion -Wno-objc-literal-conversion -Wshorten-64-to-32 -Wnewline-eof -Wno-selector -Wno-strict-selector-match -Wno-undeclared-selector -Wno-deprecated-implementations -Wno-c++11-extensions -DOS_OBJECT_USE_OBJC=0 -DLIBC_NO_LIBCRASHREPORTERCLIENT -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.13.sdk -fstrict-aliasing -Wprotocol -Wno-deprecated-declarations -Wno-invalid-offsetof -mmacosx-version-min=10.13 -g -fvisibility=hidden -fvisibility-inlines-hidden -Wno-sign-conversion -Wno-infinite-recursion -Wno-move -Wno-comma -Wno-block-capture-autoreleasing -Wno-strict-prototypes -Wno-range-loop-analysis -index-store-path /Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Index/DataStore -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/objc.A.hmap -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/include -I/tmp/objc.dst/usr/include -I/tmp/objc.dst/usr/local/include -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/include -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/include/objc -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/local/include -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/local/include/objc -I/System/Library/Frameworks/System.framework/PrivateHeaders -I/Users/janjones/Documents/objc4/objc4/../macosx.internal/System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/DerivedSources/x86_64 -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/DerivedSources -Wall -Wextra -Wstrict-aliasing=2 -Wstrict-overflow=4 -Wno-unused-parameter -Wno-deprecated-objc-isa-usage -Wno-cast-of-sel-type -F/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug -fdollars-in-identifiers -fobjc-legacy-dispatch -D_LIBCPP_VISIBLE= -MMD -MT dependencies -MF /Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/x86_64/hashtable2.d --serialize-diagnostics /Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/x86_64/hashtable2.dia -c /Users/janjones/Documents/objc4/objc4/runtime/hashtable2.mm -o /Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/x86_64/hashtable2.o
```

And this is what it shows with `-###` argument:

```txt
Apple LLVM version 9.0.0 (clang-900.0.38)
Target: x86_64-apple-darwin17.2.0
Thread model: posix
InstalledDir: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin
 "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang" "-cc1" "-triple" "x86_64-apple-macosx10.13.0" "-Wdeprecated-objc-isa-usage" "-Werror=deprecated-objc-isa-usage" "-emit-obj" "-mrelax-all" "-disable-free" "-disable-llvm-verifier" "-discard-value-names" "-main-file-name" "hashtable2.mm" "-mrelocation-model" "pic" "-pic-level" "2" "-mthread-model" "posix" "-mdisable-fp-elim" "-fno-strict-return" "-masm-verbose" "-munwind-tables" "-target-cpu" "penryn" "-target-linker-version" "302.3.1" "-dwarf-column-info" "-debug-info-kind=standalone" "-dwarf-version=4" "-debugger-tuning=lldb" "-coverage-notes-file" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/x86_64/hashtable2.gcno" "-resource-dir" "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/9.0.0" "-index-store-path" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Index/DataStore" "-dependency-file" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/x86_64/hashtable2.d" "-MT" "dependencies" "-isysroot" "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.13.sdk" "-D" "OS_OBJECT_USE_OBJC=0" "-D" "LIBC_NO_LIBCRASHREPORTERCLIENT" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/objc.A.hmap" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/include" "-I" "/tmp/objc.dst/usr/include" "-I" "/tmp/objc.dst/usr/local/include" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/include" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/include/objc" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/local/include" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/local/include/objc" "-I" "/System/Library/Frameworks/System.framework/PrivateHeaders" "-I" "/Users/janjones/Documents/objc4/objc4/../macosx.internal/System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/DerivedSources/x86_64" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/DerivedSources" "-F/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug" "-D" "_LIBCPP_VISIBLE=" "-stdlib=libc++" "-O0" "-Wno-trigraphs" "-Wno-missing-field-initializers" "-Wno-missing-prototypes" "-Wno-implicit-atomic-properties" "-Wno-arc-repeated-use-of-weak" "-Wno-non-virtual-dtor" "-Wno-overloaded-virtual" "-Wno-exit-time-destructors" "-Wno-missing-braces" "-Wparentheses" "-Wswitch" "-Wno-unused-function" "-Wno-unused-label" "-Wno-unused-parameter" "-Wunused-variable" "-Wunused-value" "-Wno-empty-body" "-Wno-uninitialized" "-Wno-unknown-pragmas" "-Wshadow" "-Wno-four-char-constants" "-Wno-conversion" "-Wno-constant-conversion" "-Wno-int-conversion" "-Wno-bool-conversion" "-Wno-enum-conversion" "-Wno-float-conversion" "-Wno-non-literal-null-conversion" "-Wno-objc-literal-conversion" "-Wshorten-64-to-32" "-Wnewline-eof" "-Wno-selector" "-Wno-strict-selector-match" "-Wno-undeclared-selector" "-Wno-deprecated-implementations" "-Wno-c++11-extensions" "-Wprotocol" "-Wno-deprecated-declarations" "-Wno-invalid-offsetof" "-Wno-sign-conversion" "-Wno-infinite-recursion" "-Wno-move" "-Wno-comma" "-Wno-block-capture-autoreleasing" "-Wno-strict-prototypes" "-Wno-range-loop-analysis" "-Wall" "-Wextra" "-Wstrict-aliasing=2" "-Wstrict-overflow=4" "-Wno-unused-parameter" "-Wno-deprecated-objc-isa-usage" "-Wno-cast-of-sel-type" "-std=gnu++11" "-fdeprecated-macro" "-fdebug-compilation-dir" "/Users/janjones/Documents/objc4/objc4" "-ferror-limit" "19" "-fmacro-backtrace-limit" "0" "-fmessage-length" "0" "-fvisibility" "hidden" "-fvisibility-inlines-hidden" "-stack-protector" "1" "-fblocks" "-fno-rtti" "-fobjc-runtime=macosx-10.13.0" "-fencode-extended-block-signature" "-fobjc-exceptions" "-fexceptions" "-fpascal-strings" "-fmax-type-align=16" "-fdiagnostics-show-option" "-fdiagnostics-show-note-include-stack" "-fcolor-diagnostics" "-fdollars-in-identifiers" "-serialize-diagnostic-file" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/x86_64/hashtable2.dia" "-o" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/x86_64/hashtable2.o" "-x" "objective-c++" "/Users/janjones/Documents/objc4/objc4/runtime/hashtable2.mm"
```

This is command and it's output with `-###` for building `assembler-with-cpp`:

```txt
/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -x assembler-with-cpp -arch i386 -fmessage-length=0 -fdiagnostics-show-note-include-stack -fmacro-backtrace-limit=0 -Wno-trigraphs -fpascal-strings -O0 -Wno-missing-field-initializers -Wno-missing-prototypes -Wno-missing-braces -Wparentheses -Wswitch -Wno-unused-function -Wno-unused-label -Wno-unused-parameter -Wunused-variable -Wunused-value -Wno-empty-body -Wno-uninitialized -Wno-unknown-pragmas -Wshadow -Wno-four-char-constants -Wno-conversion -Wno-constant-conversion -Wno-int-conversion -Wno-bool-conversion -Wno-enum-conversion -Wno-float-conversion -Wno-non-literal-null-conversion -Wno-objc-literal-conversion -Wshorten-64-to-32 -Wnewline-eof -DOS_OBJECT_USE_OBJC=0 -DLIBC_NO_LIBCRASHREPORTERCLIENT -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.13.sdk -fstrict-aliasing -Wno-deprecated-declarations -mmacosx-version-min=10.13 -g -fvisibility=hidden -Wno-sign-conversion -Wno-infinite-recursion -Wno-comma -Wno-block-capture-autoreleasing -Wno-strict-prototypes -index-store-path /Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Index/DataStore -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/objc.A.hmap -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/include -I/tmp/objc.dst/usr/include -I/tmp/objc.dst/usr/local/include -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/include -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/include/objc -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/local/include -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/local/include/objc -I/System/Library/Frameworks/System.framework/PrivateHeaders -I/Users/janjones/Documents/objc4/objc4/../macosx.internal/System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/DerivedSources/i386 -I/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/DerivedSources -Wall -Wextra -Wstrict-aliasing=2 -Wstrict-overflow=4 -Wno-unused-parameter -Wno-deprecated-objc-isa-usage -Wno-cast-of-sel-type -F/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug -fdollars-in-identifiers -MMD -MT dependencies -MF /Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/i386/a1a2-blocktramps-i386.d --serialize-diagnostics /Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/i386/a1a2-blocktramps-i386.dia -c /Users/janjones/Documents/objc4/objc4/runtime/a1a2-blocktramps-i386.s -o /Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/i386/a1a2-blocktramps-i386.o -###
Apple LLVM version 9.0.0 (clang-900.0.38)
Target: i386-apple-darwin17.2.0
Thread model: posix
InstalledDir: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin
 "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang" "-cc1" "-triple" "i386-apple-macosx10.13.0" "-E" "-disable-free" "-disable-llvm-verifier" "-discard-value-names" "-main-file-name" "a1a2-blocktramps-i386.s" "-mrelocation-model" "pic" "-pic-level" "2" "-mthread-model" "posix" "-mdisable-fp-elim" "-fno-strict-return" "-masm-verbose" "-target-cpu" "penryn" "-target-linker-version" "302.3.1" "-dwarf-column-info" "-debug-info-kind=standalone" "-dwarf-version=4" "-debugger-tuning=lldb" "-coverage-notes-file" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/i386/a1a2-blocktramps-i386.gcno" "-resource-dir" "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/9.0.0" "-index-store-path" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Index/DataStore" "-dependency-file" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/i386/a1a2-blocktramps-i386.d" "-MT" "dependencies" "-isysroot" "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.13.sdk" "-D" "OS_OBJECT_USE_OBJC=0" "-D" "LIBC_NO_LIBCRASHREPORTERCLIENT" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/objc.A.hmap" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/include" "-I" "/tmp/objc.dst/usr/include" "-I" "/tmp/objc.dst/usr/local/include" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/include" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/include/objc" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/local/include" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/local/include/objc" "-I" "/System/Library/Frameworks/System.framework/PrivateHeaders" "-I" "/Users/janjones/Documents/objc4/objc4/../macosx.internal/System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/DerivedSources/i386" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/DerivedSources" "-F/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug" "-O0" "-Wno-trigraphs" "-Wno-missing-field-initializers" "-Wno-missing-prototypes" "-Wno-missing-braces" "-Wparentheses" "-Wswitch" "-Wno-unused-function" "-Wno-unused-label" "-Wno-unused-parameter" "-Wunused-variable" "-Wunused-value" "-Wno-empty-body" "-Wno-uninitialized" "-Wno-unknown-pragmas" "-Wshadow" "-Wno-four-char-constants" "-Wno-conversion" "-Wno-constant-conversion" "-Wno-int-conversion" "-Wno-bool-conversion" "-Wno-enum-conversion" "-Wno-float-conversion" "-Wno-non-literal-null-conversion" "-Wno-objc-literal-conversion" "-Wshorten-64-to-32" "-Wnewline-eof" "-Wno-deprecated-declarations" "-Wno-sign-conversion" "-Wno-infinite-recursion" "-Wno-comma" "-Wno-block-capture-autoreleasing" "-Wno-strict-prototypes" "-Wall" "-Wextra" "-Wstrict-aliasing=2" "-Wstrict-overflow=4" "-Wno-unused-parameter" "-Wno-deprecated-objc-isa-usage" "-Wno-cast-of-sel-type" "-fdebug-compilation-dir" "/Users/janjones/Documents/objc4/objc4" "-ferror-limit" "19" "-fmacro-backtrace-limit" "0" "-fmessage-length" "0" "-fvisibility" "hidden" "-stack-protector" "1" "-fblocks" "-fobjc-runtime=macosx-fragile-10.13.0" "-fobjc-subscripting-legacy-runtime" "-fencode-extended-block-signature" "-fpascal-strings" "-fmax-type-align=16" "-fdiagnostics-show-option" "-fdiagnostics-show-note-include-stack" "-fcolor-diagnostics" "-fdollars-in-identifiers" "-serialize-diagnostic-file" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/i386/a1a2-blocktramps-i386.dia" "-o" "/var/folders/gy/b6kvdlzx3p93q6pq914m13780000gn/T/a1a2-blocktramps-i386-8043d7.s" "-x" "assembler-with-cpp" "/Users/janjones/Documents/objc4/objc4/runtime/a1a2-blocktramps-i386.s"
 "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang" "-cc1as" "-triple" "i386-apple-macosx10.13.0" "-filetype" "obj" "-main-file-name" "a1a2-blocktramps-i386.s" "-target-cpu" "penryn" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/objc.A.hmap" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/include" "-I" "/tmp/objc.dst/usr/include" "-I" "/tmp/objc.dst/usr/local/include" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/include" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/include/objc" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/local/include" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/local/include/objc" "-I" "/System/Library/Frameworks/System.framework/PrivateHeaders" "-I" "/Users/janjones/Documents/objc4/objc4/../macosx.internal/System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/DerivedSources/i386" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/DerivedSources" "-fdebug-compilation-dir" "/Users/janjones/Documents/objc4/objc4" "-dwarf-debug-producer" "Apple LLVM version 9.0.0 (clang-900.0.38)" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/objc.A.hmap" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/include" "-I" "/tmp/objc.dst/usr/include" "-I" "/tmp/objc.dst/usr/local/include" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/include" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/include/objc" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/local/include" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Products/Debug/usr/local/include/objc" "-I" "/System/Library/Frameworks/System.framework/PrivateHeaders" "-I" "/Users/janjones/Documents/objc4/objc4/../macosx.internal/System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/DerivedSources/i386" "-I" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/DerivedSources" "-debug-info-kind=limited" "-dwarf-version=4" "-mrelocation-model" "pic" "-o" "/Users/janjones/Library/Developer/Xcode/DerivedData/objc-bcczfbwxouyyjgemmfuwbzzgixlw/Build/Intermediates.noindex/objc.build/Debug/objc.build/Objects-normal/i386/a1a2-blocktramps-i386.o" "/var/folders/gy/b6kvdlzx3p93q6pq914m13780000gn/T/a1a2-blocktramps-i386-8043d7.s"
```

Now we try to construct a command for clang on Windows along with descriptions for each argument.

- `-x objective-c++`
- `-arch x86_64` - **TODO: If we change this to e.g. arm, should we also change something else?**
- `-std=gnu++11 -stdlib=libc++` - in the macOS command.
- `-fno-exceptions -fno-rtti -fno-sanitize=vptr -fpascal-strings` - same.

**TODO: Not complete!**

This is command built via copy from macOS command:

```txt
clang -x objective-c++ -arch x86_64 -fmessage-length=0 -fdiagnostics-show-note-include-stack -fmacro-backtrace-limit=0 -std=gnu++11 -stdlib=libc++ -Wno-trigraphs -fno-exceptions -fno-rtti -fno-sanitize=vptr -fpascal-strings -O0 -Wno-missing-field-initializers -Wno-missing-prototypes -Wno-implicit-atomic-properties -Wno-arc-repeated-use-of-weak -Wno-non-virtual-dtor -Wno-overloaded-virtual -Wno-exit-time-destructors -Wno-missing-braces -Wparentheses -Wswitch -Wno-unused-function -Wno-unused-label -Wno-unused-parameter -Wunused-variable -Wunused-value -Wno-empty-body -Wno-uninitialized -Wno-unknown-pragmas -Wshadow -Wno-four-char-constants -Wno-conversion -Wno-constant-conversion -Wno-int-conversion -Wno-bool-conversion -Wno-enum-conversion -Wno-float-conversion -Wno-non-literal-null-conversion -Wno-objc-literal-conversion -Wshorten-64-to-32 -Wnewline-eof -Wno-selector -Wno-strict-selector-match -Wno-undeclared-selector -Wno-deprecated-implementations -Wno-c++11-extensions -DOS_OBJECT_USE_OBJC=0 -DLIBC_NO_LIBCRASHREPORTERCLIENT -fstrict-aliasing -Wprotocol -Wno-deprecated-declarations -Wno-invalid-offsetof -mmacosx-version-min=10.13 -g -fvisibility=hidden -fvisibility-inlines-hidden -Wno-sign-conversion -Wno-infinite-recursion -Wno-move -Wno-comma -Wno-block-capture-autoreleasing -Wno-strict-prototypes -Wno-range-loop-analysis -Wall -Wextra -Wstrict-aliasing=2 -Wstrict-overflow=4 -Wno-unused-parameter -Wno-deprecated-objc-isa-usage -Wno-cast-of-sel-type -fdollars-in-identifiers -fobjc-legacy-dispatch -D_LIBCPP_VISIBLE= -MMD -MT dependencies -o ".\Debug\hashtable2_418C34B7.obj" -c "..\..\deps\objc4\runtime\hashtable2.mm"
```

Now (July 2018), we are going to use this command as a base and we will add other options to it (see `build_one.cmd` file for the result).

- `-target "i386-pc-windows-msvc"` - let's just try to build for x86 first.
  `-target "i386-apple-macosx10.13.0"` is used for language `assembler-with-cpp` since the original assembler uses directives only valid for Mach-O files and this option will generate Mach-O output for us.
  We then convert this Mach-O file to PE format using tool [objconv](www.agner.org/optimize/#objconv).
  **TODO: Add instructions on how to get the tool to section Dependencies, or include it via Git LFS.**
- `-std=c++14` - because we use MSVC C++ std library which uses C++14 features.
  This is only included if the language is `objective-c++`.
- `-fblocks` - needed and also can be found in the listing from `-###` above.
  **TODO: What other things differ between the listing with and without `-###`?**
- `-fobjc-runtime=macosx-10.13.0` - to compile against the Apple's runtime API.
  Otherwise, GCC runtime would be used (probably because of the `-target` option).
- `-DOBJC_PORT` - our flag that enables changes made by us to port the code.
- `-D__OBJC2__=1` - we want to build the "new" runtime (which is used on iPhones).
- `-DHAVE_STRUCT_TIMESPEC` - so that pthreads-win32 library doesn't redefine `struct timespec`.
- `-DNOMINMAX` - there are no `min` and `max` macros on macOS, so we don't want them either.
- `-Wno-nullability-completeness` - whatever, deal with those later.
- `-I ".\include"` - this folder contains our proxy headers.
- `-I "..\..\deps\apple-headers"` - this folder contains the real headers referenced by our proxy headers.
- `-I "..\..\deps\pthreads.2"` - for `pthread.h`.

These were removed:

- `-fno-rtti` - MSVC C++ headers use `typeid`, so they need RTTI.
- `-std=gnu++11` - we use our own `-std`.
- `-arch x86_64` - we use our own architecture inside `-target`.

**TODO: Do this with CMake.**
**TODO: Use toolchains for different arm and x86 configurations.**

Building linking command similarily (see `link.cmd`):

- `-nologo` - be quiet.
- `-dll` - we want a DLL.
- `-force:multiple` - ignore duplicate definitions.
  **TODO: Don't do this.**
- `-defaultlib:libcmt.lib` - include C Runtime (for `malloc` and related).
- `".\Debug\blocksruntime.lib"` - include `BlocksRuntime` (built by `build_blocksruntime.cmd`).
- `"..\..\Debug\pthread\pthread.lib"` - pthreads-win32 library.
  **TODO: This must currently be built using Visual Studio.
  Build it with scripts as others.**
- `@".\Debug\files.txt"` - this is the list of `.obj` files generated by `build.cmd` (both the list and the `.obj` files are generated by `build.cmd`).

### Command keywords

- `[no-direct-keys]` - `pthread_key_t` (and it's equivalent `tls_key_t`) are integers on macOS, but not in pthreads-win32, so we cannot use integers for them as the original code does.
- `[format-error-pthread-self]` - There is a format error with `phtread_self()` - original code supposed it returns a pointer, which it doesn't in pthreads-win32.
- `[use-unicorn-alloc]` - Maybe use unicorn's allocation engine instead.
- `[angle-brackets]` - We want to use `"..."` includes instead of `<objc/...>` ones.

**TODO: Maybe implement POSIX functions via Cygwin or something like that...**
