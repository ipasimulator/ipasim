# ipasim

[![Build status](https://dev.azure.com/ipasim/ipasim/_apis/build/status/ipasim-CI?branchName=master)](https://dev.azure.com/ipasim/ipasim/_build/latest?definitionId=1&branchName=master)

This repository contains source code of `ipasim`, an iOS emulator for Windows.
It takes a compiled iOS application and emulates it. However, only the
application's machine code is emulated, whereas system functionality originally
provided by iOS is translated to an equivalent functionality available on
Windows. [More detailed documentation](docs/README.md) is available.

## Cloning the repository

We use [Git Submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules)
(recursively), so make sure you clone with `--recurse-submodules`. We also use
[Git LFS](https://git-lfs.github.com/), so make sure you have that installed if
you want to get all files.

## Building and installation

If you want to use the emulator, you can either [build it from
sources](docs/build.md) (that's slow), [use partially prebuilt
artifacts](docs/artifacts.md) (that's fast and recommended if you want to make
changes; however, you still need to have Docker and Visual Studio installed) or
just [use prebuilt binaries](https://github.com/ipasimulator/ipasim/releases)
(recommended if you don't want to make changes).

## Directory structure

- [`deps`](deps) contains third-party dependencies (mostly as Git submodules because
  patching was necessary).
- [`docs`](docs) contains [documentation and issues](docs/README.md).
- [`include`](include) has C++ headers of the project.
- [`samples`](samples) contains sources of sample iOS applications and some other samples.
- [`scripts`](scripts) contains various scripts, mostly supporting build of the project.
- [`src`](src) contains C++ sources of the project.
  - [HeadersAnalyzer](src/HeadersAnalyzer/README.md) is a tool that runs at
    compile-time, generating supporting code for the emulator.
  - [IpaSimulator](src/IpaSimulator/README.md) is the emulator itself.
  - [objc](src/objc/README.md) contains our port of Apple's Objective-C
    runtime to Windows.

## Executive summary

[![Poster preview](docs/thesis/poster.png)](docs/thesis/poster.pdf)
