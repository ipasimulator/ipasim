# ipasim

[![Build status](https://img.shields.io/azure-devops/build/ipasim/ipasim/1/master)](https://dev.azure.com/ipasim/ipasim/_build/latest?definitionId=1&branchName=master)
[![Downloads](https://img.shields.io/github/downloads/ipasimulator/ipasim/total)](https://github.com/ipasimulator/ipasim/releases)

This repository contains source code of `ipasim`, an iOS emulator for Windows.
It takes a compiled iOS application and emulates it. However, only the
application's machine code is emulated, whereas system functionality originally
provided by iOS is translated to an equivalent functionality available on
Windows. [More detailed documentation](docs/README.md) is available.

## Project status

Currently, only simple applications can be emulated. Working samples can be
found in folder [`samples`](samples). For more information about (un)implemented
features, see [author's thesis](docs/thesis/README.md), its *Conclusion* in
particular.

### Related work

- [touchHLE](https://github.com/hikari-no-yume/touchHLE) (2023)

## Cloning the repository

We use [Git Submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules)
(recursively), so make sure you clone with `--recurse-submodules`. We also use
[Git LFS](https://git-lfs.github.com/), so make sure you have that installed if
you want to get all files. You might also want to use `--depth 1` for a faster
checkout.

## Building and installation

If you want to use the emulator, you can either [build it from
sources](docs/build.md) (that's slow), [use partially prebuilt
artifacts](docs/artifacts.md) (that's fast and recommended if you want to make
changes; however, you still need to have Docker and Visual Studio installed) or
just [use prebuilt binaries](docs/install.md) (recommended if you don't want to
make changes).

## Directory structure

- [`deps`](deps) contains third-party dependencies (mostly as Git submodules
  because patching was necessary).
- [`docs`](docs) contains [documentation and issues](docs/README.md).
- [`include`](include) has C++ headers of the project.
- [`samples`](samples) contains sources of sample iOS applications and some
  other samples.
- [`scripts`](scripts) contains various scripts, mostly supporting build of the
  project.
- [`src`](src) contains C++ sources of the project.
  - [HeadersAnalyzer](src/HeadersAnalyzer/README.md) is a tool that runs at
    compile-time, generating supporting code for the emulator.
  - [IpaSimulator](src/IpaSimulator/README.md) is the emulator itself.
  - [objc](src/objc/README.md) contains our port of Apple's Objective-C
    runtime to Windows.

## Executive summary

[![Poster preview](docs/thesis/poster.png)](docs/thesis/poster.pdf)

## Research

- [iOS emulator for Windows](docs/thesis/README.md), a bachelor thesis of [Jan
  Joneš](https://github.com/jjonescz).
