# ipasim

[![Build Status](https://jjones.visualstudio.com/IPASimulator/_apis/build/status/ipasim-CI?branchName=master)](https://jjones.visualstudio.com/IPASimulator/_build/latest?definitionId=19&branchName=master)

This repository contains source code of `ipasim`, an iOS emulator for Windows.
More detailed documentation [is available](docs/README.md).

## Directory structure

- `contrib` contains patches to third-party dependencies.
- `deps` contains third-party dependencies (mostly as Git submodules because
  patching was necessary).
- `docs` contains [documentation and issues](docs/README.md).
- `include` has C++ headers of the project.
- `samples` contains sources of sample iOS applications and some other samples.
- `scripts` contains various scripts, mostly supporting build of the project.
- `src` contains C++ sources of the project.
  - [HeadersAnalyzer](src/HeadersAnalyzer/README.md) is a tool that runs at
    compile-time, generating supporting code for the emulator.
  - [IpaSimulator](src/IpaSimulator/README.md) is the emulator itself.
  - [objc](src/objc/README.md) contains our port of Apple's Objective-C
    runtime to Windows.
