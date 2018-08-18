@echo off
rem Try also `build.cmd -Wno-unused-command-line-argument -Wno-duplicate-decl-specifier`.

if exist ".\Debug\files.txt" del ".\Debug\files.txt"

set dir=objc4\runtime
call build_one.cmd objective-c++ hashtable2.mm %*
call build_one.cmd objective-c++ maptable.mm %*
call build_one.cmd objective-c++ NSObject.mm %*
call build_one.cmd objective-c++ objc-accessors.mm %*
call build_one.cmd objective-c++ objc-auto.mm %*
call build_one.cmd objective-c++ objc-block-trampolines.mm %*
call build_one.cmd objective-c++ objc-cache-old.mm %*
call build_one.cmd objective-c++ objc-cache.mm %*
call build_one.cmd objective-c++ objc-class-old.mm %*
call build_one.cmd objective-c++ objc-class.mm %*
call build_one.cmd objective-c++ objc-errors.mm %*
call build_one.cmd objective-c++ objc-exception.mm %*
call build_one.cmd objective-c++ objc-file-old.mm %*
call build_one.cmd objective-c++ objc-file.mm %*
call build_one.cmd objective-c++ objc-initialize.mm %*
call build_one.cmd objective-c++ objc-layout.mm %*
call build_one.cmd objective-c++ objc-load.mm %*
call build_one.cmd objective-c++ objc-loadmethod.mm %*
call build_one.cmd objective-c++ objc-lockdebug.mm %*
call build_one.cmd objective-c++ objc-opt.mm %*
call build_one.cmd objective-c++ objc-os.mm %*
call build_one.cmd objective-c++ objc-references.mm %*
call build_one.cmd objective-c++ objc-runtime-new.mm %*
call build_one.cmd objective-c++ objc-runtime-old.mm %*
call build_one.cmd objective-c++ objc-runtime.mm %*
call build_one.cmd objective-c++ objc-sel-old.mm %*
call build_one.cmd objective-c++ objc-sel-set.mm %*
call build_one.cmd objective-c++ objc-sel.mm %*
call build_one.cmd objective-c++ objc-sync.mm %*
call build_one.cmd objective-c++ objc-typeencoding.mm %*
call build_one.cmd objective-c++ objc-weak.mm %*
call build_one.cmd objective-c++ Object.mm %*
call build_one.cmd objective-c++ Protocol.mm %*
call build_one.cmd objective-c OldClasses.subproj\List.m %*
call build_one.cmd assembler-with-cpp Messengers.subproj\objc-msg-arm.s %*
call build_one.cmd assembler-with-cpp Messengers.subproj\objc-msg-arm64.s %*
call build_one.cmd assembler-with-cpp Messengers.subproj\objc-msg-i386.s %*
call build_one.cmd assembler-with-cpp Messengers.subproj\objc-msg-simulator-i386.s %*
call build_one.cmd assembler-with-cpp Messengers.subproj\objc-msg-simulator-x86_64.s %*
call build_one.cmd assembler-with-cpp Messengers.subproj\objc-msg-x86_64.s %*
call build_one.cmd assembler-with-cpp a1a2-blocktramps-arm.s %*
call build_one.cmd assembler-with-cpp a1a2-blocktramps-arm64.s %*
call build_one.cmd assembler-with-cpp a1a2-blocktramps-i386.s %*
call build_one.cmd assembler-with-cpp a1a2-blocktramps-x86_64.s %*
call build_one.cmd assembler-with-cpp a2a3-blocktramps-arm.s %*
call build_one.cmd assembler-with-cpp a2a3-blocktramps-i386.s %*
call build_one.cmd assembler-with-cpp a2a3-blocktramps-x86_64.s %*
call build_one.cmd assembler-with-cpp objc-sel-table.s %*

set dir=libclosure
call build_one.cmd c data.c %*
rem TODO: This should also be compiled as C.
call build_one.cmd c++ runtime.c %*

set dir=..\src\objc
call build_one.cmd objective-c++ dladdr.mm %*
call build_one.cmd objective-c++ getsecbyname.mm %*
call build_one.cmd objective-c++ cxxabi.mm %*
call build_one.cmd objective-c++ stubs.mm %*

call link.cmd
