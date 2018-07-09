@echo off
call build_one.cmd hashtable2.mm %*
call build_one.cmd maptable.mm %*
call build_one.cmd NSObject.mm %*
call build_one.cmd objc-accessors.mm %*
call build_one.cmd objc-auto.mm %*
call build_one.cmd objc-block-trampolines.mm %*
call build_one.cmd objc-cache-old.mm %*
call build_one.cmd objc-cache.mm %*
call build_one.cmd objc-class-old.mm %*
call build_one.cmd objc-class.mm %*
call build_one.cmd objc-errors.mm %*
call build_one.cmd objc-exception.mm %*
call build_one.cmd objc-file-old.mm %*
call build_one.cmd objc-file.mm %*
