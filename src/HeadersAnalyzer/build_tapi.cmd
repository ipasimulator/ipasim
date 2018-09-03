@echo off

set TABLEGEN=clang
call tblgen_one.cmd Driver\DiagnosticTAPIKinds -gen-clang-diags-defs

set TABLEGEN=llvm
call tblgen_one.cmd Driver\TAPIOptions -gen-opt-parser-defs
