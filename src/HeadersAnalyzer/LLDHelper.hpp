// LLDHelper.hpp

#ifndef LLDHELPER_HPP
#define LLDHELPER_HPP

#include "LLVMHelper.hpp"

class LLDHelper {
public:
  LLDHelper(LLVMHelper &LLVM);

  StringVector Args;

  void addDylibArgs(llvm::StringRef Output, llvm::StringRef ObjectFile,
                    llvm::StringRef InstallName);
  void linkDylib(llvm::StringRef Output, llvm::StringRef ObjectFile,
                 llvm::StringRef InstallName);
  void executeArgs();
};

// !defined(LLDHELPER_HPP)
#endif
