// LLDHelper.hpp

#ifndef IPASIM_LLD_HELPER_HPP
#define IPASIM_LLD_HELPER_HPP

#include "ipasim/LLVMHelper.hpp"

namespace ipasim {

class LLDHelper {
public:
  LLDHelper(LLVMHelper &LLVM);

  StringVector Args;

  void addDylibArgs(llvm::StringRef Output, llvm::StringRef ObjectFile,
                    llvm::StringRef InstallName);
  void reexportLibrary(llvm::StringRef Name);
  void linkDylib(llvm::StringRef Output, llvm::StringRef ObjectFile,
                 llvm::StringRef InstallName);
  void executeArgs();
};

} // namespace ipasim

// !defined(IPASIM_LLD_HELPER_HPP)
#endif
