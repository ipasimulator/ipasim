// ClangHelper.hpp

#ifndef CLANGHELPER_HPP
#define CLANGHELPER_HPP

#include "LLVMHelper.hpp"

#include <clang/Frontend/CompilerInstance.h>

class ClangHelper {
public:
  ClangHelper(LLVMHelper &LLVM);

  clang::CompilerInstance CI;
  StringVector Args;

  void initFromInvocation();
  template <typename ActTy> bool executeAction() {
    ActTy Act(&LLVM.Ctx);
    if (!CI.ExecuteAction(Act))
      return false;
    LLVM.setModule(Act.takeModule());
    return true;
  }

private:
  LLVMHelper &LLVM;
};

// !defined(CLANGHELPER_HPP)
#endif
