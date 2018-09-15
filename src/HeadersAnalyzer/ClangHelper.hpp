// ClangHelper.hpp

#ifndef CLANGHELPER_HPP
#define CLANGHELPER_HPP

#include "ErrorReporting.hpp"
#include "LLVMHelper.hpp"

#include <clang/Frontend/CompilerInstance.h>

class ClangHelper {
public:
  ClangHelper(LLVMHelper &LLVM);

  clang::CompilerInstance CI;
  StringVector Args;

  void initFromInvocation();
  template <typename ActTy> void executeAction() {
    ActTy Act(&LLVM.Ctx);
    if (!CI.ExecuteAction(Act))
      reportFatalError("cannot execute action");
    LLVM.setModule(Act.takeModule());
  }

private:
  LLVMHelper &LLVM;
};

// !defined(CLANGHELPER_HPP)
#endif
