// ClangHelper.hpp

#ifndef CLANGHELPER_HPP
#define CLANGHELPER_HPP

#include "ErrorReporting.hpp"
#include "LLVMHelper.hpp"

#include <CodeGen/CodeGenModule.h>
#include <clang/Frontend/CompilerInstance.h>

class ClangHelper {
public:
  ClangHelper(LLVMHelper &LLVM);

  clang::CompilerInstance CI;
  StringVector Args;

  void initFromInvocation();
  template <typename ActTy> void executeAction() {
    ActTy Act;
    executeAction(Act);
  }
  template <typename ActTy> void executeCodeGenAction() {
    ActTy Act(&LLVM.Ctx);
    executeAction(Act);
    LLVM.setModule(Act.takeModule());
  }
  std::unique_ptr<clang::CodeGen::CodeGenModule> createCodeGenModule();
  void linkDLL(llvm::StringRef Output, llvm::StringRef ObjectFile,
               llvm::StringRef ImportLib);
  void addDylibArgs(llvm::StringRef Output, llvm::StringRef ObjectFile,
                    llvm::StringRef InstallName);
  void linkDylib(llvm::StringRef Output, llvm::StringRef ObjectFile,
                 llvm::StringRef InstallName);
  void executeArgs();

private:
  LLVMHelper &LLVM;

  void executeAction(clang::FrontendAction &Act) {
    if (!CI.ExecuteAction(Act))
      reportFatalError("cannot execute action");
  }
};

// !defined(CLANGHELPER_HPP)
#endif
