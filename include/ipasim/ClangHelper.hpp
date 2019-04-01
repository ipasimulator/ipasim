// ClangHelper.hpp

#ifndef IPASIM_CLANG_HELPER_HPP
#define IPASIM_CLANG_HELPER_HPP

#include "ipasim/ErrorReporting.hpp"
#include "ipasim/LLVMHelper.hpp"

#include <CodeGen/CodeGenModule.h>
#include <clang/Frontend/CompilerInstance.h>

namespace ipasim {

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

} // namespace ipasim

// !defined(IPASIM_CLANG_HELPER_HPP)
#endif
