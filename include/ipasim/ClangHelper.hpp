// ClangHelper.hpp: Definition of class `ClangHelper`.

#ifndef IPASIM_CLANG_HELPER_HPP
#define IPASIM_CLANG_HELPER_HPP

#include "ipasim/LLVMHelper.hpp"
#include "ipasim/Output.hpp"

#include <CodeGen/CodeGenModule.h>
#include <clang/Frontend/CompilerInstance.h>
#include <filesystem>

namespace ipasim {

// Represents an instance of compiler Clang. Encapsulates common tasks that can
// be done using Clang. A common workflow is to populate `Args`, then initialize
// the compiler from them via `initFromInvocation` and finally call one of the
// `execute*` methods.
class ClangHelper {
public:
  ClangHelper(const std::filesystem::path &BuildDir, LLVMHelper &LLVM);

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
               llvm::StringRef ImportLib, bool Debug);
  void addDylibArgs(llvm::StringRef Output, llvm::StringRef ObjectFile,
                    llvm::StringRef InstallName);
  void linkDylib(llvm::StringRef Output, llvm::StringRef ObjectFile,
                 llvm::StringRef InstallName);
  void executeArgs();

private:
  LLVMHelper &LLVM;

  void executeAction(clang::FrontendAction &Act) {
    if (!CI.ExecuteAction(Act))
      Log.fatalError("cannot execute action");
  }
};

} // namespace ipasim

// !defined(IPASIM_CLANG_HELPER_HPP)
#endif
