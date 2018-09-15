// ClangHelper.cpp

#include "ClangHelper.hpp"

using namespace clang;
using namespace clang::CodeGen;
using namespace std;

ClangHelper::ClangHelper(LLVMHelper &LLVM) : LLVM(LLVM), Args(LLVM.Saver) {
  CI.createDiagnostics();
  // First argument is expected to be an executable name.
  Args.add("clang.exe");
}

void ClangHelper::initFromInvocation() {
  CI.setInvocation(createInvocationFromCommandLine(Args.get()));
}

unique_ptr<CodeGenModule> ClangHelper::createCodeGenModule() {
  CI.createASTContext();
  return std::make_unique<CodeGenModule>(
      CI.getASTContext(), CI.getHeaderSearchOpts(), CI.getPreprocessorOpts(),
      CI.getCodeGenOpts(), *LLVM.getModule(), CI.getDiagnostics());
}
