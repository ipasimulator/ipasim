// ClangHelper.cpp

#include "ClangHelper.hpp"

using namespace clang;

ClangHelper::ClangHelper(LLVMHelper &LLVM) : LLVM(LLVM), Args(LLVM.Saver) {
  CI.createDiagnostics();
  // First argument is expected to be an executable name.
  Args.add("clang.exe");
}

void ClangHelper::initFromInvocation() {
  CI.setInvocation(createInvocationFromCommandLine(Args.get()));
}
