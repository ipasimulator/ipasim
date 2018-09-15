// ClangHelper.cpp

#include "ClangHelper.hpp"

#include <clang/Driver/Compilation.h>
#include <clang/Driver/Driver.h>

using namespace clang;
using namespace clang::CodeGen;
using namespace clang::driver;
using namespace std;
using namespace llvm;

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

void ClangHelper::linkDLL(StringRef Output, StringRef ObjectFile,
                          StringRef ImportLib) {
  Args.add("-shared");
  Args.add("-o");
  Args.add(Output.data());
  Args.add(ObjectFile.data());
  Args.add(ImportLib.data());

  executeArgs();
}

void ClangHelper::executeArgs() {
  // Inspired by `createInvocationFromCommandLine`.
  auto ArgsRef(Args.get());
  Driver TheDriver(ArgsRef[0], llvm::sys::getDefaultTargetTriple(),
                   CI.getDiagnostics());
  unique_ptr<Compilation> C(TheDriver.BuildCompilation(ArgsRef));
  if (!C || C->containsError()) {
    reportError("cannot build `Compilation`");
    return;
  }
  SmallVector<pair<int, const Command *>, 4> FailingCommands;
  if (TheDriver.ExecuteCompilation(*C, FailingCommands)) {
    reportError("failed to execute compilation");
    return;
  }
}
