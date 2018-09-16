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
  if (!CI.hasASTContext())
    CI.createASTContext();
  if (!LLVM.getModule())
    LLVM.setModule(std::make_unique<llvm::Module>("CGM", LLVM.Ctx));

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
void ClangHelper::addDylibArgs(StringRef Output, StringRef ObjectFile,
                               StringRef InstallName) {
  Args.add("-target");
  Args.add(IRHelper::Apple);
  Args.add("-fuse-ld=lld");
  Args.add("-shared");
  Args.add("-o");
  Args.add(Output.data());
  Args.add(ObjectFile.data());
  // Don't emit error that symbol `dyld_stub_binder` is undefined.
  Args.add("-undefined");
  Args.add("-warning");
  // But to do that, we cannot use two-level namespace.
  Args.add("-flat_namespace");
  // See [no-lsystem].
  Args.add("-no_lsystem");
  // Let's call this as the original DLL (in the Mach-O header), so
  // that our dynamic loader directly loads that.
  Args.add("-install_name");
  Args.add(InstallName.data());
}
void ClangHelper::linkDylib(StringRef Output, StringRef ObjectFile,
                            StringRef InstallName) {
  addDylibArgs(Output, ObjectFile, InstallName);
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
