// ClangHelper.cpp

#include "ipasim/ClangHelper.hpp"

#include "ipasim/HeadersAnalyzer/Config.hpp"

#include <clang/Driver/Compilation.h>
#include <clang/Driver/Driver.h>

using namespace clang;
using namespace clang::CodeGen;
using namespace clang::driver;
using namespace ipasim;
using namespace std;
using namespace std::filesystem;
using namespace llvm;

ClangHelper::ClangHelper(const path &BuildDir, LLVMHelper &LLVM)
    : LLVM(LLVM), Args(LLVM.Saver) {
  CI.createDiagnostics();
  // First argument is expected to be an executable name.
  // TODO: See #26.
  Args.add((BuildDir / "../clang-x86-Release/bin/clang.exe").string().c_str());
  if constexpr (VerboseClang)
    Args.add("-v");
}

void ClangHelper::initFromInvocation() {
  // TODO: No diagnostics options set at the beginning (like ignore unknown
  // arguments, etc.). How should that be done?
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
                          StringRef ImportLib, bool Debug) {
  Args.add("-shared");
  Args.add("-o");
  Args.add(Output.data());
  Args.add(ObjectFile.data());
  Args.add(ImportLib.data());
  // See #25.
  Args.add("-nostdlib");
  if (Debug)
    Args.add("-Wl,-defaultlib:msvcrtd");
  else
    Args.add("-Wl,-defaultlib:msvcrt");

  executeArgs();
}
// TODO: Not currently used (but it's referenced from a comment at
// `LLDHelper::addDylibArgs`).
void ClangHelper::addDylibArgs(StringRef Output, StringRef ObjectFile,
                               StringRef InstallName) {
  Args.add("-target");
  Args.add(IRHelper::Apple);
  Args.add("-fuse-ld=lld");
  Args.add("-shared");
  Args.add("-o");
  Args.add(Output.data());
  Args.add(ObjectFile.data());
  // See [no-lsystem].
  Args.add("-no_lsystem");
  // Let's call this as the original DLL (in the Mach-O header), so
  // that our dynamic loader directly loads that.
  Args.add("-install_name");
  Args.add(InstallName.data());
  // To suppress warning `-sdk_version is required when emitting min version
  // load command.  Setting sdk version to match provided min version`.
  Args.add("-Wl,-no_version_load_command");
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
    Log.error("cannot build `Compilation`");
    return;
  }
  SmallVector<pair<int, const Command *>, 4> FailingCommands;
  if (TheDriver.ExecuteCompilation(*C, FailingCommands) ||
      !FailingCommands.empty()) {
    string CmdLine;
    for (const char *Arg : ArgsRef)
      CmdLine = CmdLine + " " + Arg;
    Log.error() << "failed to execute:" << CmdLine << Log.end();
    return;
  }
}
