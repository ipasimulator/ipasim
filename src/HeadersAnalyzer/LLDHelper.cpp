// LLDHelper.cpp

#include "LLDHelper.hpp"

#include "ErrorReporting.hpp"

#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/Program.h>

#include <string>
#include <vector>

using namespace llvm;
using namespace std;

LLDHelper::LLDHelper(LLVMHelper &LLVM) : Args(LLVM.Saver) {
  // First argument is expected to be an executable name.
  // TODO: See #26.
  Args.add("../build/clang-x86-Release/bin/ld64.lld.exe");
}

// Inspired by what `ClangHelper::linkDylib` invokes.
void LLDHelper::addDylibArgs(StringRef Output, StringRef ObjectFile,
                             StringRef InstallName) {
  Args.add("-dynamic");
  Args.add("-dylib");
  Args.add("-arch");
  Args.add("armv7s");
  // Let's call this as the original DLL (in the Mach-O header), so
  // that our dynamic loader directly loads that.
  Args.add("-dylib_install_name");
  Args.add(InstallName.data());
  Args.add("-iphoneos_version_min");
  Args.add("10.0.0");
  Args.add("-o");
  Args.add(Output.data());
  Args.add(ObjectFile.data());
  // To suppress warning `-sdk_version is required when emitting min version
  // load command.  Setting sdk version to match provided min version`.
  Args.add("-no_version_load_command");
}
void LLDHelper::reexportLibrary(llvm::StringRef Name) {
  // See #23.
  Args.add("-reexport_library");
  Args.add(Name.data());
}
void LLDHelper::linkDylib(StringRef Output, StringRef ObjectFile,
                          StringRef InstallName) {
  addDylibArgs(Output, ObjectFile, InstallName);
  executeArgs();
}
void LLDHelper::executeArgs() {
  TerminationGuard TG(Args.terminate());
  auto ArgsRef(Args.get());
  int Argc = ArgsRef.size();
  auto Argv = const_cast<const char **>(ArgsRef.data());

  if (llvm::sys::ExecuteAndWait(ArgsRef[0], Argv)) {
    string CmdLine;
    for (const char *Arg : ArgsRef)
      CmdLine = CmdLine + " " + Arg;
    reportError(Twine("failed to execute:") + CmdLine);
  }
}