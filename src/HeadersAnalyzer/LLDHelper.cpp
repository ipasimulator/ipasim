// LLDHelper.cpp

#include "LLDHelper.hpp"

#include "ErrorReporting.hpp"

#include <lld/Common/Driver.h>

#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/InitLLVM.h>

#include <string>
#include <vector>

using namespace lld;
using namespace llvm;
using namespace std;

LLDHelper::LLDHelper(LLVMHelper &LLVM) : Args(LLVM.Saver) {
  // First argument is expected to be an executable name.
  Args.add("ld64.lld.exe");
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
// Inspired by `lld.cpp`.
void LLDHelper::executeArgs() {
  auto ArgsRef(Args.get());
  int Argc = ArgsRef.size();
  auto Argv = const_cast<const char **>(ArgsRef.data());

  // TODO: Make this work.
  // InitLLVM X(Argc, Argv);

  vector<const char *> ArgsVec(Argv, Argv + Argc);
  if (!mach_o::link(ArgsVec)) {
    string CmdLine;
    for (const char *Arg : ArgsVec)
      CmdLine = CmdLine + " " + Arg;
    reportError(Twine("failed to execute:") + CmdLine);
  }
}
