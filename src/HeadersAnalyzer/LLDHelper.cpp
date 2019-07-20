// LLDHelper.cpp: Implementation of class `LLDHelper`.

#include "ipasim/LLDHelper.hpp"

#include "ipasim/Output.hpp"

#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/Program.h>
#include <string>
#include <vector>

using namespace ipasim;
using namespace llvm;
using namespace std;
using namespace std::filesystem;

LLDHelper::LLDHelper(const path &BuildDir, LLVMHelper &LLVM)
    : Args(LLVM.Saver) {
  // First argument is expected to be an executable name.
  // TODO: See i26.
  Args.add(
      (BuildDir / "../clang-x86-Release/bin/ld64.lld.exe").string().c_str());
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
  // See i23.
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

  // Convert `const char *`s to `StringRef`s.
  llvm::SmallVector<StringRef, 256> ArgsRef;
  for (const char *Arg : Args.get())
    ArgsRef.push_back(Arg);

  if (llvm::sys::ExecuteAndWait(ArgsRef[0], ArgsRef)) {
    string CmdLine;
    for (StringRef Arg : ArgsRef)
      CmdLine = CmdLine + " " + Arg.str();
    Log.error() << "failed to execute:" << CmdLine << Log.end();
  }
}
