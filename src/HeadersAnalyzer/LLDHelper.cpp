// LLDHelper.cpp

#include "LLDHelper.hpp"

#include <lld/Common/Driver.h>

#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/InitLLVM.h>

#include <vector>

using namespace lld;
using namespace llvm;

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

  std::vector<const char *> ArgsVec(Argv, Argv + Argc);
  mach_o::link(ArgsVec);
}
