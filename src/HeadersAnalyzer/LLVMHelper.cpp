// LLVMHelper.cpp

#include "LLVMHelper.hpp"

#include "ErrorReporting.hpp"

#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/CommandLine.h>

using namespace llvm;
using namespace llvm::cl;

LLVMInitializer::LLVMInitializer() {
  InitializeAllTargetInfos();
  InitializeAllTargets();
  InitializeAllTargetMCs();
  InitializeAllAsmPrinters();
}

bool StringVector::loadConfigFile(StringRef File) {
  if (!readConfigFile(File, Saver, Vector)) {
    fatalError("couldn't load config file (" + File + ")");
    return false;
  }
  return true;
}
