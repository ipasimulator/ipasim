// LLVMHelper.cpp

#include "LLVMHelper.hpp"

#include "ErrorReporting.hpp"

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/TargetSelect.h>

using namespace llvm;
using namespace llvm::cl;

LLVMInitializer::LLVMInitializer() {
  InitializeAllTargetInfos();
  InitializeAllTargets();
  InitializeAllTargetMCs();
  InitializeAllAsmPrinters();
}

void StringVector::loadConfigFile(StringRef File) {
  if (!readConfigFile(File, Saver, Vector)) {
    reportFatalError("couldn't load config file (" + File + ")");
  }
}
