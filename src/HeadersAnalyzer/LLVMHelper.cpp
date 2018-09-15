// LLVMHelper.cpp

#include "LLVMHelper.hpp"

#include <llvm/Support/TargetSelect.h>

using namespace llvm;

LLVMInitializer::LLVMInitializer() {
  InitializeAllTargetInfos();
  InitializeAllTargets();
  InitializeAllTargetMCs();
  InitializeAllAsmPrinters();
}
