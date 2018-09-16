// LLVMHelper.cpp

#include "LLVMHelper.hpp"

#include "Common.hpp"
#include "Config.hpp"
#include "ErrorReporting.hpp"

#include <llvm/ADT/None.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Mangler.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>

using namespace llvm;
using namespace llvm::cl;
using namespace llvm::sys;
using namespace std;
using namespace std::filesystem;

LLVMInitializer::LLVMInitializer() : COM(COMThreadingMode::MultiThreaded) {
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

string LLVMHelper::mangleName(const Function &Func) {
  SmallString<16> Name;
  Mangler().getNameWithPrefix(Name, &Func,
                              /* CannotUsePrivateLabel */ false);
  return Name.str().str();
}

IRHelper::IRHelper(LLVMHelper &LLVM, StringRef Name, StringRef Path,
                   StringRef Triple)
    : LLVM(LLVM), Builder(LLVM.Ctx), Module(Name, LLVM.Ctx) {

  // Get target from the triple provided.
  string Error;
  const Target *Target = TargetRegistry::lookupTarget(Triple, Error);
  if (!Target) {
    reportError("cannot create target");
    return;
  }

  // Create basic `TargetMachine`.
  TM.reset(Target->createTargetMachine(Triple, "generic", "", TargetOptions(),
                                       /* RelocModel */ None));

  // Configure LLVM `Module`.
  Module.setSourceFileName(Path);
  Module.setTargetTriple(Triple);
  Module.setDataLayout(TM->createDataLayout());

  // DLL function wrappers have mostly type `(void *) -> void`.
  Type *VoidTy = Type::getVoidTy(LLVM.Ctx);
  WrapperTy = FunctionType::get(VoidTy, {Type::getInt8PtrTy(LLVM.Ctx)},
                                /* isVarArg */ false);

  // Although, wrappers for trivial functions (`void -> void`) have also trivial
  // signature `void -> void`.
  TrivialWrapperTy = FunctionType::get(VoidTy, /* isVarArg */ false);
}

const char *const IRHelper::Windows32 = "i386-pc-windows-msvc";
const char *const IRHelper::Apple = "armv7s-apple-ios10";

Function *IRHelper::declareFunc(const ExportEntry *Exp, bool Wrapper) {
  if (!Exp)
    return nullptr;
  // This is needed to keep `to_string(Exp->RVA)` alive.
  string WrapperRVA;
  if (Wrapper && Exp->WrapperRVA.empty())
    WrapperRVA = to_string(Exp->RVA);

  // Note that we add prefix `\01`, so that the name doesn't get mangled since
  // it already is. LLVM will remove this prefix before emitting object code for
  // the function.
  auto Name =
      Wrapper ? Twine("\01$__ipaSim_wrapper_",
                      Exp->WrapperRVA.empty() ? WrapperRVA : Exp->WrapperRVA)
              : Twine("\01", Exp->Name);

  FunctionType *Type =
      Wrapper ? (Exp->isTrivial() ? TrivialWrapperTy : WrapperTy) : Exp->Type;

  // Check whether this function hasn't already been declared.
  if (Function *Func = Module.getFunction(Name.str())) {
    assert(Func->getFunctionType() == Type &&
           "The already-declared function has a wrong type.");
    return Func;
  }

  // If not, create new declaration.
  return Function::Create(Type, Function::ExternalLinkage, Name, &Module);
}

void IRHelper::defineFunc(llvm::Function *Func) {
  // Bodies of our simple functions consist of exactly one `BasicBlock`.
  llvm::BasicBlock *BB = llvm::BasicBlock::Create(LLVM.Ctx, "entry", Func);
  Builder.SetInsertPoint(BB);
}

pair<StructType *, StructType *>
IRHelper::createParamStruct(const ExportEntry *Exp) {
  Type *RetTy = Exp->Type->getReturnType();

  // If the function has no arguments, we don't really need a struct, we just
  // want to use the return value. We create a trivial structure type for
  // compatibility with and simplicity of our callers, though.
  if (!Exp->Type->getNumParams()) {
    StructType *Struct = StructType::create(RetTy, "struct");
    StructType *Union = StructType::create(Struct, "union");
    return {Struct, Union};
  }

  // Map parameter types to their pointers.
  vector<Type *> ParamPointers;
  ParamPointers.reserve(Exp->Type->getNumParams());
  for (Type *Ty : Exp->Type->params()) {
    ParamPointers.push_back(Ty->getPointerTo());
  }

  // Create a structure that we use to store the function's arguments and return
  // value. It's actually a union of a structure and of the return value where
  // the structure in the union contains addresses of the arguments.
  StructType *Struct = StructType::create(ParamPointers, "struct");

  // In LLVM IR, union is simply a struct containing the largest element.
  Type *ContainedTy;
  if (RetTy->isVoidTy() ||
      Struct->getScalarSizeInBits() >= RetTy->getScalarSizeInBits())
    ContainedTy = Struct;
  else
    ContainedTy = RetTy;
  StructType *Union = StructType::create("union", ContainedTy);

  return {Struct, Union};
}

Value *IRHelper::createCall(Function *Func, ArrayRef<Value *> Args,
                            const Twine &Name) {
  if (Func->getReturnType()->isVoidTy()) {
    Builder.CreateCall(Func, Args);
    return nullptr;
  }
  return Builder.CreateCall(Func, Args, Name);
}
Value *IRHelper::createCall(FunctionType *FuncTy, Value *FuncPtr,
                            ArrayRef<Value *> Args, const Twine &Name) {
  if (FuncTy->getReturnType()->isVoidTy()) {
    Builder.CreateCall(FuncTy, FuncPtr, Args);
    return nullptr;
  }
  return Builder.CreateCall(FuncTy, FuncPtr, Args, Name);
}

void IRHelper::verifyFunction(Function *Func) {
  string Error;
  raw_string_ostream OS(Error);
  if (llvm::verifyFunction(*Func, &OS)) {
    OS.flush();
    reportError("invalid IR code (" + Func->getName() + "): " + Error);
  }
}

// Compiles the module. Inspired by LLVM tutorial:
// https://llvm.org/docs/tutorial/LangImpl08.html.
void IRHelper::emitObj(StringRef Path) {
  // Print out LLVM IR.
  if constexpr (OutputLLVMIR) {
    if (auto IROutput = createOutputFile(Path.str() + ".ll"))
      Module.print(*IROutput, nullptr);
  }

  // Create output file.
  auto Output(createOutputFile(Path));
  if (!Output)
    return;

  // Emit object code.
  legacy::PassManager PM;
  if (TM->addPassesToEmitFile(PM, *Output, TargetMachine::CGFT_ObjectFile)) {
    reportError("cannot emit object file");
    return;
  }
  PM.run(Module);
}
