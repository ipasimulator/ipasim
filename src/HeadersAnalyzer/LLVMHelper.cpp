// LLVMHelper.cpp

#include "LLVMHelper.hpp"

#include "ErrorReporting.hpp"

#include <llvm/ADT/None.h>
#include <llvm/IR/Mangler.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>

using namespace llvm;
using namespace llvm::cl;
using namespace std;

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

string LLVMHelper::mangleName(const Function &Func) {
  SmallString<16> Name;
  Mangler().getNameWithPrefix(Name, &Func,
                              /* CannotUsePrivateLabel */ false);
  return Name.str().str();
}

IRHelper::IRHelper(LLVMHelper &LLVM, const StringRef Name, const StringRef Path,
                   const StringRef Triple)
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

  // DLL function wrappers have all type `(void *) -> void`.
  WrapperTy = FunctionType::get(Type::getVoidTy(LLVM.Ctx),
                                {Type::getInt8PtrTy(LLVM.Ctx)},
                                /* isVarArg */ false);
}

const char *const IRHelper::Windows32 = "i386-pc-windows-msvc";
const char *const IRHelper::Apple = "armv7s-apple-ios10";

Function *IRHelper::declareFunc(const ExportEntry *Exp, bool Wrapper) {
  if (!Exp)
    return nullptr;
  // Note that we add prefix `\01`, so that the name doesn't get mangled since
  // it already is. LLVM will remove this prefix before emitting object code for
  // the function.
  auto Name = Wrapper ? Twine("\01$__ipaSim_wrapper_", to_string(Exp->RVA))
                      : Twine("\01", Exp->Name);
  FunctionType *Type = Wrapper ? WrapperTy : Exp->Type;
  return Function::Create(Type, Function::ExternalLinkage, Name, &Module);
}

void IRHelper::defineFunc(llvm::Function *Func) {
  // Bodies of our simple functions consist of exactly one `BasicBlock`.
  llvm::BasicBlock *BB = llvm::BasicBlock::Create(LLVM.Ctx, "entry", Func);
  Builder.SetInsertPoint(BB);
}

pair<StructType *, StructType *>
IRHelper::createParamStruct(const ExportEntry *Exp) {
  // Map parameter types to their pointers.
  vector<Type *> ParamPointers;
  ParamPointers.reserve(Exp->Type->getNumParams());
  for (Type *Ty : Exp->Type->params()) {
    ParamPointers.push_back(Ty->getPointerTo());
  }

  // Create a structure that we use to store the function's arguments and return
  // value. It's actually a union of a structure and of the return value where
  // the structure in the union contains addresses of the arguments.
  StructType *Struct = llvm::StructType::create(ParamPointers, "struct");

  // In LLVM IR, union is simply a struct containing the largest element.
  Type *RetTy = Exp->Type->getReturnType();
  Type *ContainedTy;
  if (RetTy->isVoidTy() ||
      Struct->getScalarSizeInBits() >= RetTy->getScalarSizeInBits())
    ContainedTy = Struct;
  else
    ContainedTy = RetTy;
  llvm::StructType *Union = llvm::StructType::create("union", ContainedTy);

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
