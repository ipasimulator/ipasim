// LLVMHelper.cpp

#include "ipasim/LLVMHelper.hpp"

#include "ipasim/ClangHelper.hpp"
#include "ipasim/Common.hpp"
#include "ipasim/ErrorReporting.hpp"
#include "ipasim/HeadersAnalyzer/Config.hpp"

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

using namespace ipasim;
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

  VoidPtrTy = Type::getInt8PtrTy(LLVM.Ctx);

  // DLL function wrappers have mostly type `(void *) -> void`.
  Type *VoidTy = Type::getVoidTy(LLVM.Ctx);
  WrapperTy = FunctionType::get(VoidTy, {VoidPtrTy}, /* isVarArg */ false);

  // However, wrappers for trivial functions (`void -> void`) have also trivial
  // signature `void -> void`.
  TrivialWrapperTy = FunctionType::get(VoidTy, /* isVarArg */ false);
}

const char *const IRHelper::Windows32 = "i386-pc-windows-msvc";
const char *const IRHelper::Apple = "armv7s-apple-ios10";

template <LibType T> GlobalValue *IRHelper::declare(const ExportEntry &Exp) {
  if (Exp.getType<T>())
    return declareFunc<T>(Exp);

  Twine RawName(Twine('\01') + Exp.Name);
  return static_cast<GlobalValue *>(
      Module.getOrInsertGlobal(LLVM.Saver.save(RawName), VoidPtrTy));
}
template GlobalValue *IRHelper::declare<LibType::Dylib>(const ExportEntry &);
template GlobalValue *IRHelper::declare<LibType::DLL>(const ExportEntry &);

template <LibType T>
Function *IRHelper::declareFunc(const ExportEntry &Exp, bool Wrapper) {
  // This is needed to keep `to_string(Exp.RVA)` alive.
  StringRef WrapperRVA(LLVM.Saver.save(to_string(Exp.RVA)));

  auto Name =
      Wrapper ? Twine("$__ipaSim_wrapper_") + WrapperRVA : Twine(Exp.Name);

  FunctionType *Type = Wrapper
                           ? (Exp.isTrivial() ? TrivialWrapperTy : WrapperTy)
                           : Exp.getType<T>();

  return declareFunc(Type, Name);
}
template Function *IRHelper::declareFunc<LibType::Dylib>(const ExportEntry &,
                                                         bool);
template Function *IRHelper::declareFunc<LibType::DLL>(const ExportEntry &,
                                                       bool);

Function *IRHelper::declareFunc(FunctionType *Type, const Twine &Name) {
  // Note that we add prefix `\01`, so that the name doesn't get mangled since
  // it already is. LLVM will remove this prefix before emitting object code for
  // the function.
  Twine RawName(Twine('\01') + Name);

  // Check whether this function hasn't already been declared.
  if (Function *Func = Module.getFunction(RawName.str())) {
    assert(Func->getFunctionType() == Type &&
           "The already-declared function has a wrong type.");
    return Func;
  }

  // If not, create new declaration.
  return Function::Create(Type, Function::ExternalLinkage, RawName, &Module);
}

void IRHelper::defineFunc(llvm::Function *Func) {
  // Bodies of our simple functions consist of exactly one `BasicBlock`.
  llvm::BasicBlock *BB = llvm::BasicBlock::Create(LLVM.Ctx, "entry", Func);
  Builder.SetInsertPoint(BB);
}

// TODO: Store types with size less than pointer size directly in the structure
// (instead of storing pointer to it as we are doing now). But make sure it'll
// be aligned equally on both architectures.
// TODO: Originally, this used union to share space for arguments and return
// value, but it generated wrong machine code. However, we still would like to
// share the space if possible.
StructType *IRHelper::createParamStruct(const ExportEntry &Exp) {
  Type *RetTy = Exp.getDylibType()->getReturnType();

  // If the function has no arguments, we don't really need a struct, we just
  // want to use the return value. We create a trivial structure type for
  // compatibility with and simplicity of our callers, though.
  if (!Exp.getDylibType()->getNumParams())
    return StructType::create(RetTy, "struct");

  // Map parameter types to their pointers.
  vector<Type *> ParamPointers;
  ParamPointers.reserve(Exp.getDylibType()->getNumParams() +
                        (RetTy->isVoidTy() ? 0 : 1));
  for (Type *Ty : Exp.getDylibType()->params()) {
    ParamPointers.push_back(Ty->getPointerTo());
  }
  if (!RetTy->isVoidTy())
    ParamPointers.push_back(RetTy);

  // Create a structure that we use to store the function's arguments and return
  // value. It contains space for the return value and addresses of arguments.
  return StructType::create(ParamPointers, "struct");
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
  // Generate LLVM IR.
  string IRPath(Path.str() + ".ll");
  auto IROutput(createOutputFile(IRPath));
  if (!IROutput)
    return;
  Module.print(*IROutput, nullptr);

  // Emit object file.
  // TODO: Doing this via `PassManager` and `addPassesToEmitFile` didn't work
  // well (for, e.g., `UIApplicationMain`).
  ClangHelper Clang(LLVM);
  Clang.Args.add("-target");
  Clang.Args.add(Module.getTargetTriple().c_str());
  Clang.Args.add("-c");
  Clang.Args.add(IRPath.c_str());
  Clang.Args.add("-o");
  Clang.Args.add(Path.data());
  // TODO: Use THUMB, but make sure it's emulated correctly.
  if (TM->getTargetTriple().isARM())
    Clang.Args.add("-mno-thumb");
  Clang.Args.add("-Wno-override-module");
  Clang.executeArgs();
}
