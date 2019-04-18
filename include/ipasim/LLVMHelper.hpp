// LLVMHelper.hpp

#ifndef IPASIM_LLVM_HELPER_HPP
#define IPASIM_LLVM_HELPER_HPP

#include "ipasim/HAContext.hpp"

#include <filesystem>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Allocator.h>
#include <llvm/Support/COM.h>
#include <llvm/Support/StringSaver.h>
#include <llvm/Target/TargetMachine.h>
#include <memory>
#include <string>

namespace ipasim {

class LLVMInitializer {
public:
  LLVMInitializer();

private:
  // We need COM initialized so that the DIA SDK can be loaded (see
  // `LLDBHelper`).
  llvm::sys::InitializeCOMRAII COM;
};

class TerminationGuard {
public:
  TerminationGuard(llvm::SmallVector<const char *, 256> &Vector)
      : Vector(Vector) {
    Vector.push_back(nullptr);
  }
  ~TerminationGuard() { Vector.pop_back(); }

private:
  llvm::SmallVector<const char *, 256> Vector;
};

class StringVector {
public:
  StringVector(llvm::StringSaver &S) : Saver(S) {}

  void add(const char *S) { Vector.emplace_back(Saver.save(S).data()); }
  TerminationGuard terminate() { return TerminationGuard(Vector); }
  void loadConfigFile(llvm::StringRef File);
  llvm::ArrayRef<const char *> get() { return Vector; }

private:
  llvm::StringSaver &Saver;
  llvm::SmallVector<const char *, 256> Vector;
};

class LLVMHelper {
public:
  LLVMHelper(LLVMInitializer &) : A(), Saver(A) {}

  llvm::LLVMContext Ctx;
  llvm::StringSaver Saver;

  llvm::Module *getModule() { return Module.get(); }
  void setModule(std::unique_ptr<llvm::Module> &&Module) {
    this->Module = move(Module);
  }

  std::string mangleName(const llvm::Function &Func);

private:
  llvm::BumpPtrAllocator A;
  std::unique_ptr<llvm::Module> Module;
};

class IRHelper {
public:
  IRHelper(LLVMHelper &LLVM, llvm::StringRef Name, llvm::StringRef Path,
           llvm::StringRef Triple);

  static const char *const Windows32;
  static const char *const Apple;

  llvm::IRBuilder<> Builder;

  bool isLittleEndian() const {
    return Module.getDataLayout().isLittleEndian();
  }
  bool isBigEndian() const { return Module.getDataLayout().isBigEndian(); }
  template <LibType T> llvm::GlobalValue *declare(const ExportEntry &Exp);
  template <LibType T>
  llvm::Function *declareFunc(const ExportEntry &Exp, bool Wrapper = false);
  llvm::Function *declareFunc(llvm::FunctionType *Type,
                              const llvm::Twine &Name);
  void defineFunc(llvm::Function *Func);
  llvm::StructType *createParamStruct(const ExportEntry &Exp);
  llvm::Value *createCall(llvm::Function *Func,
                          llvm::ArrayRef<llvm::Value *> Args,
                          const llvm::Twine &Name);
  llvm::Value *createCall(llvm::FunctionType *FuncTy, llvm::Value *FuncPtr,
                          llvm::ArrayRef<llvm::Value *> Args,
                          const llvm::Twine &Name);
  void verifyFunction(llvm::Function *Func);
  void emitObj(const std::filesystem::path &BuildDir, llvm::StringRef Path);
  uint64_t getSize(llvm::Type *T) {
    return Module.getDataLayout().getTypeAllocSize(T);
  }

private:
  LLVMHelper &LLVM;
  llvm::Module Module;
  std::unique_ptr<llvm::TargetMachine> TM;
  llvm::FunctionType *WrapperTy, *TrivialWrapperTy;
  llvm::Type *VoidPtrTy;
};

class FunctionGuard {
public:
  FunctionGuard(IRHelper &IR, llvm::Function *Func) : IR(IR), Func(Func) {
    IR.defineFunc(Func);
  }
  ~FunctionGuard() { IR.verifyFunction(Func); }

private:
  IRHelper &IR;
  llvm::Function *Func;
};

} // namespace ipasim

// !defined(IPASIM_LLVM_HELPER_HPP)
#endif
