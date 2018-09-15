// LLVMHelper.hpp

#ifndef LLVMHELPER_HPP
#define LLVMHELPER_HPP

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Allocator.h>
#include <llvm/Support/StringSaver.h>

#include <memory>
#include <string>

class LLVMInitializer {
public:
  LLVMInitializer();
};

class StringVector {
public:
  StringVector() : A(), Saver(A) {}

  void add(const char *S) { Vector.emplace_back(Saver.save(S).data()); }
  void loadConfigFile(llvm::StringRef File);
  llvm::ArrayRef<const char *> get() { return Vector; }

private:
  llvm::BumpPtrAllocator A;
  llvm::StringSaver Saver;
  llvm::SmallVector<const char *, 256> Vector;
};

class LLVMHelper {
public:
  LLVMHelper(LLVMInitializer &) {}

  llvm::LLVMContext Ctx;

  llvm::Module *getModule() { return Module.get(); }
  void setModule(std::unique_ptr<llvm::Module> &&Module) {
    this->Module = move(Module);
  }

private:
  std::unique_ptr<llvm::Module> Module;
};

// !defined(LLVMHELPER_HPP)
#endif
