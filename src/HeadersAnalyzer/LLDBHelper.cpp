// LLDBHelper.cpp

#include "LLDBHelper.hpp"

#include <Plugins/SymbolFile/PDB/SymbolFilePDB.h>
#include <lldb/API/SBDebugger.h>
#include <lldb/Symbol/ClangUtil.h>
#include <lldb/Utility/DataBufferHeap.h>

#include <clang/CodeGen/CodeGenABITypes.h>

#include <llvm/DebugInfo/PDB/PDBSymbolFunc.h>
#include <llvm/DebugInfo/PDB/PDBSymbolPublicSymbol.h>

#include <memory>

using namespace lldb;
using namespace lldb_private;
using namespace llvm::pdb;
using namespace std;

// We do `SBDebugger` initialization in a class separate from `LLDBHelper`, so
// that `SBDebugger::Terminate` is called after everything else has been
// destroyed.
LLDBInitializer::LLDBInitializer() { SBDebugger::Initialize(); }
LLDBInitializer::~LLDBInitializer() { SBDebugger::Terminate(); }

LLDBHelper::LLDBHelper() { Debugger = Debugger::CreateInstance(); }

void LLDBHelper::load(const char *DLL, const char *PDB) {
  // Load PDB into LLDB. This is a hack, actually, because no simple way of
  // loading the PDB worked for us. We do this simply because we use some LLDB
  // functions in our `TypeComparer` and they require some initialized LLDB
  // structures (like `SymbolFile`). Otherwise, we wouldn't need LLDB at all,
  // since we work directly with `IPDBSession` which is a LLVM object that can
  // work without LLDB.
  ModuleSpec ModuleSpec(FileSpec(DLL, /* resolve_path */ true));
  ModuleSpec.GetSymbolFileSpec().SetFile(PDB, /* resolve_path */ true);
  Module = Debugger->GetSelectedOrDummyTarget()->GetSharedModule(ModuleSpec);
  Buffer.reset(new DataBufferHeap);
  Obj = std::make_unique<ObjectFileDummy>(Module, Buffer);
  SymbolFile.reset(
      static_cast<SymbolFilePDB *>(SymbolFilePDB::CreateInstance(Obj.get())));
  SymbolFile->CalculateAbilities(); // Initialization, actually.
  RootSymbol = SymbolFile->GetPDBSession().getGlobalScope();
}

template <typename SymbolTy> string LLDBHelper::mangleName(SymbolTy &Func) {
  // Get function's name, mangled if possible.
  string Name(Func.getUndecoratedName());
  if (Name.empty()) {
    Name = Func.getName();
    assert(!Name.empty() && "A function has no name.");
  }
  return move(Name);
}
template string LLDBHelper::mangleName(PDBSymbolFunc &);
template string LLDBHelper::mangleName(PDBSymbolPublicSymbol &);

llvm::Type *TypeComparer::getLLVMType(const PDBSymbol &Symbol) {
  using namespace clang;

  TypeSP LLDBType = Parser.CreateLLDBTypeFromPDBType(Symbol);
  if (!LLDBType)
    return nullptr;
  QualType CanonType =
      ClangUtil::GetCanonicalQualType(LLDBType->GetFullCompilerType());
  return convertTypeForMemory(CGM, CanonType);
}
template <typename SymbolTy>
bool TypeComparer::areEquivalent(llvm::FunctionType *Func,
                                 const SymbolTy &SymbolFunc) {
  auto *Func2 = static_cast<llvm::FunctionType *>(getLLVMType(SymbolFunc));
  if (!Func2) {
    reportError(
        llvm::Twine(
            "cannot compare signatures of a function and non-typed symbol `") +
        LLDBHelper::mangleName(SymbolFunc) + "'");
    return true;
  }
  return FunctionComparer::compareTypes(Module, Func, Func2) == 0;
}
template bool TypeComparer::areEquivalent(llvm::FunctionType *Func,
                                          const PDBSymbolFunc &SymbolFunc);
template bool
TypeComparer::areEquivalent(llvm::FunctionType *Func,
                            const PDBSymbolPublicSymbol &SymbolFunc);
