// LLDBHelper.hpp: Definition of class `LLDBHelper`, some `ObjectFile`
// descendants and class `TypeComparer`.

#ifndef IPASIM_LLDB_HELPER_HPP
#define IPASIM_LLDB_HELPER_HPP

#include "ipasim/Common.hpp"
#include "ipasim/Output.hpp"

#include <CodeGen/CodeGenModule.h>
#include <Plugins/SymbolFile/PDB/PDBASTParser.h>
#include <Plugins/SymbolFile/PDB/SymbolFilePDB.h>
#include <lldb/Core/Debugger.h>
#include <lldb/Symbol/ClangASTContext.h>
#include <lldb/Symbol/ObjectFile.h>
#include <llvm/DebugInfo/PDB/PDBSymbolExe.h>
#include <llvm/Transforms/Utils/FunctionComparator.h>

namespace ipasim {

// An `ObjectFile` whose all methods are unimplemented.
class ObjectFileUnimplemented : public lldb_private::ObjectFile {
public:
  ObjectFileUnimplemented(const lldb::ModuleSP &Module,
                          const lldb::DataBufferSP &Buffer)
      : ObjectFile(Module, nullptr, 0, 0, Buffer, 0) {}

#define unimplemented Log.fatalError("function is not implemented")
  void Dump(lldb_private::Stream *S) override { unimplemented; }
  uint32_t GetAddressByteSize() const override { unimplemented; }
  uint32_t GetDependentModules(lldb_private::FileSpecList &file_list) override {
    unimplemented;
  }
  bool IsExecutable() const override { unimplemented; }
  bool GetArchitecture(lldb_private::ArchSpec &arch) override { unimplemented; }
  void
  CreateSections(lldb_private::SectionList &unified_section_list) override {
    unimplemented;
  }
  lldb_private::Symtab *GetSymtab() override { unimplemented; }
  bool IsStripped() override { unimplemented; }
  bool GetUUID(lldb_private::UUID *uuid) override { unimplemented; }
  lldb::ByteOrder GetByteOrder() const override { unimplemented; }
  bool ParseHeader() override { unimplemented; }
  Type CalculateType() override { unimplemented; }
  Strata CalculateStrata() override { unimplemented; }
  lldb_private::ConstString GetPluginName() override { unimplemented; }
  uint32_t GetPluginVersion() override { unimplemented; }
#undef unimplemented
};

// A dummy `ObjectFile`. Currently, it's equivalent to the unimplemented
// `ObjectFile`. It's used to ease the integration with LLDB.
class ObjectFileDummy : public ObjectFileUnimplemented {
public:
  ObjectFileDummy(const lldb::ModuleSP &Module,
                  const lldb::DataBufferSP &Buffer)
      : ObjectFileUnimplemented(Module, Buffer) {}
};

// Used to initialize LLDB via RAII.
class LLDBInitializer {
public:
  LLDBInitializer();
  ~LLDBInitializer();
};

// Represents an instance of LLDB (a LLVM debugger). We use that to parse PDBs
// (Windows debugging symbol files).
class LLDBHelper {
public:
  LLDBHelper();

  void load(const char *DLL, const char *PDB);
  lldb_private::SymbolFile *getSymbolFile() { return SymbolFile.get(); }

private:
  LLDBInitializer LLDBInit; // This has to be first.
  lldb::DebuggerSP Debugger;
  lldb::ModuleSP Module;
  lldb::DataBufferSP Buffer;
  std::unique_ptr<ObjectFileDummy> Obj;
  std::unique_ptr<SymbolFilePDB> SymbolFile;
  std::unique_ptr<llvm::pdb::PDBSymbolExe> RootSymbol;

public:
  // Helper iterator over PDB's symbols
  template <typename> class SymbolIterator;
  template <typename SymbolTy> class SymbolList {
  public:
    SymbolList(std::unique_ptr<llvm::pdb::IPDBEnumSymbols> &&Enum)
        : Enum(move(Enum)) {}

    std::unique_ptr<llvm::pdb::IPDBEnumSymbols> Enum;

    SymbolIterator<SymbolTy> begin();
    SymbolIterator<SymbolTy> end();
  };
  template <typename SymbolTy> class SymbolIterator {
  public:
    SymbolIterator(SymbolList<SymbolTy> &List, uint32_t Index)
        : List(List), Index(Index) {}

    SymbolIterator IPASIM_PREFIX(++) {
      ++Index;
      Current = nullptr;
      return *this;
    }
    bool operator==(const SymbolIterator &Other) const {
      return Index == Other.Index;
    }
    bool operator!=(const SymbolIterator &Other) const {
      return !(*this == Other);
    }
    SymbolTy &operator*() {
      if (!Current)
        Current = List.Enum->getChildAtIndex(Index);
      return *static_cast<SymbolTy *>(Current.get());
    }

  private:
    SymbolList<SymbolTy> &List;
    std::unique_ptr<llvm::pdb::PDBSymbol> Current;
    uint32_t Index = 0;
  };

  template <typename SymbolTy> SymbolList<SymbolTy> enumerate() {
    return SymbolList<SymbolTy>(RootSymbol->findAllChildren(SymbolTy::Tag));
  }
};

template <typename SymbolTy>
LLDBHelper::SymbolIterator<SymbolTy> LLDBHelper::SymbolList<SymbolTy>::begin() {
  return SymbolIterator<SymbolTy>(*this, 0);
}
template <typename SymbolTy>
LLDBHelper::SymbolIterator<SymbolTy> LLDBHelper::SymbolList<SymbolTy>::end() {
  return SymbolIterator<SymbolTy>(*this, Enum->getChildCount());
}

// Helper class that can compare types from PDB and LLVM IR.
class TypeComparer {
public:
  // Note that if we got `PDBAstParser` from `Module` rather then created it,
  // `CreateLLDBTypeFromPDBType` wouldn't work.
  TypeComparer(clang::CodeGen::CodeGenModule &CGM, llvm::Module *Module,
               lldb_private::SymbolFile *SymbolFile)
      : CGM(CGM), Module(Module), ClangCtx(), Parser(ClangCtx) {
    ClangCtx.SetSymbolFile(SymbolFile);
  }

  llvm::Type *getLLVMType(const llvm::pdb::PDBSymbol &Symbol);
  bool areEqual(const llvm::Type *Type, const llvm::pdb::PDBSymbol &Symbol) {
    return Type == getLLVMType(Symbol);
  }
  template <typename SymbolTy>
  bool areEquivalent(llvm::FunctionType *Func, const SymbolTy &SymbolFunc);

private:
  clang::CodeGen::CodeGenModule &CGM;
  llvm::Module *Module;
  lldb_private::ClangASTContext ClangCtx;
  PDBASTParser Parser;

  // Just to get access to protected function `cmpTypes`.
  class FunctionComparer : llvm::FunctionComparator {
  public:
    static int compareTypes(llvm::Module *Module, llvm::FunctionType *FTy1,
                            llvm::FunctionType *FTy2) {
      return FunctionComparer(Module, FTy1).cmpTypes(FTy1, FTy2);
    }

  private:
    FunctionComparer(llvm::Module *Module, llvm::FunctionType *FTy)
        : FunctionComparator(
              llvm::Function::Create(FTy, llvm::GlobalValue::ExternalLinkage,
                                     "", Module),
              nullptr, nullptr) {}
  };
};

} // namespace ipasim

// !defined(IPASIM_LLDB_HELPER_HPP)
#endif
