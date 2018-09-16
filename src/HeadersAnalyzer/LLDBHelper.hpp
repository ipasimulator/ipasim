// LLDBHelper.hpp

#ifndef LLDBHELPER_HPP
#define LLDBHELPER_HPP

#include "Common.hpp"
#include "ErrorReporting.hpp"

#include <Plugins/SymbolFile/PDB/SymbolFilePDB.h>
#include <lldb/Core/Debugger.h>
#include <lldb/Symbol/ObjectFile.h>

#include <llvm/DebugInfo/PDB/PDBSymbolExe.h>

class ObjectFileUnimplemented : public lldb_private::ObjectFile {
public:
  ObjectFileUnimplemented(const lldb::ModuleSP &Module,
                          const lldb::DataBufferSP &Buffer)
      : ObjectFile(Module, nullptr, 0, 0, Buffer, 0) {}

#define unimplemented reportFatalError("function is not implemented")
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

class ObjectFileDummy : public ObjectFileUnimplemented {
public:
  ObjectFileDummy(const lldb::ModuleSP &Module,
                  const lldb::DataBufferSP &Buffer)
      : ObjectFileUnimplemented(Module, Buffer) {}
};

class LLDBInitializer {
public:
  LLDBInitializer();
  ~LLDBInitializer();
};

class LLDBHelper {
public:
  LLDBHelper();

  void load(const char *DLL, const char *PDB);
  static std::string mangleName(llvm::pdb::PDBSymbolFunc &Func);
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

    SymbolIterator prefix(++) {
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

// !defined(LLDBHELPER_HPP)
#endif
