// LLDBHelper.cpp

#include "LLDBHelper.hpp"

#include "ErrorReporting.hpp"

#include <Plugins/SymbolFile/PDB/SymbolFilePDB.h>
#include <lldb/API/SBDebugger.h>
#include <lldb/Symbol/ObjectFile.h>
#include <lldb/Utility/DataBufferHeap.h>

#include <memory>

using namespace std;
using namespace lldb;
using namespace lldb_private;
using namespace llvm::pdb;

LLDBHelper::LLDBHelper() {
  SBDebugger::Initialize();
  Debugger = Debugger::CreateInstance();
}
LLDBHelper::~LLDBHelper() {
  Debugger::Destroy(Debugger);
  SBDebugger::Terminate();
}

namespace {
class ObjectFileUnimplemented : public ObjectFile {
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
} // namespace

void LLDBHelper::load(const char *DLL, const char *PDB) {
  // Load PDB into LLDB. This is a hack, actually, because no simple way of
  // loading the PDB worked for us. We do this simply because we use some LLDB
  // functions in our `TypeComparer` and they require some initialized LLDB
  // structures (like `SymbolFile`). Otherwise, we wouldn't need LLDB at all,
  // since we work directly with `IPDBSession` which is a LLVM object that can
  // work without LLDB. Although, for some reason, the DIA SDK is not registered
  // properly when we don't use `Debugger::Initialize`, so this would also have
  // to be solved before removing LLDB from our dependencies completely.
  ModuleSpec ModuleSpec(FileSpec(DLL, /* resolve_path */ true));
  ModuleSpec.GetSymbolFileSpec().SetFile(PDB, /* resolve_path */ true);
  ModuleSP Module =
      Debugger->GetSelectedOrDummyTarget()->GetSharedModule(ModuleSpec);
  DataBufferSP Buffer(new DataBufferHeap);
  ObjectFileDummy Obj(Module, Buffer);
  SymbolFilePDB *SymbolFile =
      static_cast<SymbolFilePDB *>(SymbolFilePDB::CreateInstance(&Obj));
  SymbolFile->CalculateAbilities(); // Initialization, actually.
  RootSymbol = SymbolFile->GetPDBSession().getGlobalScope();
}
