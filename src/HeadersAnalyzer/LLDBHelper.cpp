// LLDBHelper.cpp

#include "LLDBHelper.hpp"

#include <Plugins/SymbolFile/PDB/SymbolFilePDB.h>
#include <lldb/API/SBDebugger.h>
#include <lldb/Utility/DataBufferHeap.h>

#include <llvm/DebugInfo/PDB/PDBSymbolFunc.h>

#include <memory>

using namespace std;
using namespace lldb;
using namespace lldb_private;
using namespace llvm::pdb;

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

string LLDBHelper::mangleName(PDBSymbolFunc &Func) {
  // Get function's name, mangled if possible.
  string Name(Func.getUndecoratedName());
  if (Name.empty()) {
    Name = Func.getName();
    assert(!Name.empty() && "A function has no name.");
  }
  return move(Name);
}
