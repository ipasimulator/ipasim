// LLDBHelper.hpp

#ifndef LLDBHELPER_HPP
#define LLDBHELPER_HPP

#include <lldb/Core/Debugger.h>

#include <llvm/DebugInfo/PDB/PDBSymbolExe.h>

class LLDBHelper {
public:
  LLDBHelper();
  ~LLDBHelper();

  std::unique_ptr<llvm::pdb::PDBSymbolExe> load(const char *DLL,
                                                const char *PDB);

private:
  lldb::DebuggerSP Debugger;
};

// !defined(LLDBHELPER_HPP)
#endif
