// LLDBHelper.hpp

#ifndef LLDBHELPER_HPP
#define LLDBHELPER_HPP

#include <lldb/Core/Debugger.h>

#include <llvm/DebugInfo/PDB/PDBSymbolExe.h>

class LLDBHelper {
public:
  LLDBHelper();
  ~LLDBHelper();

  void load(const char *DLL, const char *PDB);
  std::string mangleName(llvm::pdb::PDBSymbolFunc &Func);

private:
  lldb::DebuggerSP Debugger;
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
    SymbolIterator() {}
    SymbolIterator(SymbolList<SymbolTy> &List, uint32_t Index)
        : List(List), Index(Index) {}

    SymbolIterator &operator++() {
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
