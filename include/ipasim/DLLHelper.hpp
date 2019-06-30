// DLLHelper.hpp: Definition of class `DLLHelper`.

#ifndef IPASIM_DLL_HELPER_HPP
#define IPASIM_DLL_HELPER_HPP

#include "ipasim/ClangHelper.hpp"
#include "ipasim/HAContext.hpp"
#include "ipasim/LLDBHelper.hpp"
#include "ipasim/LLVMHelper.hpp"

#include <CodeGen/CodeGenModule.h>
#include <filesystem>
#include <set>
#include <string>

namespace ipasim {

// Represents one `.dll` file that can be either analyzed or have its wrapper
// generated.
class DLLHelper {
public:
  DLLHelper(HAContext &HAC, LLVMHelper &LLVM, DLLGroup &Group, size_t GroupIdx,
            DLLEntry &DLL, size_t DLLIdx)
      : HAC(HAC), LLVM(LLVM), Group(Group), GroupIdx(GroupIdx), DLL(DLL),
        DLLIdx(DLLIdx), DLLPath(Group.Dir / DLL.Name),
        DLLPathStr(DLLPath.string()) {}

  // Analyzes the `.dll` and populates `HAContext` with information retrieved.
  void load(LLDBHelper &LLDB, ClangHelper &Clang,
            clang::CodeGen::CodeGenModule *CGM);
  // Generates wrappers associated with the `.dll`.
  void generate(const DirContext &DC, bool Debug);
  // Helper method that can invoke one of the methods above on multiple DLLs.
  template <typename... ArgTys, typename FTy = void(ArgTys...)>
  static void forEach(HAContext &HAC, LLVMHelper &LLVM, FTy DLLHelper::*Func,
                      ArgTys &&... Args) {
    for (auto [GroupIdx, Group] : withIndices(HAC.DLLGroups))
      for (auto [DLLIdx, DLL] : withIndices(Group.DLLs)) {
        DLLHelper DH(HAC, LLVM, Group, GroupIdx, DLL, DLLIdx);
        (DH.*Func)(std::forward<ArgTys>(Args)...);
      }
  }

private:
  HAContext &HAC;
  LLVMHelper &LLVM;
  DLLGroup &Group;
  size_t GroupIdx;
  DLLEntry &DLL;
  size_t DLLIdx;
  std::filesystem::path DLLPath;
  std::string DLLPathStr;
  std::set<uint32_t> Exports;

  bool analyzeWindowsFunction(const std::string &Name, uint32_t RVA,
                              bool IgnoreDuplicates, ExportPtr &Exp);
};

} // namespace ipasim

// !defined(IPASIM_DLL_HELPER_HPP)
#endif
