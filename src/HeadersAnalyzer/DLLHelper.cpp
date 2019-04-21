// DLLHelper.cpp

#include "ipasim/DLLHelper.hpp"

#include "ipasim/HeadersAnalyzer/Config.hpp"
#include "ipasim/ObjCHelper.hpp"

#include <llvm/DebugInfo/PDB/PDBSymbolFunc.h>
#include <llvm/DebugInfo/PDB/PDBSymbolPublicSymbol.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ObjectFile.h>

using namespace clang::CodeGen;
using namespace ipasim;
using namespace llvm;
using namespace llvm::object;
using namespace llvm::pdb;
using namespace std;
using namespace std::filesystem;

void DLLHelper::load(LLDBHelper &LLDB, ClangHelper &Clang, CodeGenModule *CGM) {
  path PDBPath(DLLPath);
  PDBPath.replace_extension(".pdb");

  LLDB.load(DLLPathStr.c_str(), PDBPath.string().c_str());
  TypeComparer TC(*CGM, LLVM.getModule(), LLDB.getSymbolFile());

  // Load DLL.
  auto DLLFile(ObjectFile::createObjectFile(DLLPathStr));
  if (!DLLFile) {
    Log.error() << toString(DLLFile.takeError()) << " (" << DLLPathStr << ")"
                << Log.end();
    return;
  }
  auto COFF = dyn_cast<COFFObjectFile>(DLLFile->getBinary());
  if (!COFF) {
    Log.error() << "expected COFF (" << DLLPathStr << ")" << Log.end();
    return;
  }

  // Discover exports.
  for (auto &Export : COFF->export_directories()) {
    uint32_t ExportRVA;
    if (error_code Error = Export.getExportRVA(ExportRVA)) {
      Log.error() << "cannot get RVA of an export symbol (" << DLLPathStr
                  << "): " << Error.message() << Log.end();
      continue;
    }
    // Note that there can be aliases, so the current `ExportRVA` can
    // already be present in `Exports`, but that's OK.
    Exports.insert(ExportRVA);
  }

  // Release PDBs don't contain Objective-C methods, so we find them
  // manually in the metadata.
  set<uint32_t> ObjCMethods(ObjCMethodScout::discoverMethods(DLLPathStr, COFF));

  // Analyze functions.
  auto Analyzer = [this](auto &&Func, bool IgnoreDuplicates = false) mutable {
    string Name(Func.getName());
    uint32_t RVA = Func.getRelativeVirtualAddress();

    // If undecorated name has underscore at the beginning, use that
    // instead.
    string UN(Func.getUndecoratedName());
    if (!UN.empty() && Name != UN && UN[0] == '_' &&
        !UN.compare(1, Name.length(), Name))
      Name = move(UN);

    ExportPtr Exp;
    if (!analyzeWindowsFunction(Name, RVA, IgnoreDuplicates, Exp))
      return;

    // Verify that the function has the same signature as the iOS one.
    if constexpr (CompareTypes) {
      // TODO: #28 is not considered here.
      if (!TC.areEquivalent(Exp->getDylibType(), Func))
        Log.error() << "functions' signatures are not equivalent (" << Exp->Name
                    << ")" << Log.end();
    } else if constexpr (is_same_v<decltype(Func),
                                   llvm::pdb::PDBSymbolFunc &>) {
      if (!Func.getSignature()) {
        Log.error() << "function doesn't have a signature (" << Exp->Name << ")"
                    << Log.end();
        return;
      }

      // Check at least number of arguments.
      size_t DylibCount = Exp->getDylibType()->getNumParams();
      size_t DLLCount = Func.getSignature()->getCount();

      // TODO: Also check that `Func`'s return type is NOT void.
      if (DylibCount == DLLCount + 1 &&
          Exp->getDylibType()->getReturnType()->isVoidTy())
        // See #28.
        Exp->DylibStretOnly = true;
      else if (DylibCount != DLLCount)
        Log.error() << "function '" << Exp->Name
                    << "' has different number of arguments in iOS "
                       "headers and in DLL ("
                    << to_string(DylibCount) << " v. " << to_string(DLLCount)
                    << ")" << Log.end();
    }
  };
  for (auto &Func : LLDB.enumerate<PDBSymbolFunc>())
    Analyzer(Func);
  for (auto &Func : LLDB.enumerate<PDBSymbolPublicSymbol>())
    Analyzer(Func, /* IgnoreDuplicates */ true);
}

bool DLLHelper::analyzeWindowsFunction(const string &Name, uint32_t RVA,
                                       bool IgnoreDuplicates, ExportPtr &Exp) {
  // We are only interested in exported symbols or Objective-C methods.
  if (!HAC.isClassMethod(Name) && Exports.find(RVA) == Exports.end())
    return false;

  // Find the corresponding export info from TBD files.
  if (!HAC.isInterestingForWindows(Name, Exp, RVA, IgnoreDuplicates))
    return false;
  bool DataSymbol = Exp->Status == ExportStatus::NotFound;

  // Update status accordingly.
  Exp->Status = ExportStatus::FoundInDLL;
  Exp->RVA = RVA;
  DLL.Exports.push_back(Exp);
  Exp->DLLGroup = GroupIdx;
  Exp->DLL = DLLIdx;

  // Save symbol that will serve as a reference for computing addresses
  // of Objective-C methods.
  if (!DLL.ReferenceSymbol && !Exp->ObjCMethod)
    DLL.ReferenceSymbol = Exp;

  // If this is not a function, we can skip the rest of analysis.
  if (DataSymbol)
    return false;

  auto FlagsSetter = [&]() {
    // If it's a normal messenger, it has two parameters (`id` and
    // `SEL`, both actually `void *`). If it's a `stret` messenger, it
    // has one more parameter at the front (a `void *` for struct
    // return).
    Exp->Stret = endsWith(Exp->Name, HAContext::StretPostfix);
    // Also recognize `Super` functions.
    if (Exp->Name.find("Super2") != string::npos)
      Exp->Super2 = true;
    else if (Exp->Name.find("Super") != string::npos)
      Exp->Super = true;
  };

  // Find Objective-C messengers. Note that they used to be variadic,
  // but that's deprecated and so we cannot rely on that.
  if (startsWith(Exp->Name, HAContext::MsgSendPrefix)) {
    Exp->Messenger = true;
    FlagsSetter();

    // Don't verify their types.
    return false;
  }

  // Also, change type of the lookup functions. In Apple headers, they
  // are declared as `void -> void`, but we need them to have the few
  // first arguments they base their lookup on, so that we transfer them
  // correctly.
  if (startsWith(Exp->Name, HAContext::MsgLookupPrefix)) {
    FlagsSetter();
    Exp->setType(LLVM.LookupTy);

    // Don't verify their types.
    return false;
  }

  // Skip type verification of vararg functions. It doesn't work well -
  // at least for `_NSLog`. There is a weird bug that happens randomly -
  // sometimes everything works fine, sometimes there is an assertion
  // failure `Assertion failed: isValidArgumentType(Params[i]) && "Not a
  // valid type for function argument!", file ..\..\lib\IR\Type.cpp,
  // line 288`.
  // TODO: Investigate and fix this bug.
  if (Exp->getDylibType()->isVarArg())
    return false;

  return true;
}
