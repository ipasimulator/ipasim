// DLLHelper.cpp

#include "ipasim/DLLHelper.hpp"

#include "ipasim/HeadersAnalyzer/Config.hpp"
#include "ipasim/LLDHelper.hpp"
#include "ipasim/ObjCHelper.hpp"

#include <fstream>
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
    } else if constexpr (is_same_v<decltype(Func), PDBSymbolFunc &>) {
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

void DLLHelper::generate(const DirContext &DC, bool Debug) {
  IRHelper IR(LLVM, DLL.Name, DLLPath.string(), IRHelper::Windows32);
  IRHelper DylibIR(LLVM, DLL.Name, DLLPath.string(), IRHelper::Apple);

  // Since we are transferring data in memory across architectures, they
  // must have the same endianness for that to work.
  if (IR.isLittleEndian() != DylibIR.isLittleEndian())
    Log.error("target platforms don't have the same endianness");
  else
    assert(IR.isBigEndian() == DylibIR.isBigEndian() &&
           "Inconsistency in endianness.");

  // Declare reference symbol.
  GlobalValue *RefSymbol = !DLL.ReferenceSymbol
                               ? nullptr
                               : IR.declare<LibType::DLL>(*DLL.ReferenceSymbol);
  if (RefSymbol)
    RefSymbol->setDLLStorageClass(GlobalValue::DLLImportStorageClass);

  // Generate function wrappers.
  for (const ExportEntry &Exp : deref(DLL.Exports)) {
    assert(Exp.Status == ExportStatus::FoundInDLL &&
           "Unexpected status of `ExportEntry`.");

    // Don't generate wrappers for Objective-C messengers. We handle those
    // specially. Also don't generate wrappers for data.
    if (!Exp.getDLLType() || Exp.Messenger)
      continue;

    // Declarations.
    Function *Func =
        Exp.ObjCMethod ? nullptr : IR.declareFunc<LibType::DLL>(Exp);
    Function *Wrapper = IR.declareFunc<LibType::DLL>(Exp, /* Wrapper */ true);
    Function *Stub =
        DylibIR.declareFunc<LibType::Dylib>(Exp, /* Wrapper */ true);

    // Export the wrapper and import the original function.
    Wrapper->setDLLStorageClass(Function::DLLExportStorageClass);
    if (Func)
      Func->setDLLStorageClass(Function::DLLImportStorageClass);

    // Generate the Dylib stub.
    DylibIR.defineFunc(Stub);
    DylibIR.Builder.CreateRetVoid();

    FunctionGuard WrapperGuard(IR, Wrapper);

    // TODO: Handle variadic functions specially. For now, we simply don't
    // call them.
    if (Exp.getDLLType()->isVarArg()) {
      Log.error() << "unhandled variadic function (" << Exp.Name << ")"
                  << Log.end();
      IR.Builder.CreateRetVoid();
      continue;
    }

    StructType *Struct;
    Value *SP;
    vector<Value *> Args;
    if (Exp.isTrivial()) {
      // Trivial functions (`void -> void`) have no arguments, so no
      // struct pointer nor type exist - we set them to `nullptr` to check
      // that we don't use them anywhere in the following code.
      Struct = nullptr;
      SP = nullptr;
    } else {
      // The struct pointer is the first argument.
      Struct = IR.createParamStruct(Exp);
      SP = IR.Builder.CreateBitCast(Wrapper->args().begin(),
                                    Struct->getPointerTo(), "sp");

      // Process arguments.
      Args.reserve(Exp.getDLLType()->getNumParams());
      for (auto [ArgIdx, ArgTy] : withIndices(Exp.getDLLType()->params())) {
        if (Exp.DylibStretOnly)
          ++ArgIdx;

        string ArgNo = to_string(ArgIdx);

        // Load argument from the structure.
        Value *APP = IR.Builder.CreateStructGEP(Struct, SP, ArgIdx,
                                                Twine("app") + ArgNo);
        Value *AP = IR.Builder.CreateLoad(APP, Twine("ap") + ArgNo);
        Value *A = IR.Builder.CreateLoad(AP, Twine("a") + ArgNo);

        // Save the argument.
        Args.push_back(A);
      }
    }

    Value *R;
    if (Exp.ObjCMethod) {
      // Objective-C methods are not exported, so we call them by
      // computing their address using their RVA.
      if (!DLL.ReferenceSymbol) {
        Log.error() << "no reference function, cannot emit Objective-C "
                       "method DLL wrappers ("
                    << DLL.Name << ")" << Log.end();
        continue;
      }

      // Add RVA to the reference symbol's address.
      Value *Addr = ConstantInt::getSigned(Type::getInt32Ty(LLVM.Ctx),
                                           Exp.RVA - DLL.ReferenceSymbol->RVA);
      Value *RefPtr = IR.Builder.CreateBitCast(RefSymbol, LLVM.VoidPtrTy);
      Value *ComputedPtr =
          IR.Builder.CreateInBoundsGEP(Type::getInt8Ty(LLVM.Ctx), RefPtr, Addr);
      Value *FP = IR.Builder.CreateBitCast(
          ComputedPtr, Exp.getDLLType()->getPointerTo(), "fp");

      // Call the original DLL function.
      R = IR.createCall(Exp.getDLLType(), FP, Args, "r");
    } else
      R = IR.createCall(Func, Args, "r");

    if (R) {
      // See #28.
      if (Exp.DylibStretOnly) {
        // Store the return value.
        Value *RS = IR.Builder.CreateAlloca(R->getType());
        IR.Builder.CreateStore(R, RS);

        // Load stret argument from the structure.
        Value *SRPP = IR.Builder.CreateStructGEP(Struct, SP, 0, "srpp");
        Value *SRP = IR.Builder.CreateLoad(SRPP, "srp");
        Value *SR = IR.Builder.CreateLoad(SRP, "sr");

        // Copy structure's content.
        // TODO: Don't hardcode the alignments here.
        IR.Builder.CreateMemCpy(SR, 4, RS, 4, IR.getSize(R->getType()));
      } else { // !Exp.DylibStretOnly
        // Get pointer to the return value inside the union.
        Value *RP = IR.Builder.CreateStructGEP(
            Struct, SP, Exp.getDLLType()->getNumParams(), "rp");

        // Save return value back into the structure.
        IR.Builder.CreateStore(R, RP);
      }
    }

    // Finish.
    IR.Builder.CreateRetVoid();
  }

  // Generate `WrapperIndex`.
  string IndexFile(
      (DC.OutputDir / DLL.Name).replace_extension(".cpp").string());
  {
    ofstream OS;
    OS.open(IndexFile, ios_base::out | ios_base::trunc);
    if (!OS) {
      Log.error() << "cannot create index file for " << DLL.Name << Log.end();
      return;
    }

    ifstream IS;
    IS.open("./src/HeadersAnalyzer/WrapperIndex.cpp");
    if (!IS) {
      Log.error("cannot open WrapperIndex.cpp");
      return;
    }

    OS << IS.rdbuf();

    // Add libraries.
    std::map<DylibPtr, size_t> Dylibs;
    size_t Counter = 0;
    for (const ExportEntry &Exp : deref(DLL.Exports))
      if (Exp.Dylib && Dylibs.find(Exp.Dylib) == Dylibs.end()) {
        Dylibs[Exp.Dylib] = Counter++;
        OS << "ADD_LIBRARY(\"" << Exp.Dylib->Name << "\");\n";
      }

    // Fill the index.
    for (const ExportEntry &Exp : deref(DLL.Exports))
      if (Exp.Dylib)
        OS << "MAP(" << Exp.RVA << ", " << Dylibs[Exp.Dylib] << ");\n";

    OS << "END\n";
    OS.flush();
  }

  // Emit `.obj` file.
  string ObjectFile(
      (DC.OutputDir / DLL.Name).replace_extension(".obj").string());
  IR.emitObj(DC.BuildDir, ObjectFile);

  // Create the wrapper DLL.
  {
    ClangHelper Clang(DC.BuildDir, LLVM);
    // See #24.
    if (DLL.Name == (Debug ? "ucrtbased.dll" : "ucrtbase.dll"))
      Clang.Args.add(
          (DC.BuildDir / "src/crt/CMakeFiles/crtstubs.dir/stubs.cpp.obj")
              .string()
              .c_str());

    Clang.Args.add("-I./include");
    Clang.Args.add(IndexFile.c_str());

    Clang.linkDLL(
        (DC.GenDir / DLL.Name).replace_extension(".wrapper.dll").string(),
        ObjectFile, path(DLLPath).replace_extension(".dll.a").string(), Debug);
  }

  // Emit `.o` file.
  string DylibObjectFile(
      (DC.OutputDir / DLL.Name).replace_extension(".o").string());
  DylibIR.emitObj(DC.BuildDir, DylibObjectFile);

  // Create the stub Dylib.
  {
    LLDHelper LLD(DC.BuildDir, LLVM);
    LLD.linkDylib(
        (DC.OutputDir / ("lib" + DLL.Name))
            .replace_extension(".dll.dylib")
            .string(),
        DylibObjectFile,
        path("/" + DLL.Name).replace_extension(".wrapper.dll").string());
  }
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
