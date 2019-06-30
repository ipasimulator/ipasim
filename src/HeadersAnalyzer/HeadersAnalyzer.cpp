// HeadersAnalyzer.cpp: Main logic of tool `HeadersAnalyzer`.

#include "ipasim/ClangHelper.hpp"
#include "ipasim/DLLHelper.hpp"
#include "ipasim/HAContext.hpp"
#include "ipasim/HeadersAnalyzer/Config.hpp"
#include "ipasim/LLDBHelper.hpp"
#include "ipasim/LLDHelper.hpp"
#include "ipasim/LLVMHelper.hpp"
#include "ipasim/ObjCHelper.hpp"
#include "ipasim/TapiHelper.hpp"

#include <CodeGen/CodeGenModule.h>
#include <Plugins/SymbolFile/PDB/PDBASTParser.h>
#include <Plugins/SymbolFile/PDB/SymbolFilePDB.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Type.h>
#include <clang/CodeGen/CodeGenABITypes.h>
#include <clang/CodeGen/CodeGenAction.h>
#include <clang/Driver/Compilation.h>
#include <clang/Driver/Driver.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Parse/ParseAST.h>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <lldb/Core/Debugger.h>
#include <lldb/Core/Module.h>
#include <lldb/Symbol/ClangASTContext.h>
#include <lldb/Symbol/ClangUtil.h>
#include <lldb/Symbol/Type.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Mangler.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/ValueSymbolTable.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Transforms/Utils/FunctionComparator.h>
#include <vector>

using namespace clang;
using namespace clang::frontend;
using namespace ipasim;
using namespace std;
using namespace std::filesystem;
using namespace tapi::internal;

namespace {

// Encapsulates the workflow of `HeadersAnalyzer`.
// TODO: Generate distinct wrappers only for functions with distinct signatures.
// And then export those wrappers as aliases for all functions with the same
// signature.
// TODO: Also analyze WinObjC's header files to find API status information and
// also our DLLs, e.g., our Objective-C runtime to find types of
// assembly-implemented functions.
class HeadersAnalyzer {
public:
  HeadersAnalyzer(path BuildDir, bool Debug) : Debug(Debug), LLVM(LLVMInit) {
    DC.BuildDir = move(BuildDir);
  }

  void discoverTBDs() {
    Log.info("discovering TBDs");

    TBDHandler TH(HAC);
    vector<string> Dirs{
        "./deps/apple-headers/iPhoneOS11.1.sdk/usr/lib/",
        "./deps/apple-headers/iPhoneOS11.1.sdk/System/Library/TextInput/"};
    for (const string &Dir : Dirs)
      for (auto &File : directory_iterator(Dir))
        TH.handleFile(File.path().string());
    // Discover `.tbd` files inside frameworks.
    string FrameworksDir =
        "./deps/apple-headers/iPhoneOS11.1.sdk/System/Library/Frameworks/";
    for (auto &File : directory_iterator(FrameworksDir))
      if (File.status().type() == file_type::directory &&
          !File.path().extension().compare(".framework"))
        TH.handleFile(
            (File.path() / File.path().filename().replace_extension(".tbd"))
                .string());

    // Fill `ExportEntry.Dylib` fields. This must not be done earlier since
    // `DylibPtr`s need to be stable.
    // TODO: Maybe don't do this and have only Objective-C methods inside
    // `WrapperIndex`.
    for (auto [LibPtr, Lib] : withPtrs(HAC.iOSLibs))
      for (const ExportPtr &Exp : Lib.Exports)
        if (!Exp->Dylib)
          Exp->Dylib = LibPtr;
  }
  void discoverDLLs() {
    Log.info("discovering DLLs");

    // Note that groups must be added just once and together because references
    // to them are invalidated after that.
    HAC.DLLGroups.push_back({DC.BuildDir / "bin/"});
    if constexpr (!Sample) {
      HAC.DLLGroups.push_back({DC.BuildDir / "bin/Frameworks/"});
      HAC.DLLGroups.push_back(
          {"./deps/WinObjC/tools/deps/prebuilt/Universal Windows/x86/"});
      HAC.DLLGroups.push_back({"./deps/crt/"});
    }
    size_t I = 0;

    // Our Objective-C runtime
    HAC.DLLGroups[I++].DLLs.push_back(DLLEntry("libobjc.dll"));

    if constexpr (!Sample) {
      // WinObjC DLLs (i.e., Windows versions of Apple's frameworks)
      DLLGroup &FxGroup = HAC.DLLGroups[I++];
      for (auto &File : directory_iterator(FxGroup.Dir)) {
        path FilePath(File.path());

        // We are only interested in DLLs that have accompanying PDBs with them.
        if (FilePath.extension() == ".pdb") {
          path DLLPath(FilePath.replace_extension(".dll"));
          if (exists(DLLPath))
            FxGroup.DLLs.push_back(DLLEntry(DLLPath.filename().string()));
        }
      }

      // Prebuilt `libdispatch.dll`
      HAC.DLLGroups[I++].DLLs.push_back(DLLEntry("libdispatch.dll"));

      // C runtime
      HAC.DLLGroups[I++].DLLs.push_back(
          DLLEntry(Debug ? "ucrtbased.dll" : "ucrtbase.dll"));
    }
  }
  void parseAppleHeaders() {
    Log.info("parsing Apple headers");

    compileAppleHeaders();

    for (const llvm::Function &Func : *LLVM.getModule())
      analyzeAppleFunction(Func);

    // Now we simply consider all symbols found in TBDs and not in headers to be
    // data symbols.
    // TODO: We should actually search for definitions of those data symbols in
    // `Module`, as well, to be sure they're really data and not functions. But
    // be aware that class symbols (e.g., `_OBJC_CLASS_$_NSObject`) are probably
    // not gonna be listed explicitly in `Module`'s tables.
  }
  void loadDLLs() {
    Log.info("loading DLLs");

    LLDBHelper LLDB;
    ClangHelper Clang(DC.BuildDir, LLVM);

    // Create `clang::CodeGen::CodeGenModule` needed in our `TypeComparer`.
    Clang.Args.add("-target");
    Clang.Args.add(IRHelper::Windows32);
    // Note that this file is not really analyzed, but it still needs to exist
    // (because it's opened) and also its extension is important (to set
    // language options - Objective-C++ for `.mm`).
    Clang.Args.add("./src/HeadersAnalyzer/iOSHeaders.mm");
    Clang.initFromInvocation();
    Clang.executeAction<InitOnlyAction>();
    auto CGM(Clang.createCodeGenModule());

    // Load DLLs and PDBs.
    DLLHelper::forEach(HAC, LLVM, &DLLHelper::load, LLDB, Clang, CGM.get());
  }
  void createDirs() {
    DC.OutputDir = createOutputDir((DC.BuildDir / "cg/").string().c_str());
    DC.GenDir = createOutputDir((DC.BuildDir / "gen/").string().c_str());
  }
  void generateDLLs() {
    Log.info("generating DLLs");

    // Generate DLL wrappers and also stub Dylibs for them.
    DLLHelper::forEach(HAC, LLVM, &DLLHelper::generate, DC, Debug);
  }
  void generateDylibs() {
    Log.info("generating Dylibs");

    size_t Unimplemented = 0;
    for (auto [LibIdx, Lib] : withIndices(HAC.iOSLibs)) {
      string LibNo = to_string(LibIdx);

      IRHelper IR(LLVM, LibNo, Lib.Name, IRHelper::Apple);

      // Generate function wrappers.
      // TODO: Shouldn't we use aligned instructions?
      for (ExportPtr Exp : Lib.Exports) {

        // Ignore functions that haven't been found in any DLL.
        if (Exp->Status != ExportStatus::FoundInDLL) {
          if constexpr (ErrorUnimplementedFunctions & LibType::DLL)
            if (Exp->Status == ExportStatus::Found)
              Log.error() << "function found in Dylib wasn't found in any DLL ("
                          << Exp->Name << ")" << Log.end();
          if constexpr (SumUnimplementedFunctions & LibType::DLL)
            if (Exp->Status == ExportStatus::Found)
              ++Unimplemented;
          continue;
        }

        // Re-export data symbols. See #23.
        if (!Exp->getDylibType()) {
          Lib.ReExports.insert({Exp->DLLGroup, Exp->DLL});
          continue;
        }

        // Handle Objective-C messengers specially.
        if (Exp->Messenger) {
          // Now here comes the trick. We actually declare the `msgSend`
          // function to have four parameters. `msgLookup` is declared to return
          // a four-parameter function. We then call `msgLookup` inside of
          // `msgSend` and tail-call the result. Thanks to that four parameters,
          // no parameter registers are changed when jumping to the result of
          // `msgLookup`. And thanks to that tail call, even returning should
          // work correctly.
          // TODO: Ideally, we would like to use `PreserveMost` CC (see commit
          // `eeae6dc2`), but it's only for `x86_64` right now.

          // Declare the messenger.
          llvm::Function *MessengerFunc =
              IR.declareFunc(LLVM.SendTy, Exp->Name);
          createAlias(*Exp, MessengerFunc);

          // And define it, too.
          FunctionGuard MessengerGuard(IR, MessengerFunc);

          // Construct name of the corresponding lookup function.
          Twine LookupName(Twine(HAContext::MsgLookupPrefix.S) +
                           (Exp->Name.c_str() + HAContext::MsgSendPrefix.Len));

          // If the corresponding lookup function doesn't exist, don't call it
          // (so that we don't have unresolved references in the resulting
          // binary).
          if (HAC.iOSExps.find(ExportEntry(LookupName.str())) ==
              HAC.iOSExps.end()) {
            Exp->UnhandledMessenger = true;
            Log.error() << "lookup function not found (" << LookupName << ")"
                        << Log.end();
            IR.Builder.CreateUnreachable();
            continue;
          }

          // Declare the lookup function.
          llvm::Function *LookupFunc =
              IR.declareFunc(LLVM.LookupTy, LookupName);

          // Collect arguments.
          vector<llvm::Value *> Args;
          Args.reserve(MessengerFunc->arg_size());
          for (llvm::Argument &Arg : MessengerFunc->args())
            Args.push_back(&Arg);

          // Call the lookup function and jump to its result.
          llvm::Value *IMP = IR.Builder.CreateCall(LookupFunc, Args, "imp");
          // Also replace `super` with `super->receiver` if necessary.
          if (Exp->Super || Exp->Super2) {
            llvm::Value *Super = Args[Exp->Stret ? 1 : 0];
            llvm::Value *SuperP = IR.Builder.CreateBitCast(
                Super, llvm::Type::getInt32PtrTy(LLVM.Ctx), "superP");
            llvm::Value *ReceiverP = IR.Builder.CreateConstInBoundsGEP1_32(
                llvm::Type::getInt32Ty(LLVM.Ctx), SuperP, 0, "receiverP");
            llvm::Value *Receiver =
                IR.Builder.CreateLoad(ReceiverP, "receiver");
            Args[Exp->Stret ? 1 : 0] =
                IR.Builder.CreateIntToPtr(Receiver, LLVM.VoidPtrTy);
          }
          llvm::CallInst *Call = IR.Builder.CreateCall(
              MessengerFunc->getFunctionType(), IMP, Args);
          Call->setTailCallKind(llvm::CallInst::TCK_MustTail);
          IR.Builder.CreateRetVoid();

          continue;
        }

        // Declarations.
        llvm::Function *Func = IR.declareFunc<LibType::Dylib>(*Exp);
        llvm::Function *Wrapper =
            IR.declareFunc<LibType::Dylib>(*Exp, /* Wrapper */ true);
        createAlias(*Exp, Func);

        FunctionGuard FuncGuard(IR, Func);

        // Handle trivial `void -> void` functions specially.
        if (Exp->isTrivial()) {
          IR.Builder.CreateCall(Wrapper);
          IR.Builder.CreateRetVoid();
          continue;
        }

        // TODO: For some reason, order matters here a lot. Other orderings can
        // even generate wrong machine code. Or does it? Maybe the bug was
        // somewhere else...

        // Reserve space for arguments.
        vector<llvm::Value *> APs;
        vector<string> ArgNos;
        APs.reserve(Func->arg_size());
        ArgNos.reserve(Func->arg_size());
        for (llvm::Argument &Arg : Func->args()) {
          string ArgNo = to_string(Arg.getArgNo());
          ArgNos.push_back(ArgNo);
          APs.push_back(IR.Builder.CreateAlloca(Arg.getType(), nullptr,
                                                Twine("ap") + ArgNo));
        }

        // Allocate the struct.
        llvm::StructType *Struct = IR.createParamStruct(*Exp);
        llvm::Value *SP = IR.Builder.CreateAlloca(Struct, nullptr, "sp");

        // Load arguments.
        for (auto [I, Arg] : withIndices(Func->args()))
          IR.Builder.CreateStore(&Arg, APs[I]);

        // Process arguments.
        for (auto [I, Arg] : withIndices(Func->args())) {
          // Get pointer to the corresponding structure's element.
          llvm::Value *EP = IR.Builder.CreateStructGEP(
              Struct, SP, Arg.getArgNo(), Twine("ep") + ArgNos[I]);

          // Store argument address in it.
          IR.Builder.CreateStore(APs[I], EP);
        }

        // Call the DLL wrapper function.
        llvm::Value *VP = IR.Builder.CreateBitCast(SP, LLVM.VoidPtrTy, "vp");
        IR.Builder.CreateCall(Wrapper, {VP});

        // Return.
        llvm::Type *RetTy = Exp->getDylibType()->getReturnType();
        if (!RetTy->isVoidTy()) {

          // Get pointer to the return value inside the struct.
          llvm::Value *RP =
              IR.Builder.CreateStructGEP(Struct, SP, Func->arg_size(), "rp");

          // Load and return it.
          llvm::Value *R = IR.Builder.CreateLoad(RP, "r");
          IR.Builder.CreateRet(R);
        } else
          IR.Builder.CreateRetVoid();
      }

      // Emit `.o` file.
      string ObjectFile((DC.OutputDir / (LibNo + ".o")).string());
      IR.emitObj(DC.BuildDir, ObjectFile);

      // We add `./` to the library name to convert it to a relative path.
      path DylibPath(DC.GenDir / ("./" + Lib.Name));

      // Initialize LLD args to create the Dylib.
      LLDHelper LLD(DC.BuildDir, LLVM);
      LLD.addDylibArgs(DylibPath.string(), ObjectFile, Lib.Name);
      LLD.Args.add(("-L" + DC.OutputDir.string()).c_str());

      // Add DLLs to link.
      {
        set<pair<GroupPtr, DLLPtr>> DLLs;
        for (const ExportEntry &Exp : deref(Lib.Exports))
          if (Exp.Status == ExportStatus::FoundInDLL &&
              DLLs.insert({Exp.DLLGroup, Exp.DLL}).second) {
            LLD.Args.add(
                ("-l" + path(HAC.DLLGroups[Exp.DLLGroup].DLLs[Exp.DLL].Name)
                            .replace_extension(".dll")
                            .string())
                    .c_str());
          }
      }

      // Add re-exports.
      for (auto &ReExport : Lib.ReExports) {
        DLLGroup &Group = HAC.DLLGroups[ReExport.first];
        DLLEntry &DLL = Group.DLLs[ReExport.second];
        LLD.reexportLibrary(DLL.Name);
      }

      // Create output directory.
      createOutputDir(DylibPath.parent_path().string().c_str());

      // Link the Dylib.
      LLD.executeArgs();
    }

    if constexpr (SumUnimplementedFunctions & LibType::DLL)
      if (Unimplemented)
        Log.error() << "functions found in Dylibs weren't found in any DLL ("
                    << Unimplemented << ")" << Log.end();
  }
  void writeExports() {
    auto ExportsOS = createOutputFile((DC.OutputDir / "exports.txt").string());
    if (!ExportsOS)
      return;

    for (const ExportEntry &Exp : HAC.iOSExps)
      if (Exp.Status == ExportStatus::FoundInDLL)
        *ExportsOS << Exp.Name << " ("
                   << (Exp.getDylibType() ? "function" : "data") << " in "
                   << HAC.DLLGroups[Exp.DLLGroup].DLLs[Exp.DLL].Name << " at "
                   << llvm::format_hex(Exp.RVA, 8) << ")\n";
  }
  void writeReport() {
    auto ReportOS = createOutputFile((DC.OutputDir / "report.csv").string());
    if (!ReportOS)
      return;

    *ReportOS << "name,status,func,dll,rva,un_vararg,un_msg\n";
    for (const ExportEntry &Exp : HAC.iOSExps) {
      *ReportOS << Exp.Name << "," << static_cast<uint32_t>(Exp.Status) << ","
                << (Exp.getDylibType() ? "1," : "0,");
      if (Exp.Status == ExportStatus::FoundInDLL)
        *ReportOS << HAC.DLLGroups[Exp.DLLGroup].DLLs[Exp.DLL].Name << ","
                  << llvm::format_hex(Exp.RVA, 8) << ",";
      else
        *ReportOS << ",,";
      *ReportOS << (Exp.UnhandledVararg ? "1," : "0,")
                << (Exp.UnhandledMessenger ? "1\n" : "0\n");
    }
  }

private:
  HAContext HAC;
  LLVMInitializer LLVMInit;
  LLVMHelper LLVM;
  DirContext DC;
  bool Debug;

  void analyzeAppleFunction(const llvm::Function &Func) {
    // We use mangled names to uniquely identify functions.
    string Name(LLVM.mangleName(Func));

    analyzeAppleFunction(Name, Func.getFunctionType());
  }
  void analyzeAppleFunction(const string &Name, llvm::FunctionType *Type) {
    // Find the corresponding export info from TBD files.
    ExportPtr Exp;
    if (!HAC.isInteresting(Name, Exp))
      return;

    // Update status accordingly.
    switch (Exp->Status) {
    case ExportStatus::Found:
      Exp->Status = ExportStatus::Overloaded;
      Log.error() << "function overloaded (" << Name << ")" << Log.end();
      return;
    case ExportStatus::Overloaded:
      return;
    case ExportStatus::NotFound:
      Exp->Status = ExportStatus::Found;
      break;
    default:
      Log.fatalError("unexpected status of `ExportEntry`");
    }

    // Save the function's signature.
    Exp->setType(Type);
  }
  void compileAppleHeaders() {
    ClangHelper Clang(DC.BuildDir, LLVM);
    Clang.Args.loadConfigFile("./src/HeadersAnalyzer/analyze_ios_headers.cfg");
    if constexpr (Sample)
      Clang.Args.add("-DIPASIM_CG_SAMPLE");
    Clang.initFromInvocation();

    // Include all declarations in the result. See [emit-all-decls].
    // TODO: Maybe filter them (include only those exported from iOS Dylibs).
    Clang.CI.getLangOpts().EmitAllDecls = true;

    // But don't emit bodies, we don't need them. See [emit-bodies].
    Clang.CI.getLangOpts().EmitBodies = false;

    // Compile to LLVM IR.
    Clang.executeCodeGenAction<EmitLLVMOnlyAction>();
  }
  void createAlias(const ExportEntry &Exp, llvm::Function *Func) {
    llvm::StringRef RVAStr = LLVM.Saver.save(to_string(Exp.RVA));
    llvm::StringRef DLLName = LLVM.Saver.save(
        path(HAC.DLLGroups[Exp.DLLGroup].DLLs[Exp.DLL].Name).stem().string());
    llvm::GlobalAlias::create(
        Twine("\01$__ipaSim_wraps_") + DLLName + "_" + RVAStr, Func);
  }
};

} // namespace

int main(int ArgC, char **ArgV) {
  // Parse arguments.
  if (ArgC != 2 && (ArgC != 3 || strcmp(ArgV[1], "-d"))) {
    Log.error() << "usage: " << ArgV[0] << " [-d] path-to-build-directory"
                << Log.end();
    return 2;
  }

  try {
    HeadersAnalyzer HA(ArgV[ArgC - 1], /* Debug */ ArgC == 3);
    HA.discoverTBDs();
    HA.discoverDLLs();
    HA.parseAppleHeaders();
    HA.loadDLLs();
    HA.createDirs();
    HA.generateDLLs();
    HA.generateDylibs();
    HA.writeExports();
    HA.writeReport();
    Log.info("completed, exiting");

    // HACK: Running destructors is too slow.
    quick_exit(0);
  } catch (const FatalError &) {
    return 1;
  }

  return 0;
}
