// HeadersAnalyzer.cpp : Defines the entry point for the console application.
//

#include "ClangHelper.hpp"
#include "Config.hpp"
#include "HAContext.hpp"
#include "LLDBHelper.hpp"
#include "LLDHelper.hpp"
#include "LLVMHelper.hpp"
#include "TapiHelper.hpp"

#include <Plugins/SymbolFile/PDB/PDBASTParser.h>
#include <Plugins/SymbolFile/PDB/SymbolFilePDB.h>
#include <lldb/Core/Debugger.h>
#include <lldb/Core/Module.h>
#include <lldb/Symbol/ClangASTContext.h>
#include <lldb/Symbol/ClangUtil.h>
#include <lldb/Symbol/Type.h>

#include <CodeGen/CodeGenModule.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Type.h>
#include <clang/CodeGen/CodeGenABITypes.h>
#include <clang/CodeGen/CodeGenAction.h>
#include <clang/Driver/Compilation.h>
#include <clang/Driver/Driver.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Parse/ParseAST.h>

#include <llvm/DebugInfo/PDB/PDBSymbolFunc.h>
#include <llvm/DebugInfo/PDB/PDBSymbolPublicSymbol.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Mangler.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/ValueSymbolTable.h>
#include <llvm/Object/COFF.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Transforms/Utils/FunctionComparator.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

using namespace clang;
using namespace frontend;
using namespace std;
using namespace filesystem;
using namespace tapi::internal;

// TODO: Generate distinct wrappers only for functions with distinct signatures.
// And then export those wrappers as aliases for all functions with the same
// signature.
// TODO: Also analyze WinObjC's header files to find API status information and
// also our DLLs, e.g., our Objective-C runtime to find types of
// assembly-implemented functions.
class HeadersAnalyzer {
public:
  HeadersAnalyzer() : LLVM(LLVMInit) {}

  void discoverTBDs() {
    reportStatus("discovering TBDs");

    TBDHandler TH(HAC);
    if constexpr (Sample) {
      TH.handleFile("./deps/apple-headers/iPhoneOS11.1.sdk/System/Library/"
                    "Frameworks/UIKit.framework/UIKit.tbd");
      TH.handleFile("./deps/apple-headers/iPhoneOS11.1.sdk/System/Library/"
                    "Frameworks/Foundation.framework/Foundation.tbd");
    } else {
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
    }

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
    reportStatus("discovering DLLs");

    // Note that groups must be added just once and together because references
    // to them are invalidated after that.
    HAC.DLLGroups.push_back({"../build/ipasim-x86-Debug/bin/Frameworks/"});
    if constexpr (!Sample) {
      HAC.DLLGroups.push_back({"../build/ipasim-x86-Debug/bin/"});
      HAC.DLLGroups.push_back(
          {"./deps/WinObjC/tools/deps/prebuilt/Universal Windows/x86/"});
      HAC.DLLGroups.push_back({"./lib/crt/"});
    }
    size_t I = 0;

    if constexpr (Sample)
      HAC.DLLGroups[I++].DLLs.push_back(DLLEntry("UIKit.dll"));
    else {
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

      // Our Objective-C runtime
      HAC.DLLGroups[I++].DLLs.push_back(DLLEntry("libobjc.dll"));

      // Prebuilt `libdispatch.dll`
      HAC.DLLGroups[I++].DLLs.push_back(DLLEntry("libdispatch.dll"));

      // C runtime
      HAC.DLLGroups[I++].DLLs.push_back(DLLEntry("ucrtbased.dll"));
    }
  }
  void parseAppleHeaders() {
    reportStatus("parsing Apple headers");

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
    reportStatus("loading DLLs");

    using namespace llvm::pdb;
    LLDBHelper LLDB;
    ClangHelper Clang(LLVM);

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
    for (auto [GroupIdx, DLLGroup] : withIndices(HAC.DLLGroups)) {
      for (auto [DLLIdx, DLL] : withIndices(DLLGroup.DLLs)) {
        path DLLPath(DLLGroup.Dir / DLL.Name);
        path PDBPath(DLLPath);
        PDBPath.replace_extension(".pdb");

        string DLLPathStr(DLLPath.string());
        LLDB.load(DLLPathStr.c_str(), PDBPath.string().c_str());
        TypeComparer TC(*CGM, LLVM.getModule(), LLDB.getSymbolFile());

        // Load DLL.
        auto DLLFile(llvm::object::ObjectFile::createObjectFile(DLLPathStr));
        if (!DLLFile) {
          reportError(Twine(toString(DLLFile.takeError())) + " (" + DLLPathStr +
                      ")");
          continue;
        }
        auto COFF =
            dyn_cast<llvm::object::COFFObjectFile>(DLLFile->getBinary());
        if (!COFF) {
          reportError(Twine("expected COFF (") + DLLPathStr + ")");
          continue;
        }

        // Discover exports.
        std::set<uint32_t> Exports;
        for (auto &Export : COFF->export_directories()) {
          uint32_t ExportRVA;
          if (error_code Error = Export.getExportRVA(ExportRVA)) {
            reportError(Twine("cannot get RVA of an export symbol (") +
                        DLLPathStr + "): " + Error.message());
            continue;
          }
          // Note that there can be aliases, so the current `ExportRVA` can
          // already be present in `Exports`, but that's OK.
          Exports.insert(ExportRVA);
        }

        // Analyze functions.
        auto Analyzer = [&, DLL = ref(DLL), GroupIdx = GroupIdx,
                         DLLIdx = DLLIdx](auto &&Func, bool IgnoreDuplicates =
                                                           false) mutable {
          string Name(Func.getName());
          uint32_t RVA = Func.getRelativeVirtualAddress();

          // If undecorated name has underscore at the beginning, use that
          // instead.
          // TODO: This eliminates exporting some functions (e.g., `fdopen` from
          // `ucrtbased`). But if we didn't do that, linking would fail due to
          // unresolved symbols (because of different underscore prefixes). On
          // the other hand, we probably want those functions to be exported.
          string UN(Func.getUndecoratedName());
          if (!UN.empty() && Name != UN && UN[0] == '_' &&
              !UN.compare(1, Name.length(), Name))
            Name = move(UN);

          // We are only interested in exported symbols or Objective-C methods.
          if (!HAC.isClassMethod(Name) && Exports.find(RVA) == Exports.end())
            return;

          // Find the corresponding export info from TBD files.
          ExportPtr Exp;
          if (!HAC.isInterestingForWindows(Name, Exp, RVA, IgnoreDuplicates))
            return;
          bool DataSymbol = Exp->Status == ExportStatus::NotFound;

          // Update status accordingly.
          Exp->Status = ExportStatus::FoundInDLL;
          Exp->RVA = RVA;
          DLL.get().Exports.push_back(Exp);
          Exp->DLLGroup = GroupIdx;
          Exp->DLL = DLLIdx;

          // Save symbol that will serve as a reference for computing addresses
          // of Objective-C methods.
          if (!DLL.get().ReferenceSymbol && !Exp->ObjCMethod)
            DLL.get().ReferenceSymbol = Exp;

          // If this is not a function, we can skip the rest of analysis.
          if (DataSymbol)
            return;

          auto IsStretSetter = [&]() {
            // If it's a normal messenger, it has two parameters (`id` and
            // `SEL`, both actually `void *`). If it's a `stret` messenger, it
            // has one more parameter at the front (a `void *` for struct
            // return).
            Exp->Stret = !Exp->Name.compare(
                Exp->Name.size() - HAContext::StretLength,
                HAContext::StretLength, HAContext::StretPostfix);
          };

          // Find Objective-C messengers. Note that they used to be variadic,
          // but that's deprecated and so we cannot rely on that.
          if (!Exp->Name.compare(0, HAContext::MsgSendLength,
                                 HAContext::MsgSendPrefix)) {
            Exp->Messenger = true;
            IsStretSetter();

            // Don't verify their types.
            return;
          }

          // Also, change type of the lookup functions. In Apple headers, they
          // are declared as `void -> void`, but we need them to have the few
          // first arguments they base their lookup on, so that we transfer them
          // correctly.
          if (!Exp->Name.compare(0, HAContext::MsgLookupLength,
                                 HAContext::MsgLookupPrefix)) {
            IsStretSetter();
            Exp->Type = LookupTy;

            // Don't verify their types.
            return;
          }

          // Skip type verification of vararg functions. It doesn't work well -
          // at least for `_NSLog`. There is a weird bug that happens randomly -
          // sometimes everything works fine, sometimes there is an assertion
          // failure `Assertion failed: isValidArgumentType(Params[i]) && "Not a
          // valid type for function argument!", file ..\..\lib\IR\Type.cpp,
          // line 288`.
          // TODO: Investigate and fix this bug.
          if (Exp->Type->isVarArg())
            return;

          // Verify that the function has the same signature as the iOS one.
          if constexpr (CompareTypes)
            if (!TC.areEquivalent(Exp->Type, Func))
              reportError("functions' signatures are not equivalent (" +
                          Exp->Name + ")");
        };
        for (auto &Func : LLDB.enumerate<PDBSymbolFunc>())
          Analyzer(Func);
        for (auto &Func : LLDB.enumerate<PDBSymbolPublicSymbol>())
          Analyzer(Func, /* IgnoreDuplicates */ true);
      }
    }
  }
  void createDirs() {
    OutputDir = createOutputDir("../build/ipasim-x86-Debug/cg/");
    GenDir = createOutputDir("../build/ipasim-x86-Debug/gen/");
  }
  void generateDLLs() {
    reportStatus("generating DLLs");

    // Generate DLL wrappers and also stub Dylibs for them.
    for (const DLLGroup &DLLGroup : HAC.DLLGroups) {
      for (const DLLEntry &DLL : DLLGroup.DLLs) {
        path DLLPath(DLLGroup.Dir / DLL.Name);

        IRHelper IR(LLVM, DLL.Name, DLLPath.string(), IRHelper::Windows32);
        IRHelper DylibIR(LLVM, DLL.Name, DLLPath.string(), IRHelper::Apple);

        // Since we are transferring data in memory across architectures, they
        // must have the same endianness for that to work.
        if (IR.isLittleEndian() != DylibIR.isLittleEndian())
          reportError("target platforms don't have the same endianness");
        else
          assert(IR.isBigEndian() == DylibIR.isBigEndian() &&
                 "Inconsistency in endianness.");

        // Declare reference symbol.
        llvm::GlobalValue *RefSymbol =
            !DLL.ReferenceSymbol ? nullptr : IR.declare(*DLL.ReferenceSymbol);
        if (RefSymbol)
          RefSymbol->setDLLStorageClass(
              llvm::GlobalValue::DLLImportStorageClass);

        // Generate function wrappers.
        for (const ExportEntry &Exp : deref(DLL.Exports)) {
          assert(Exp.Status == ExportStatus::FoundInDLL &&
                 "Unexpected status of `ExportEntry`.");

          // Don't generate wrappers for Objective-C messengers. We handle those
          // specially. Also don't generate wrappers for data.
          if (!Exp.Type || Exp.Messenger)
            continue;

          // TODO: Handle variadic functions specially.
          if (Exp.Type->isVarArg())
            reportError(Twine("unhandled variadic function (") + Exp.Name +
                        ")");

          // Declarations.
          llvm::Function *Func = Exp.ObjCMethod ? nullptr : IR.declareFunc(Exp);
          llvm::Function *Wrapper = IR.declareFunc(Exp, /* Wrapper */ true);
          llvm::Function *Stub = DylibIR.declareFunc(Exp, /* Wrapper */ true);

          // Export the wrapper and import the original function.
          Wrapper->setDLLStorageClass(llvm::Function::DLLExportStorageClass);
          if (Func)
            Func->setDLLStorageClass(llvm::Function::DLLImportStorageClass);

          // Generate the Dylib stub.
          DylibIR.defineFunc(Stub);
          DylibIR.Builder.CreateRetVoid();

          FunctionGuard WrapperGuard(IR, Wrapper);

          llvm::Value *UP;
          vector<llvm::Value *> Args;
          if (Exp.isTrivial()) {
            // Trivial functions (`void -> void`) have no arguments, so no union
            // pointer exists - we set it to `nullptr` to check that we don't
            // use it anywhere in the following code.
            UP = nullptr;
          } else {
            auto [Struct, Union] = IR.createParamStruct(Exp);

            // The union pointer is in the first argument.
            UP = Wrapper->args().begin();

            // Get pointer to the structure inside the union.
            llvm::Value *SP =
                IR.Builder.CreateBitCast(UP, Struct->getPointerTo(), "sp");

            // Process arguments.
            Args.reserve(Exp.Type->getNumParams());
            for (auto [ArgIdx, ArgTy] : withIndices(Exp.Type->params())) {
              string ArgNo = to_string(ArgIdx);

              // Load argument from the structure.
              llvm::Value *APP =
                  IR.Builder.CreateStructGEP(Struct, SP, ArgIdx, "app" + ArgNo);
              llvm::Value *AP = IR.Builder.CreateLoad(APP, "ap" + ArgNo);
              llvm::Value *A = IR.Builder.CreateLoad(AP, "a" + ArgNo);

              // Save the argument.
              Args.push_back(A);
            }
          }

          llvm::Value *R;
          if (Exp.ObjCMethod) {
            // Objective-C methods are not exported, so we call them by
            // computing their address using their RVA.
            if (!DLL.ReferenceSymbol) {
              reportError("no reference function, cannot emit Objective-C "
                          "method DLL wrappers (" +
                          DLL.Name + ")");
              continue;
            }

            // Add RVA to the reference symbol's address.
            llvm::Value *Addr = llvm::ConstantInt::getSigned(
                llvm::Type::getInt32Ty(LLVM.Ctx),
                Exp.RVA - DLL.ReferenceSymbol->RVA);
            llvm::Value *RefPtr =
                IR.Builder.CreateBitCast(RefSymbol, VoidPtrTy);
            llvm::Value *ComputedPtr = IR.Builder.CreateInBoundsGEP(
                llvm::Type::getInt8Ty(LLVM.Ctx), RefPtr, Addr);
            llvm::Value *FP = IR.Builder.CreateBitCast(
                ComputedPtr, Exp.Type->getPointerTo(), "fp");

            // Call the original DLL function.
            R = IR.createCall(Exp.Type, FP, Args, "r");
          } else
            R = IR.createCall(Func, Args, "r");

          if (R) {
            // Get pointer to the return value inside the union.
            llvm::Value *RP = IR.Builder.CreateBitCast(
                UP, Exp.Type->getReturnType()->getPointerTo(), "rp");

            // Save return value back into the structure.
            IR.Builder.CreateStore(R, RP);
          }

          // Finish.
          IR.Builder.CreateRetVoid();
        }

        // Generate `WrapperIndex`.
        string IndexFile(
            (OutputDir / DLL.Name).replace_extension(".cpp").string());
        {
          ofstream OS;
          OS.open(IndexFile, ios_base::out | ios_base::trunc);
          if (!OS) {
            reportError(llvm::Twine("cannot create index file for ") +
                        DLL.Name);
            continue;
          }

          ifstream IS;
          IS.open("./src/HeadersAnalyzer/WrapperIndex.cpp");
          if (!IS) {
            reportError("cannot open WrapperIndex.cpp");
            continue;
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
            (OutputDir / DLL.Name).replace_extension(".obj").string());
        IR.emitObj(ObjectFile);

        // Create the wrapper DLL.
        {
          ClangHelper Clang(LLVM);
          // See #24.
          if (DLL.Name == "ucrtbased.dll")
            Clang.Args.add("./lib/crt/stubs.obj");

          Clang.Args.add("-I./src/HeadersAnalyzer/include");
          Clang.Args.add(IndexFile.c_str());

          Clang.linkDLL(
              (GenDir / DLL.Name).replace_extension(".wrapper.dll").string(),
              ObjectFile, path(DLLPath).replace_extension(".dll.a").string());
        }

        // Emit `.o` file.
        string DylibObjectFile(
            (OutputDir / DLL.Name).replace_extension(".o").string());
        DylibIR.emitObj(DylibObjectFile);

        // Create the stub Dylib.
        LLDHelper(LLVM).linkDylib(
            (OutputDir / ("lib" + DLL.Name))
                .replace_extension(".dll.dylib")
                .string(),
            DylibObjectFile,
            path("/" + DLL.Name).replace_extension(".wrapper.dll").string());
      }
    }
  }
  void generateDylibs() {
    reportStatus("generating Dylibs");

    size_t Unimplemented = 0;
    for (auto [LibIdx, Lib] : withIndices(HAC.iOSLibs)) {
      string LibNo = to_string(LibIdx);

      IRHelper IR(LLVM, LibNo, Lib.Name, IRHelper::Apple);

      // Generate function wrappers.
      // TODO: Shouldn't we use aligned instructions?
      for (const ExportEntry &Exp : deref(Lib.Exports)) {

        // Ignore functions that haven't been found in any DLL.
        if (Exp.Status != ExportStatus::FoundInDLL) {
          if constexpr (ErrorUnimplementedFunctions & LibType::DLL)
            if (Exp.Status == ExportStatus::Found)
              reportError(
                  Twine("function found in Dylib wasn't found in any DLL (") +
                  Exp.Name + ")");
          if constexpr (SumUnimplementedFunctions & LibType::DLL)
            if (Exp.Status == ExportStatus::Found)
              ++Unimplemented;
          continue;
        }

        // Re-export data symbols. See #23.
        if (!Exp.Type) {
          Lib.ReExports.insert({Exp.DLLGroup, Exp.DLL});
          continue;
        }

        // Handle Objective-C messengers specially.
        if (Exp.Messenger) {
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
          llvm::Function *MessengerFunc = IR.declareFunc(SendTy, Exp.Name);
          createAlias(Exp, MessengerFunc);

          // And define it, too.
          FunctionGuard MessengerGuard(IR, MessengerFunc);

          // Construct name of the corresponding lookup function.
          Twine LookupName(Twine(HAContext::MsgLookupPrefix) +
                           (Exp.Name.c_str() + HAContext::MsgSendLength));

          // If the corresponding lookup function doesn't exist, don't call it
          // (so that we don't have unresolved references in the resulting
          // binary).
          if (HAC.iOSExps.find(ExportEntry(LookupName.str())) ==
              HAC.iOSExps.end()) {
            reportError(Twine("lookup function not found (") + LookupName +
                        ")");
            IR.Builder.CreateRetVoid();
            continue;
          }

          // Declare the lookup function.
          llvm::Function *LookupFunc = IR.declareFunc(LookupTy, LookupName);

          // Collect arguments.
          vector<llvm::Value *> Args;
          Args.reserve(MessengerFunc->arg_size());
          for (llvm::Argument &Arg : MessengerFunc->args())
            Args.push_back(&Arg);

          // Call the lookup function and jump to its result.
          llvm::Value *IMP = IR.Builder.CreateCall(LookupFunc, Args, "imp");
          llvm::CallInst *Call = IR.Builder.CreateCall(
              MessengerFunc->getFunctionType(), IMP, Args);
          Call->setTailCallKind(llvm::CallInst::TCK_MustTail);
          IR.Builder.CreateRetVoid();

          continue;
        }

        // Declarations.
        llvm::Function *Func = IR.declareFunc(Exp);
        llvm::Function *Wrapper = IR.declareFunc(Exp, /* Wrapper */ true);
        createAlias(Exp, Func);

        FunctionGuard FuncGuard(IR, Func);

        // Handle trivial `void -> void` functions specially.
        if (Exp.isTrivial()) {
          IR.Builder.CreateCall(Wrapper);
          IR.Builder.CreateRetVoid();
          continue;
        }

        auto [Struct, Union] = IR.createParamStruct(Exp);

        // Allocate the union.
        llvm::Value *S = IR.Builder.CreateAlloca(Union, nullptr, "s");

        // Get pointer to the structure inside it.
        llvm::Value *SP =
            IR.Builder.CreateBitCast(S, Struct->getPointerTo(), "sp");

        // Process arguments.
        for (llvm::Argument &Arg : Func->args()) {
          string ArgNo = to_string(Arg.getArgNo());

          // Load the argument.
          llvm::Value *AP =
              IR.Builder.CreateAlloca(Arg.getType(), nullptr, "ap" + ArgNo);
          IR.Builder.CreateStore(&Arg, AP);

          // Get pointer to the corresponding structure's element.
          llvm::Value *EP = IR.Builder.CreateStructGEP(
              Struct, SP, Arg.getArgNo(), "ep" + ArgNo);

          // Store argument address in it.
          IR.Builder.CreateStore(AP, EP);
        }

        // Call the DLL wrapper function.
        llvm::Value *VP = IR.Builder.CreateBitCast(
            SP, llvm::Type::getInt8PtrTy(LLVM.Ctx), "vp");
        IR.Builder.CreateCall(Wrapper, {VP});

        // Return.
        llvm::Type *RetTy = Exp.Type->getReturnType();
        if (!RetTy->isVoidTy()) {

          // Get pointer to the return value inside the union.
          llvm::Value *RP =
              IR.Builder.CreateBitCast(S, RetTy->getPointerTo(), "rp");

          // Load and return it.
          llvm::Value *R = IR.Builder.CreateLoad(RP, "r");
          IR.Builder.CreateRet(R);
        } else
          IR.Builder.CreateRetVoid();
      }

      // Emit `.o` file.
      string ObjectFile((OutputDir / (LibNo + ".o")).string());
      IR.emitObj(ObjectFile);

      // We add `./` to the library name to convert it to a relative path.
      path DylibPath(GenDir / ("./" + Lib.Name));

      // Initialize LLD args to create the Dylib.
      LLDHelper LLD(LLVM);
      LLD.addDylibArgs(DylibPath.string(), ObjectFile, Lib.Name);
      LLD.Args.add(("-L" + OutputDir.string()).c_str());

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
        reportError(
            Twine("functions found in Dylibs weren't found in any DLL (") +
            to_string(Unimplemented) + ")");
  }
  void writeReport() {
    if (auto OS = createOutputFile((OutputDir / "exports.txt").string()))
      for (const ExportEntry &Exp : HAC.iOSExps)
        if (Exp.Status == ExportStatus::FoundInDLL)
          *OS << Exp.Name << '\n';
  }

private:
  HAContext HAC;
  LLVMInitializer LLVMInit;
  LLVMHelper LLVM;
  path OutputDir, GenDir;

  // Some common types.
  llvm::Type *VoidTy = llvm::Type::getVoidTy(LLVM.Ctx);
  llvm::Type *VoidPtrTy = llvm::Type::getInt8PtrTy(LLVM.Ctx);
  llvm::FunctionType *SendTy = llvm::FunctionType::get(
      VoidTy, {VoidPtrTy, VoidPtrTy, VoidPtrTy, VoidPtrTy},
      /* isVarArg */ false);
  llvm::FunctionType *LookupTy = llvm::FunctionType::get(
      SendTy->getPointerTo(), {VoidPtrTy, VoidPtrTy, VoidPtrTy, VoidPtrTy},
      /* isVarArg */ false);

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
      reportError("function overloaded (" + Name + ")");
      return;
    case ExportStatus::Overloaded:
      return;
    case ExportStatus::NotFound:
      Exp->Status = ExportStatus::Found;
      break;
    default:
      reportFatalError("unexpected status of `ExportEntry`");
    }

    // Save the function's signature.
    Exp->Type = Type;
  }
  void compileAppleHeaders() {
    ClangHelper Clang(LLVM);
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
    llvm::GlobalAlias::create(Twine("\01$__ipaSim_wraps_") + RVAStr, Func);
  }
};

int main() {
  try {
    HeadersAnalyzer HA;
    HA.discoverTBDs();
    HA.discoverDLLs();
    HA.parseAppleHeaders();
    HA.loadDLLs();
    HA.createDirs();
    HA.generateDLLs();
    HA.generateDylibs();
    HA.writeReport();
  } catch (const FatalError &) {
    return 1;
  }

  return 0;
}
