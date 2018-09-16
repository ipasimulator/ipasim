// HeadersAnalyzer.cpp : Defines the entry point for the console application.
//

#include "ClangHelper.hpp"
#include "Config.hpp"
#include "HAContext.hpp"
#include "LLDBHelper.hpp"
#include "LLVMHelper.hpp"

#include <Plugins/SymbolFile/PDB/PDBASTParser.h>
#include <Plugins/SymbolFile/PDB/SymbolFilePDB.h>
#include <lldb/Core/Debugger.h>
#include <lldb/Core/Module.h>
#include <lldb/Symbol/ClangASTContext.h>
#include <lldb/Symbol/ClangUtil.h>
#include <lldb/Symbol/Type.h>

#include <tapi/Core/FileManager.h>
#include <tapi/Core/InterfaceFile.h>
#include <tapi/Core/InterfaceFileManager.h>

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
#include <llvm/Target/TargetMachine.h>
#include <llvm/Transforms/Utils/FunctionComparator.h>

#include <filesystem>
#include <iostream>
#include <vector>

using namespace clang;
using namespace frontend;
using namespace std;
using namespace filesystem;
using namespace tapi::internal;

enum class export_status { NotFound = 0, Found, Overloaded, Generated };

struct export_entry {
  export_entry() : status(export_status::NotFound), decl(nullptr) {}
  export_entry(string firstLib)
      : status(export_status::NotFound), decl(nullptr) {
    libs.insert(move(firstLib));
  }

  set<string> libs;
  export_status status;
  const FunctionDecl *decl;
};

// Key is symbol name.
using export_list = map<string, export_entry>;

class tbd_handler {
public:
  tbd_handler(export_list &exps)
      : exps_(exps), fm_(FileSystemOptions()), ifm_(fm_) {}
  void handle_tbd_file(const string &path) {
    // Check file.
    auto fileOrError = ifm_.readFile(path);
    if (!fileOrError) {
      cerr << "Error: " << llvm::toString(fileOrError.takeError()) << " ("
           << path << ")." << endl;
      return;
    }
    auto file = *fileOrError;
    if (!file->getArchitectures().contains(Architecture::armv7)) {
      cerr << "TBD file does not contain architecture ARMv7 (" << path << ")."
           << endl;
      return;
    }
    auto ifile = dynamic_cast<InterfaceFile *>(file);
    if (!ifile) {
      cerr << "Interface file expected (" << path << ")." << endl;
      return;
    }
    cout << "Found TBD file (" << path << ")." << endl;

    // Find exports.
    for (auto sym : ifile->exports()) {
      // Determine symbol name.
      // TODO: Skip `ObjectiveC*` symbols, since they aren't functions.
      string name;
      switch (sym->getKind()) {
      case SymbolKind::ObjectiveCClass:
        name = ("_OBJC_CLASS_$_" + sym->getName()).str();
        break;
      case SymbolKind::ObjectiveCInstanceVariable:
        name = ("_OBJC_IVAR_$_" + sym->getName()).str();
        break;
      case SymbolKind::ObjectiveCClassEHType:
        name = ("_OBJC_EHTYPE_$_" + sym->getName()).str();
        break;
      case SymbolKind::GlobalSymbol:
        name = sym->getName();
        break;
      default:
        cerr << "Unrecognized symbol type (" << sym->getAnnotatedName() << ")."
             << endl;
        continue;
      }

      // Save export.
      auto it = exps_.find(name);
      if (it != exps_.end()) {
        it->second.libs.insert(ifile->getInstallName());
      } else {
        exps_[name] = export_entry(ifile->getInstallName());
      }
    }
  }

private:
  export_list &exps_;
  tapi::internal::FileManager fm_;
  InterfaceFileManager ifm_;
};

class HeadersAnalyzer {
public:
  HeadersAnalyzer() : LLVM(LLVMInit) {}

  void parseAppleHeaders() {
    compileAppleHeaders();

    for (const llvm::Function &Func : *LLVM.getModule()) {
      analyzeAppleFunction(Func);
    }

    reportUnimplementedFunctions();
  }
  void loadDLLs() {
    using namespace llvm::pdb;
    LLDBHelper LLDB;
    ClangHelper Clang(LLVM);

    // Create `clang::CodeGen::CodeGenModule` needed in our `TypeComparer`.
    Clang.Args.add("-target");
    Clang.Args.add(IRHelper::Windows32);
    // Note that this file is not really analyzed, but it still needs to exist
    // (because it's opened) and also its extension is important (to set
    // language options - Objective-C for `.mm`).
    Clang.Args.add("./src/HeadersAnalyzer/iOSHeaders.mm");
    Clang.initFromInvocation();
    Clang.executeAction<InitOnlyAction>();
    auto CGM(Clang.createCodeGenModule());

    // Load DLLs and PDBs.
    for (DLLGroup &DLLGroup : HAC.DLLGroups) {
      for (DLLEntry &DLL : DLLGroup.DLLs) {
        path DLLPath(DLLGroup.Dir / DLL.Name);
        path PDBPath(DLLPath);
        PDBPath.replace_extension(".pdb");

        LLDB.load(DLLPath.string().c_str(), PDBPath.string().c_str());
        TypeComparer TC(*CGM, LLVM.getModule(), LLDB.getSymbolFile());

        // Analyze functions.
        auto Analyzer = [&](auto &&Func, bool IgnoreDuplicates = false) {
          string Name(LLDBHelper::mangleName(Func));

          // Find the corresponding export info from TBD files.
          ExportList::iterator Exp;
          if (!HAC.isInterestingForWindows(Name, Exp, IgnoreDuplicates))
            return;

          // Update status accordingly.
          Exp->Status = ExportStatus::FoundInDLL;
          Exp->RVA = Func.getRelativeVirtualAddress();
          DLL.Exports.push_back(&*Exp);
          Exp->DLLGroup = &DLLGroup;
          Exp->DLL = &DLL;

          // Save function that will serve as a reference for computing
          // addresses of Objective-C methods.
          if (!DLL.ReferenceFunc && !Exp->ObjCMethod)
            DLL.ReferenceFunc = &*Exp;

          // Verify that the function has the same signature as the iOS one.
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
    OutputDir = createOutputDir("./src/HeadersAnalyzer/Debug/");
    WrappersDir = createOutputDir("./out/Wrappers/");
    DylibsDir = createOutputDir("./out/Dylibs/");
  }
  void generateDLLs() {
    // Generate DLL wrappers and also stub Dylibs for them.
    for (const DLLGroup &DLLGroup : HAC.DLLGroups) {
      for (const DLLEntry &DLL : DLLGroup.DLLs) {
        path DLLPath(DLLGroup.Dir / DLL.Name);

        IRHelper IR(LLVM, DLL.Name, DLLPath.string(), IRHelper::Windows32);
        IRHelper DylibIR(LLVM, DLL.Name, DLLPath.string(), IRHelper::Apple);

        // Since we are transferring data in memory across architectures, they
        // must have the same endianness for that to work.
        if (IR.isLittleEndian() != DylibIR.isLittleEndian()) {
          reportError("target platforms don't have the same endianness");
        } else {
          assert(IR.isBigEndian() == DylibIR.isBigEndian() &&
                 "Inconsistency in endianness.");
        }

        // Declare reference function.
        // TODO: What if there are no non-Objective-C functions?
        llvm::Function *RefFunc = IR.declareFunc(DLL.ReferenceFunc);

        // Generate function wrappers.
        for (const ExportEntry *Exp : DLL.Exports) {
          assert(Exp->Status == ExportStatus::FoundInDLL &&
                 "Unexpected status of `ExportEntry`.");

          // Handle Objective-C messengers specially. Note that they used to be
          // variadic, but that's deprecated and so we cannot rely on that.
          if (!Exp->Name.compare(0, HAContext::MsgSendLength,
                                 HAContext::MsgSendPrefix)) {
            // Remember it, so that we don't have to do expensive string
            // comparison when generating Dylibs later.
            Exp->Messenger = true;

            // Don't generate wrappers for those functions.
            continue;
          }

          // TODO: Handle variadic functions specially.
          if (Exp->Type->isVarArg()) {
            reportError(Twine("unhandled variadic function (") + Exp->Name +
                        ")");
          }

          // Declarations.
          llvm::Function *Func =
              Exp->ObjCMethod ? nullptr : IR.declareFunc(Exp);
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
          if (Exp->isTrivial()) {
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
            Args.reserve(Exp->Type->getNumParams());
            size_t ArgIdx = 0;
            for (llvm::Type *ArgTy : Exp->Type->params()) {
              string ArgNo = to_string(ArgIdx);

              // Load argument from the structure.
              llvm::Value *APP =
                  IR.Builder.CreateStructGEP(Struct, SP, ArgIdx, "app" + ArgNo);
              llvm::Value *AP = IR.Builder.CreateLoad(APP, "ap" + ArgNo);
              llvm::Value *A = IR.Builder.CreateLoad(AP, "a" + ArgNo);

              // Save the argument.
              Args.push_back(A);
              ++ArgIdx;
            }
          }

          llvm::Value *R;
          if (Exp->ObjCMethod) {
            // Objective-C methods are not exported, so we call them by
            // computing their address using their RVA.
            if (!DLL.ReferenceFunc) {
              reportError("no reference function, cannot emit Objective-C "
                          "method DLL wrappers (" +
                          DLL.Name + ")");
              continue;
            }

            // Add RVA to the reference function's address.
            llvm::Value *Addr =
                llvm::ConstantInt::getSigned(llvm::Type::getInt32Ty(LLVM.Ctx),
                                             Exp->RVA - DLL.ReferenceFunc->RVA);
            llvm::Value *RefPtr = IR.Builder.CreateBitCast(
                RefFunc, llvm::Type::getInt8PtrTy(LLVM.Ctx));
            llvm::Value *ComputedPtr = IR.Builder.CreateInBoundsGEP(
                llvm::Type::getInt8Ty(LLVM.Ctx), RefPtr, Addr);
            llvm::Value *FP = IR.Builder.CreateBitCast(
                ComputedPtr, Exp->Type->getPointerTo(), "fp");

            // Call the original DLL function.
            R = IR.createCall(Exp->Type, FP, Args, "r");
          } else {
            R = IR.createCall(Func, Args, "r");
          }

          if (R) {
            // Get pointer to the return value inside the union.
            llvm::Value *RP = IR.Builder.CreateBitCast(
                UP, Exp->Type->getReturnType()->getPointerTo(), "rp");

            // Save return value back into the structure.
            IR.Builder.CreateStore(R, RP);
          }

          // Finish.
          IR.Builder.CreateRetVoid();
        }

        // Emit `.obj` file.
        string ObjectFile(
            (OutputDir / DLL.Name).replace_extension(".obj").string());
        IR.emitObj(ObjectFile);

        // Create the wrapper DLL.
        ClangHelper(LLVM).linkDLL(
            (WrappersDir / DLL.Name).string(), ObjectFile,
            path(DLLPath).replace_extension(".lib").string());

        // Emit `.o` file.
        string DylibObjectFile(
            (OutputDir / DLL.Name).replace_extension(".o").string());
        DylibIR.emitObj(DylibObjectFile);

        // Create the stub Dylib.
        ClangHelper(LLVM).linkDylib(
            (OutputDir / DLL.Name).replace_extension(".dll.dylib").string(),
            DylibObjectFile, "/Wrappers/" + DLL.Name);
      }
    }
  }
  void generateDylibs() {
    size_t LibIdx = 0;
    for (const Dylib &Lib : HAC.iOSLibs) {
      string LibNo = to_string(LibIdx++);

      IRHelper IR(LLVM, LibNo, Lib.Name, IRHelper::Apple);

      // Generate function wrappers.
      // TODO: Shouldn't we use aligned instructions?
      for (const ExportEntry *Exp : Lib.Exports) {

        // Ignore functions that haven't been found in any DLL.
        if (Exp->Status != ExportStatus::FoundInDLL) {
          if constexpr (ErrorUnimplementedFunctions & LibType::DLL) {
            if (Exp->Status == ExportStatus::Found) {
              reportError(
                  Twine("function found in Dylib wasn't found in any DLL (") +
                  Exp->Name + ")");
            }
          }
          continue;
        }

        // Handle Objective-C messengers specially.
        if (Exp->Messenger) {
          // Construct name of the corresponding lookup function.
          string LookupName("_objc_msgLookup" +
                            Exp->Name.substr(HAContext::MsgSendLength));

          // And let's call the lookup function instead.
          // TODO: Wrong, this should be RVA instead of name.
          Exp->WrapperRVA = move(LookupName);
        }

        // Declarations.
        llvm::Function *Func = IR.declareFunc(Exp);
        llvm::Function *Wrapper = IR.declareFunc(Exp, /* Wrapper */ true);

        FunctionGuard FuncGuard(IR, Func);

        // Handle trivial `void -> void` functions specially.
        if (Exp->isTrivial()) {
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
        llvm::Type *RetTy = Exp->Type->getReturnType();
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

      // Initialize Clang args to create the Dylib.
      ClangHelper Clang(LLVM);
      // We add `./` to the library name to convert it to a relative path.
      Clang.addDylibArgs((DylibsDir / ("./" + Lib.Name)).string(), ObjectFile,
                         Lib.Name);
      Clang.Args.add("-L");
      Clang.Args.add(OutputDir.string().c_str());

      // Add DLLs to link.
      set<const DLLEntry *> DLLs;
      for (const ExportEntry *Exp : Lib.Exports) {
        if (Exp->DLL && DLLs.insert(Exp->DLL).second) {
          string DylibName(
              path(Exp->DLL->Name).replace_extension(".dll").string());

          // Remove prefix `lib`.
          if (!DylibName.compare(0, 3, "lib"))
            DylibName = DylibName.substr(3);

          Clang.Args.add("-l");
          Clang.Args.add(DylibName.c_str());
        }
      }

      // Create output directory.
      createOutputDir((DylibsDir / Lib.Name).parent_path().string().c_str());

      // Link the Dylib.
      Clang.executeArgs();
    }
  }

private:
  HAContext HAC;
  LLVMInitializer LLVMInit;
  LLVMHelper LLVM;
  path OutputDir, WrappersDir, DylibsDir;

  void analyzeAppleFunction(const llvm::Function &Func) {
    // We use mangled names to uniquely identify functions.
    string Name(LLVM.mangleName(Func));

    // Find the corresponding export info from TBD files.
    ExportList::iterator Exp;
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
    Exp->Type = Func.getFunctionType();
  }
  void compileAppleHeaders() {
    ClangHelper Clang(LLVM);
    Clang.Args.loadConfigFile("./src/HeadersAnalyzer/analyze_ios_headers.cfg");
    Clang.initFromInvocation();

    // Include all declarations in the result. See [emit-all-decls].
    // TODO: Maybe filter them (include only those exported from iOS Dylibs).
    Clang.CI.getLangOpts().EmitAllDecls = true;

    // Compile to LLVM IR.
    Clang.executeCodeGenAction<EmitLLVMOnlyAction>();
  }
  void reportUnimplementedFunctions() {
    if constexpr (ErrorUnimplementedFunctions & LibType::Dylib) {
      for (const ExportEntry &Exp : HAC.iOSExps) {
        if (Exp.Status == ExportStatus::NotFound) {
          reportError(
              "function found in TBD files wasn't found in any Dylib (" +
              Exp.Name + ")");
        }
      }
    }
  }
};

int main() {
  // TODO: This is so up here just for testing. In production, it should be
  // lower.
  try {
    HeadersAnalyzer HA;
    HA.parseAppleHeaders();
    HA.loadDLLs();
    HA.createDirs();
    HA.generateDLLs();
    HA.generateDylibs();
  } catch (const FatalError &) {
    return 1;
  }

  // TODO: Again, just for testing.
  return 0;

  export_list exps;

  // Discover `.tbd` files.
  {
    tbd_handler tbdh(exps);
    vector<string> tbdDirs{
        "./deps/apple-headers/iPhoneOS11.1.sdk/usr/lib/",
        "./deps/apple-headers/iPhoneOS11.1.sdk/System/Library/TextInput/"};
    for (auto &&dir : tbdDirs) {
      for (auto &&file : directory_iterator(dir)) {
        tbdh.handle_tbd_file(file.path().string());
      }
    }
    // Discover `.tbd` files inside frameworks.
    string frameworksDir =
        "./deps/apple-headers/iPhoneOS11.1.sdk/System/Library/Frameworks/";
    for (auto &&entry : directory_iterator(frameworksDir)) {
      if (entry.status().type() == file_type::directory &&
          !entry.path().extension().compare(".framework")) {
        tbdh.handle_tbd_file(
            (entry.path() / entry.path().filename().replace_extension(".tbd"))
                .string());
      }
    }
    cout << endl;
  }

  return 0;
}
